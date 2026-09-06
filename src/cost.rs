//! The cost-delta adapter (alpibrusl/lex-iac#4).
//!
//! Cloud spend is the one place where lex-os's "budget in integer
//! cents" is literally true, so a plan's predicted cost delta is
//! charged against `Budget::max_money_cents` like any other mediated
//! spend.
//!
//! # Integer cents, never floats
//!
//! House rule in lex-os, and a budget wall that drifts is not a wall.
//! Estimators emit decimal *strings* (`"128.50"`), which is convenient:
//! [`parse_cents`] reads them digit by digit and never constructs an
//! `f64`. `128.50` has no exact binary representation, and a ceiling
//! you cross by a rounding error is a ceiling nobody can reason about.
//!
//! # This is a ceiling on predicted spend, not a meter
//!
//! Every estimator is approximate: it prices the resources it knows,
//! at list rates, ignoring commitments, tiering and usage. A reader who
//! treats this as a meter will size the budget wrong. It bounds what a
//! change is *forecast* to add, which is a different and more tractable
//! question than what it will actually cost.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Why a cost report could not be read.
///
/// Every variant refuses. There is no "assume zero": an estimator that
/// ran and produced something unreadable is not evidence of a free
/// change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CostError {
    #[error("cost report is not JSON: {0}")]
    NotJson(String),
    #[error(
        "cost report declares no total delta: expected `diffTotalMonthlyCost`, \
         or a `diff.totalMonthlyCost` on at least one project"
    )]
    NoTotal,
    #[error("cost report field `{field}` is not a decimal amount: `{value}`")]
    NotAnAmount { field: String, value: String },
    #[error(
        "cost report is in {report}, but the grant's budget is denominated in \
         {expected} — comparing them would silently mis-size the ceiling"
    )]
    CurrencyMismatch { report: String, expected: String },
}

/// A plan's predicted cost delta, in integer minor units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostReport {
    /// ISO 4217 code as the estimator reported it, upper-cased.
    pub currency: String,
    /// Predicted change in *monthly* cost, in minor units. Negative
    /// when the plan is a saving — a teardown is not a spend, and
    /// charging it as one would refuse exactly the changes an operator
    /// most wants to make.
    pub monthly_delta_minor: i64,
    /// Per-address deltas, when the estimator reports them. Used only
    /// to name the resource that dominates a refusal, so the operator
    /// has one line to look at rather than a total.
    #[serde(default)]
    pub by_address: BTreeMap<String, i64>,
}

impl CostReport {
    /// Read Infracost's `breakdown`/`diff` JSON.
    ///
    /// The obvious first adapter, per the issue: it is what most teams
    /// already run in CI. Other estimators get their own constructor —
    /// the gate only ever sees a [`CostReport`].
    pub fn from_infracost_json(src: &str) -> Result<Self, CostError> {
        let v: serde_json::Value =
            serde_json::from_str(src).map_err(|e| CostError::NotJson(e.to_string()))?;

        let currency = v
            .get("currency")
            .and_then(|c| c.as_str())
            .unwrap_or("USD")
            .to_ascii_uppercase();

        // Prefer the top-level total; fall back to summing the
        // projects. Infracost emits the first for a diff and the second
        // for a multi-project breakdown, and a gate that only read one
        // would refuse half the reports it is handed.
        let total = match v.get("diffTotalMonthlyCost") {
            Some(t) => Some(amount(t, "diffTotalMonthlyCost")?),
            None => {
                let mut sum: Option<i64> = None;
                for p in v
                    .get("projects")
                    .and_then(|p| p.as_array())
                    .unwrap_or(&Vec::new())
                {
                    if let Some(t) = p.pointer("/diff/totalMonthlyCost") {
                        let cents = amount(t, "projects[].diff.totalMonthlyCost")?;
                        sum = Some(sum.unwrap_or(0) + cents);
                    }
                }
                sum
            }
        };
        let monthly_delta_minor = total.ok_or(CostError::NoTotal)?;

        // Per-resource deltas are optional. Their absence is not a
        // failure — it costs the refusal a name, not its correctness.
        let mut by_address = BTreeMap::new();
        for p in v
            .get("projects")
            .and_then(|p| p.as_array())
            .unwrap_or(&Vec::new())
        {
            for r in p
                .pointer("/diff/resources")
                .and_then(|r| r.as_array())
                .unwrap_or(&Vec::new())
            {
                let (Some(name), Some(cost)) =
                    (r.get("name").and_then(|n| n.as_str()), r.get("monthlyCost"))
                else {
                    continue;
                };
                if let Ok(cents) = amount(cost, "monthlyCost") {
                    *by_address.entry(name.to_string()).or_insert(0) += cents;
                }
            }
        }

        Ok(CostReport {
            currency,
            monthly_delta_minor,
            by_address,
        })
    }

    /// The address contributing most to the increase, if the estimator
    /// broke the total down.
    pub fn dominant_address(&self) -> Option<(&str, i64)> {
        self.by_address
            .iter()
            .filter(|(_, cents)| **cents > 0)
            .max_by_key(|(_, cents)| **cents)
            .map(|(a, c)| (a.as_str(), *c))
    }

    /// Refuse a report denominated differently from the budget.
    ///
    /// `max_money_cents` is a bare integer: nothing in it says which
    /// currency. Charging a EUR estimate against a ceiling someone
    /// sized in USD is off by whatever the rate is that day, silently
    /// and in whichever direction. Refuse, don't downgrade.
    pub fn check_currency(&self, expected: &str) -> Result<(), CostError> {
        if self.currency.eq_ignore_ascii_case(expected) {
            return Ok(());
        }
        Err(CostError::CurrencyMismatch {
            report: self.currency.clone(),
            expected: expected.to_ascii_uppercase(),
        })
    }
}

fn amount(v: &serde_json::Value, field: &str) -> Result<i64, CostError> {
    // Estimators emit amounts as strings. A JSON *number* would already
    // have been through a float by the time serde_json hands it over,
    // so it is refused rather than rounded: the caller should fix the
    // producer, not inherit its precision.
    let s = v.as_str().ok_or_else(|| CostError::NotAnAmount {
        field: field.to_string(),
        value: v.to_string(),
    })?;
    parse_cents(s).ok_or_else(|| CostError::NotAnAmount {
        field: field.to_string(),
        value: s.to_string(),
    })
}

/// Parse a decimal amount to integer minor units, without floats.
///
/// Accepts an optional sign, digits, and at most two fractional
/// digits. More than two is refused rather than rounded — an estimator
/// reporting sub-cent precision is telling us something about its
/// model, and quietly truncating it would hide that.
///
/// ```
/// use lex_iac::cost::parse_cents;
///
/// assert_eq!(parse_cents("128.50"), Some(12850));
/// assert_eq!(parse_cents("-4"), Some(-400));
/// assert_eq!(parse_cents("0.07"), Some(7));
/// assert_eq!(parse_cents("1.005"), None);
/// ```
pub fn parse_cents(s: &str) -> Option<i64> {
    let s = s.trim();
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };

    let (whole, frac) = match digits.split_once('.') {
        Some((w, f)) => (w, f),
        None => (digits, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if frac.len() > 2 {
        return None;
    }

    let whole: i64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let frac: i64 = match frac.len() {
        0 => 0,
        1 => frac.parse::<i64>().ok()? * 10,
        _ => frac.parse().ok()?,
    };

    let total = whole.checked_mul(100)?.checked_add(frac)?;
    Some(if negative { -total } else { total })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_without_touching_a_float() {
        for (src, want) in [
            ("0", 0),
            ("1", 100),
            ("128.50", 12850),
            ("128.5", 12850),
            ("0.07", 7),
            (".07", 7),
            ("-12.34", -1234),
            ("+12.34", 1234),
            ("  9.99  ", 999),
        ] {
            assert_eq!(parse_cents(src), Some(want), "parsing {src:?}");
        }
    }

    /// The bug this module exists to avoid, demonstrated rather than
    /// asserted in a comment. `1.15` has no exact binary form: the
    /// obvious `(amount * 100.0) as i64` reads it as 114 cents, so a
    /// budget wall built that way is off by one in the permissive
    /// direction, silently, on ordinary inputs.
    #[test]
    fn the_float_route_loses_a_cent_and_this_one_does_not() {
        let src = "1.15";
        let via_float = (src.parse::<f64>().unwrap() * 100.0) as i64;
        assert_eq!(via_float, 114, "the naive route, for the record");
        assert_eq!(parse_cents(src), Some(115));
    }

    /// And cents add exactly, so a ceiling is crossed when it is
    /// crossed rather than when the accumulated error says so.
    #[test]
    fn cents_add_exactly() {
        let sum: i64 = ["0.10", "0.20"].iter().filter_map(|s| parse_cents(s)).sum();
        assert_eq!(sum, 30);
    }

    #[test]
    fn nonsense_is_refused_rather_than_coerced_to_zero() {
        for bad in [
            "", "-", ".", "abc", "1.234", "1e5", "1,50", "$4.00", "1.2.3", "12 34",
        ] {
            assert_eq!(parse_cents(bad), None, "{bad:?} should not parse");
        }
    }

    const INFRACOST_DIFF: &str = r#"{
      "version": "0.2",
      "currency": "USD",
      "projects": [{
        "name": "payments",
        "diff": {
          "totalMonthlyCost": "412.90",
          "resources": [
            { "name": "aws_db_instance.payments", "monthlyCost": "380.00" },
            { "name": "aws_ecs_service.api",      "monthlyCost": "32.90"  }
          ]
        }
      }],
      "diffTotalMonthlyCost": "412.90"
    }"#;

    #[test]
    fn an_infracost_diff_reads_as_integer_minor_units() {
        let r = CostReport::from_infracost_json(INFRACOST_DIFF).unwrap();
        assert_eq!(r.currency, "USD");
        assert_eq!(r.monthly_delta_minor, 41290);
        assert_eq!(
            r.dominant_address(),
            Some(("aws_db_instance.payments", 38000)),
            "the refusal should be able to name the resource that dominates"
        );
    }

    #[test]
    fn a_multi_project_breakdown_sums_its_projects() {
        let src = r#"{
          "currency": "USD",
          "projects": [
            { "diff": { "totalMonthlyCost": "10.00" } },
            { "diff": { "totalMonthlyCost": "5.50"  } }
          ]
        }"#;
        let r = CostReport::from_infracost_json(src).unwrap();
        assert_eq!(r.monthly_delta_minor, 1550);
    }

    /// A saving is not a spend. Charging a teardown against the budget
    /// would refuse exactly the changes an operator most wants to make.
    #[test]
    fn a_teardown_reads_as_a_negative_delta() {
        let src = r#"{"currency":"USD","diffTotalMonthlyCost":"-380.00"}"#;
        let r = CostReport::from_infracost_json(src).unwrap();
        assert_eq!(r.monthly_delta_minor, -38000);
    }

    #[test]
    fn a_report_with_no_total_is_refused_not_read_as_free() {
        let err = CostReport::from_infracost_json(r#"{"currency":"USD"}"#).unwrap_err();
        assert_eq!(err, CostError::NoTotal);
    }

    /// A JSON number has already been through an f64 by the time serde
    /// hands it over. Refusing sends the caller to fix the producer;
    /// rounding would inherit its precision silently.
    #[test]
    fn a_numeric_amount_is_refused_rather_than_rounded() {
        let src = r#"{"currency":"USD","diffTotalMonthlyCost":412.90}"#;
        assert!(matches!(
            CostReport::from_infracost_json(src),
            Err(CostError::NotAnAmount { .. })
        ));
    }

    #[test]
    fn a_differently_denominated_report_is_refused() {
        let src = r#"{"currency":"EUR","diffTotalMonthlyCost":"100.00"}"#;
        let r = CostReport::from_infracost_json(src).unwrap();
        assert!(r.check_currency("USD").is_err());
        assert!(r.check_currency("eur").is_ok(), "the code is case-blind");
    }
}
