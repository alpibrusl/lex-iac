//! The gate: plan in, verdict out, with the record written first.
//!
//! ```text
//! plan_requested                       ← logged BEFORE any gate decides
//!   → effects        plan → effect rows                        (#2)
//!   → narrowing      every effect ⊆ the infra facet
//!   → reversibility  destroying state needs the verb named
//!   → spend_charged  the predicted delta, recorded              (#4)
//!   → budget         the delta must fit `max_money_cents`
//!   → trust          an unscored submitter names every verb it uses
//!   → plan_accepted | plan_refused
//! ```
//!
//! Two properties are load-bearing, both inherited rather than invented.
//!
//! **The request is logged before any decision.** That is the order
//! lex-os's supervisor uses, and it means a refusal is exactly as
//! legible in the record as an approval. A gate that logged only what it
//! allowed would be a gate you could not audit.
//!
//! **The budget leg sits after reversibility, before allow**, matching
//! lex-os's gate order, and the charge is recorded whether or not it
//! fits. A budget you can only see when it was exceeded is not a
//! budget anyone can plan against.
//!
//! **A verdict is `Allow`, `Deny` or `Inconclusive`.** The third is
//! borrowed from `lex-guard`, which had it right: something the gate
//! cannot *read* is not thereby harmless. Inconclusive refuses, and
//! carries why — "refuse, don't downgrade" in the type rather than in a
//! comment.

use lex_os_audit::{Chain, ChainPayload};
use lex_os_manifest::{Manifest, ManifestError, Reversibility};
use serde::{Deserialize, Serialize};

use crate::{
    compile_any,
    cost::CostError,
    facet::Gravity,
    manifest::infra_facet,
    trust::{Standing, Submitter},
    CompiledPlan, CostReport, Denial, EffectRow, InfraFacet, PlanError, Verb,
};

/// What this gate records. lex-os knows nothing about any of it — which
/// is why `Chain<E>` is generic (lex-os#67).
///
/// # The promotion contract
///
/// `plan_accepted` and `plan_refused` are shaped to satisfy
/// `lex attest import-apply` (alpibrusl/lex-lang#794), which does not
/// know this repo's vocabulary and so names three fields of its own:
/// **`artifact_sha256`** (the decided bytes), **`manifest`** (the
/// ceiling), and **`signer`** (who authorised it). `subject` is
/// optional and human-facing.
///
/// That is why the plan hash is spelled `artifact_sha256` in the log
/// while [`CompiledPlan`] still calls its field `plan_sha256`: the
/// contract name belongs where the contract applies, and nowhere else.
/// A gate that spelled it `plan_sha256` here would promote nothing —
/// silently, which is the failure mode worth designing out.
///
/// `spend_charged` carries no signer because it is a measurement, not a
/// decision. Nothing promotes it, and attributing a number to somebody
/// would imply they chose it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanEvent {
    /// Written before anything is decided. `artifact_sha256` is the
    /// identity of the exact bytes; an acceptance authorises only these.
    PlanRequested {
        artifact_sha256: String,
        manifest: String,
        goal: String,
        effects: Vec<String>,
        /// Who submitted it, when the caller said. Absent rather than
        /// invented: `import-apply` then needs its own `--signer`, and
        /// being asked for one is better than being handed a guess.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        /// What the keyring said — `not-consulted` when none was given.
        trust: String,
    },
    /// The predicted spend, recorded before the budget wall decides —
    /// so an approval carries the number it was approved against, not
    /// only a refusal.
    SpendCharged {
        artifact_sha256: String,
        currency: String,
        monthly_delta_minor: i64,
        budget_minor: u64,
    },
    PlanAccepted {
        artifact_sha256: String,
        manifest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        /// The goal this plan was approved in service of. `subject` is
        /// the contract's optional human-facing field.
        subject: String,
    },
    /// Refused, naming the single effect that tripped the wall — the
    /// operator needs one line to look at, not a verdict on the plan.
    ///
    /// `reason` doubles as the contract's failure detail: `import-apply`
    /// reads it into `AttestationResult::Failed { detail }`, so a
    /// submitter's record says *why* it was refused, not merely that it
    /// was.
    PlanRefused {
        artifact_sha256: String,
        manifest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        subject: String,
        wall: String,
        effect: String,
        address: String,
        reason: String,
    },
}

impl ChainPayload for PlanEvent {
    const DOMAIN: &'static [u8] = b"lex.iac.audit.v1";
}

/// The gate could not run.
///
/// Distinct from a refusal on purpose, and mapped to a distinct exit
/// code: a refusal is a decision the gate reached, and a pipeline that
/// conflates the two will eventually read a broken gate as an approval.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// The plan JSON would not parse.
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// The manifest carries an `infra` facet this build cannot read.
    /// Neither "grants nothing" nor "grants everything" is a safe
    /// reading of it, so neither is guessed.
    ///
    /// Transparent because lex-os's own message already names the facet
    /// and says it does not parse; wrapping it would only say so twice.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The cost report could not be read, or is denominated
    /// differently from the budget. An estimator that ran and produced
    /// something unreadable is not evidence of a free change.
    #[error(transparent)]
    Cost(#[from] CostError),
}

/// Which wall a refusal hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Wall {
    /// The effect is outside the grant.
    Narrowing,
    /// The effect destroys state the grant does not name explicitly.
    Reversibility,
    /// The predicted spend exceeds `budget.max_money_cents`.
    Budget,
    /// A wildcard would have admitted it, but the submitter has no
    /// earned standing, so the verb has to be named.
    Trust,
    /// The gate could not read the effect well enough to check it.
    Unreadable,
}

impl Wall {
    pub fn as_str(self) -> &'static str {
        match self {
            Wall::Narrowing => "narrowing",
            Wall::Reversibility => "reversibility",
            Wall::Budget => "budget",
            Wall::Trust => "trust",
            Wall::Unreadable => "unreadable",
        }
    }
}

/// One refusal, in the shape an agent can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub wall: Wall,
    /// `provider.service.verb` that tripped it.
    pub effect: String,
    pub address: String,
    pub reason: String,
    /// What the grant does allow, so the answer is actionable rather
    /// than merely negative.
    pub grant_allows: Vec<String>,
}

/// The gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Refused. The first refusal is the reported one; `all` carries the
    /// rest so a caller can show the whole picture without re-running.
    Deny {
        first: Refusal,
        all: Vec<Refusal>,
    },
}

impl Verdict {
    pub fn allowed(&self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

/// A completed check: the verdict, the compiled plan, and the audit log
/// written along the way.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub plan: CompiledPlan,
    pub audit: Chain<PlanEvent>,
    /// The predicted monthly delta in minor units, when an estimate was
    /// supplied. `None` means *unpriced*, never zero.
    pub charged: Option<i64>,
    /// Who asked, if anyone said.
    pub signer: Option<String>,
    /// What the keyring said about them.
    pub standing: Standing,
}

impl Decision {
    /// Semantic exit code, following lex-os's convention: 0 allowed,
    /// 8 refused.
    pub fn exit_code(&self) -> i32 {
        match self.verdict {
            Verdict::Allow => 0,
            Verdict::Deny { .. } => 8,
        }
    }
}

/// Check a plan against a manifest.
///
/// `cost` is the predicted spend, from whatever estimator the team
/// already runs. It is an `Option` rather than a default because the
/// two cases are genuinely different and the caller has to say which it
/// is in: **no estimate is not an estimate of zero**. Without one, a
/// row that creates or replaces infrastructure has an unknown price,
/// and an unknown price is treated as consequential — a wildcard will
/// not authorise it, the verb has to be named. See [`unpriced`].
///
/// `submitter` is who is asking, and what the earned keyring says
/// about them. It is an `Option` for the same reason `cost` is: a run
/// with no submitter identity and a run by somebody nobody has scored
/// are different, and the gate will not pick one for you. Supplying a
/// submitter with [`Standing::Unknown`](crate::trust::Standing::Unknown)
/// holds every mutating row to the **narrower** reading of the same
/// grant — each verb named, no wildcards. It never widens anything; the
/// manifest is the ceiling regardless of anyone's score.
///
/// The only errors are inputs the gate cannot read; a plan that parses
/// but over-reaches is a `Deny`, not an `Err`. That distinction
/// matters: a refusal is a normal, recorded outcome, and conflating it
/// with a malfunction is how refusals end up unlogged.
pub fn check(
    plan_json: &str,
    manifest: &Manifest,
    cost: Option<&CostReport>,
    submitter: Option<&Submitter>,
) -> Result<Decision, GateError> {
    // The one line milestone 5 changed in the gate: which reader runs.
    // Everything downstream — the walls, the facet, the audit vocabulary
    // — is frontend-independent.
    let plan = compile_any(plan_json)?;
    // Read the authority before writing anything: a manifest whose
    // facet will not parse means the gate cannot run, and a request
    // record would claim it did.
    let infra = infra_facet(manifest)?;
    if let Some(c) = cost {
        c.check_currency(&infra.currency)?;
    }

    let mut audit: Chain<PlanEvent> = Chain::new();
    let manifest_id = manifest.content_id().0;
    let signer = submitter.map(|s| s.signer.clone());
    let standing = submitter.map_or(Standing::NotConsulted, |s| s.standing);
    let subject = manifest.goal.description.clone();

    // Logged before any gate runs — including who asked and what the
    // keyring said, so a refusal for want of standing is as legible in
    // the record as the decision that followed it.
    audit.append(PlanEvent::PlanRequested {
        artifact_sha256: plan.plan_sha256.clone(),
        manifest: manifest_id.clone(),
        goal: subject.clone(),
        effects: plan.required_effects(),
        signer: signer.clone(),
        trust: standing.as_str().to_string(),
    });

    let untrusted = standing.needs_the_verb_named();
    let mut refusals: Vec<Refusal> = plan
        .rows
        .iter()
        .filter(|row| row.effect.verb.mutates())
        .filter_map(|row| refuse(row, &infra, cost.is_some(), untrusted))
        .collect();

    // The budget leg: after reversibility, before allow. Recorded
    // whether or not it fits — a budget you only see when it was
    // exceeded is not a budget anyone can plan against.
    if let Some(c) = cost {
        let budget = manifest.budget.max_money_cents;
        audit.append(PlanEvent::SpendCharged {
            artifact_sha256: plan.plan_sha256.clone(),
            currency: infra.currency.clone(),
            monthly_delta_minor: c.monthly_delta_minor,
            budget_minor: budget,
        });
        if let Some(r) = over_budget(c, budget, &infra) {
            refusals.push(r);
        }
    }

    let verdict = match refusals.split_first() {
        None => {
            audit.append(PlanEvent::PlanAccepted {
                artifact_sha256: plan.plan_sha256.clone(),
                manifest: manifest_id,
                signer: signer.clone(),
                subject: subject.clone(),
            });
            Verdict::Allow
        }
        Some((first, _)) => {
            audit.append(PlanEvent::PlanRefused {
                artifact_sha256: plan.plan_sha256.clone(),
                manifest: manifest_id,
                signer: signer.clone(),
                subject: subject.clone(),
                wall: first.wall.as_str().to_string(),
                effect: first.effect.clone(),
                address: first.address.clone(),
                reason: first.reason.clone(),
            });
            Verdict::Deny {
                first: first.clone(),
                all: refusals.clone(),
            }
        }
    };

    Ok(Decision {
        verdict,
        plan,
        audit,
        charged: cost.map(|c| c.monthly_delta_minor),
        signer,
        standing,
    })
}

/// Does a verb add cost the estimator would have had to price?
///
/// `create` and `replace` bring resources into existence. `update` can
/// resize one, and is deliberately *not* here: escalating every update
/// would refuse nearly every plan, and the pressure that puts on
/// operators is to widen the grant until it means nothing — the exact
/// failure this project exists to prevent. It is a real gap, named in
/// the README rather than papered over.
pub fn unpriced(verb: Verb) -> bool {
    matches!(verb, Verb::Create | Verb::Replace)
}

/// The predicted delta against the ceiling.
///
/// A *negative* delta is a saving, and is never refused: charging a
/// teardown against the budget would refuse exactly the changes an
/// operator most wants to make.
fn over_budget(cost: &CostReport, budget_minor: u64, infra: &InfraFacet) -> Option<Refusal> {
    let delta = cost.monthly_delta_minor;
    if delta <= 0 || (delta as u128) <= budget_minor as u128 {
        return None;
    }
    let (address, share) = match cost.dominant_address() {
        Some((a, c)) => (a.to_string(), format!(", of which `{a}` is {}", money(c))),
        None => ("(whole plan)".to_string(), String::new()),
    };
    Some(Refusal {
        wall: Wall::Budget,
        effect: "spend".to_string(),
        address,
        reason: format!(
            "predicted monthly spend rises by {}{share}, and the grant's budget is {} \
             ({} over) — this is a ceiling on forecast spend, not a meter",
            money(delta),
            money(budget_minor as i64),
            money(delta - budget_minor as i64),
        ),
        grant_allows: infra.allow.clone(),
    })
}

/// Minor units as a decimal, without going near a float.
fn money(minor: i64) -> String {
    let sign = if minor < 0 { "-" } else { "" };
    let n = minor.unsigned_abs();
    format!("{sign}{}.{:02}", n / 100, n % 100)
}

/// Is this row refused, and why?
fn refuse(row: &EffectRow, infra: &InfraFacet, priced: bool, untrusted: bool) -> Option<Refusal> {
    // Three reasons a wildcard will not do, and they are kept apart:
    // destroying state is not the same as nobody having priced the
    // change, which is not the same as nobody vouching for the
    // submitter. An operator told their `aws.ecs.create` "destroys
    // stateful infrastructure" loses the time it takes to find out it
    // does not.
    //
    // The order is gravest first, and each remedy is different:
    // destruction is resolved by naming the verb, an unpriced change
    // also by supplying an estimate, and an unknown submitter also by
    // earning a score. Reporting the weakest reason when a graver one
    // applies would send the reader to the wrong remedy.
    let gravity = if row.reversibility == Reversibility::IrreversibleConsequential {
        Gravity::DestroysState
    } else if !priced && unpriced(row.effect.verb) {
        Gravity::Unpriced
    } else if untrusted {
        Gravity::Untrusted
    } else {
        Gravity::Routine
    };
    match infra.admits(&row.effect, gravity) {
        Ok(()) => None,
        Err(denial) => {
            let wall = match &denial {
                Denial::NotGranted => Wall::Narrowing,
                Denial::WildcardIsNotEnough {
                    why: Gravity::Unpriced,
                    ..
                } => Wall::Budget,
                Denial::WildcardIsNotEnough {
                    why: Gravity::Untrusted,
                    ..
                } => Wall::Trust,
                Denial::WildcardIsNotEnough { .. } => Wall::Reversibility,
                Denial::Unreadable(_) => Wall::Unreadable,
            };
            Some(Refusal {
                wall,
                effect: row.effect.qualified(),
                address: row.address.clone(),
                reason: denial.to_string(),
                grant_allows: infra.allow.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Budget, Goal, Grant, Level};

    fn manifest(allow: &[&str]) -> Manifest {
        Manifest::new(
            Goal::new("rotate the payments API deployment"),
            Grant::new(Level::None, Level::Allowlist, Level::None),
            Budget::research_default(),
        )
        .with_facet(&InfraFacet::new(allow.iter().copied()))
        .expect("the facet serialises")
    }

    const ROTATE: &str = r#"{"resource_changes":[
        {"address":"aws_ecs_service.api","type":"aws_ecs_service","mode":"managed",
         "change":{"actions":["update"]}}
    ]}"#;

    const REPLACE_DB: &str = r#"{"resource_changes":[
        {"address":"aws_ecs_service.api","type":"aws_ecs_service","mode":"managed",
         "change":{"actions":["update"]}},
        {"address":"aws_db_instance.payments","type":"aws_db_instance","mode":"managed",
         "change":{"actions":["delete","create"]}}
    ]}"#;

    #[test]
    fn an_in_grant_plan_is_allowed_and_recorded() {
        let d = check(ROTATE, &manifest(&["aws.ecs.*"]), None, None).unwrap();
        assert!(d.verdict.allowed());
        assert_eq!(d.exit_code(), 0);
        assert_eq!(d.audit.len(), 2);
        d.audit.verify().expect("the chain verifies");
    }

    /// The headline case: a broad grant does not silently cover
    /// destroying a database.
    #[test]
    fn a_wildcard_grant_does_not_authorise_the_hidden_replace() {
        let d = check(
            REPLACE_DB,
            &manifest(&["aws.ecs.*", "aws.rds.*"]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(d.exit_code(), 8);
        let Verdict::Deny { first, .. } = &d.verdict else {
            panic!("expected a refusal, got {:?}", d.verdict);
        };
        assert_eq!(first.wall, Wall::Reversibility);
        assert_eq!(first.effect, "aws.rds.replace");
        assert_eq!(first.address, "aws_db_instance.payments");
        assert!(first.reason.contains("name the verb explicitly"));
    }

    #[test]
    fn naming_the_verb_authorises_it() {
        let d = check(
            REPLACE_DB,
            &manifest(&["aws.ecs.*", "aws.rds.replace"]),
            None,
            None,
        )
        .unwrap();
        assert!(d.verdict.allowed(), "{:?}", d.verdict);
    }

    #[test]
    fn an_effect_outside_the_grant_hits_the_narrowing_wall() {
        let d = check(ROTATE, &manifest(&["aws.iam.read"]), None, None).unwrap();
        let Verdict::Deny { first, .. } = &d.verdict else {
            panic!("expected a refusal");
        };
        assert_eq!(first.wall, Wall::Narrowing);
        assert_eq!(first.grant_allows, vec!["aws.iam.read"]);
    }

    /// The record has to be written before the decision, or a refusal is
    /// less legible than an approval.
    #[test]
    fn the_request_is_logged_before_the_decision() {
        let d = check(REPLACE_DB, &manifest(&["aws.ecs.*"]), None, None).unwrap();
        assert_eq!(d.audit.len(), 2);
        assert!(matches!(
            d.audit.entries()[0].event,
            PlanEvent::PlanRequested { .. }
        ));
        assert!(matches!(
            d.audit.entries()[1].event,
            PlanEvent::PlanRefused { .. }
        ));
        d.audit.verify().unwrap();
    }

    #[test]
    fn every_refusal_is_carried_not_just_the_first() {
        // Neither effect is granted.
        let d = check(REPLACE_DB, &manifest(&["gcp.sql.create"]), None, None).unwrap();
        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!("expected a refusal");
        };
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn an_empty_plan_is_allowed() {
        let d = check(r#"{"resource_changes":[]}"#, &manifest(&[]), None, None).unwrap();
        assert!(d.verdict.allowed());
    }

    #[test]
    fn a_malformed_plan_is_an_error_not_a_verdict() {
        assert!(check("{not json", &manifest(&["aws.ecs.*"]), None, None).is_err());
    }

    /// A refusal pins the same bytes the request did, so an accepted
    /// plan cannot be swapped for another after the fact.
    #[test]
    fn the_audit_record_pins_the_plan_bytes() {
        let d = check(ROTATE, &manifest(&["aws.ecs.*"]), None, None).unwrap();
        let PlanEvent::PlanRequested {
            artifact_sha256, ..
        } = &d.audit.entries()[0].event
        else {
            panic!("expected plan_requested");
        };
        assert_eq!(artifact_sha256, &d.plan.plan_sha256);
        assert_eq!(artifact_sha256.len(), 64);
    }
}
