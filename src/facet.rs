//! The `infra` facet: which `provider.service.verb` effects a run may
//! use, and within which account and regions.
//!
//! This is an authority domain outside the trust lattice, so it is a
//! **facet** in lex-os's sense: it implements
//! [`lex_os_manifest::Facet`] and narrows using that crate's lattice
//! primitives rather than inventing its own comparison rules.
//!
//! # Allow-only
//!
//! There is no deny list, deliberately (lex-os `docs/design/plan-gates.md`
//! *Amendments* §3). A deny list does not narrow: a child that omits one
//! of its parent's deny entries has *widened*, which inverts the whole
//! invariant — and the claim against Sentinel, OPA and Checkov is
//! precisely that we narrow where they enumerate. A prohibition is
//! expressed as the absence of an allow entry.
//!
//! # Patterns
//!
//! An allow entry is exactly three dot-separated segments —
//! `provider.service.verb` — each a literal or `*`:
//!
//! ```text
//! aws.ecs.*        every ECS verb
//! aws.iam.read     that verb and no other
//! *.*.read         reads anywhere
//! ```
//!
//! Requiring three segments is a safety choice. A two-segment `aws.*`
//! would have to mean either "every aws service, one verb" or "every aws
//! effect", and a grant whose breadth depends on how a reader parses it
//! is worse than no grant.

use lex_os_manifest::{
    facet::{narrow_allowlist, FacetError},
    Facet,
};
use serde::{Deserialize, Serialize};

use crate::Effect;

/// Where the run is allowed to act. Empty means unconstrained on that
/// axis, which is legible in a manifest and narrows the obvious way.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub region: Vec<String>,
}

/// The `infra` facet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfraFacet {
    /// `provider.service.verb` patterns. Nothing outside these is
    /// authorised.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub scope: Scope,
    /// What `budget.max_money_cents` is denominated in (#4).
    ///
    /// lex-os's budget is a bare integer, so nothing in it says which
    /// currency. A cost report in another one is refused rather than
    /// charged: EUR against a ceiling sized in USD is wrong by whatever
    /// the rate is that day, silently and in whichever direction.
    ///
    /// It sits on the facet rather than in CLI configuration because a
    /// child that redenominated its budget would have widened it —
    /// ¥5000 is not $50 — so it has to narrow with everything else.
    #[serde(default = "default_currency")]
    pub currency: String,
}

fn default_currency() -> String {
    "USD".to_string()
}

impl Default for InfraFacet {
    fn default() -> Self {
        InfraFacet {
            allow: Vec::new(),
            scope: Scope::default(),
            currency: default_currency(),
        }
    }
}

/// A parsed allow entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern<'a> {
    segments: [&'a str; 3],
}

impl<'a> Pattern<'a> {
    /// Parse `provider.service.verb`. Anything that is not exactly three
    /// segments is rejected rather than guessed at.
    fn parse(src: &'a str) -> Option<Pattern<'a>> {
        let mut it = src.split('.');
        let (a, b, c) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() || a.is_empty() || b.is_empty() || c.is_empty() {
            return None;
        }
        Some(Pattern {
            segments: [a, b, c],
        })
    }

    /// Does this pattern admit `effect` (`provider.service.verb`)?
    fn admits(&self, effect: &Pattern<'_>) -> bool {
        self.segments
            .iter()
            .zip(effect.segments.iter())
            .all(|(p, e)| *p == "*" || p == e)
    }

    /// Does this pattern cover everything another pattern covers?
    ///
    /// A `*` in the child where the parent has a literal is a widening:
    /// the child would admit effects the parent never did.
    fn covers(&self, other: &Pattern<'_>) -> bool {
        self.segments
            .iter()
            .zip(other.segments.iter())
            .all(|(p, c)| *p == "*" || p == c)
    }

    fn has_wildcard(&self) -> bool {
        self.segments.contains(&"*")
    }
}

/// Why an effect needs its verb spelled out, rather than being covered
/// by a wildcard.
///
/// Two different reasons, kept apart because they send an operator to
/// different places. Telling someone their `aws.ecs.create` "destroys
/// stateful infrastructure" is a lie that costs them the time it takes
/// to work out it is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gravity {
    /// A wildcard is enough.
    Routine,
    /// Destroys state that re-running cannot restore. `aws.rds.*` reads
    /// to an operator as "manage RDS", not "you may delete the
    /// production database", and the gate holds it to the first
    /// reading.
    DestroysState,
    /// Nobody priced it (alpibrusl/lex-iac#4). "We did not measure it"
    /// must not read as "it is free", so an unpriced create needs the
    /// same explicitness — either an estimate, or the verb named.
    Unpriced,
}

impl Gravity {
    pub fn needs_the_verb_named(self) -> bool {
        !matches!(self, Gravity::Routine)
    }

    /// The second half of a refusal: what a wildcard cannot do here,
    /// and what the operator can do about it. Each reason carries its
    /// own remedy, because they are different remedies.
    fn as_reason(self) -> &'static str {
        match self {
            // Never rendered: a routine effect is not denied.
            Gravity::Routine => "it is authorised",
            Gravity::DestroysState => {
                "a wildcard cannot authorise destruction of stateful \
                 infrastructure — name the verb explicitly"
            }
            Gravity::Unpriced => {
                "nothing has priced this change, so a wildcard cannot \
                 authorise it — supply a cost estimate, or name the verb \
                 explicitly"
            }
        }
    }
}

/// Why an effect is not authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// Nothing in `allow` admits it.
    NotGranted,
    /// Admitted only by a wildcard, and the effect is one a wildcard
    /// does not stretch to — see [`Gravity`] and [`InfraFacet::admits`].
    WildcardIsNotEnough { matched: String, why: Gravity },
    /// The effect could not be reduced to `provider.service.verb`, so
    /// there is nothing to check it against.
    Unreadable(String),
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Denial::NotGranted => write!(f, "no allow entry admits it"),
            Denial::WildcardIsNotEnough { matched, why } => {
                write!(f, "only `{matched}` admits it, and {}", why.as_reason())
            }
            Denial::Unreadable(why) => write!(f, "{why}"),
        }
    }
}

impl InfraFacet {
    pub fn new(allow: impl IntoIterator<Item = impl Into<String>>) -> Self {
        InfraFacet {
            allow: allow.into_iter().map(Into::into).collect(),
            ..InfraFacet::default()
        }
    }

    /// Is `effect` authorised, at the given [`Gravity`]?
    ///
    /// The non-routine cases are the ones that matter. A grant of
    /// `aws.rds.*` reads to an operator as "manage RDS", not "you may
    /// delete the production database" — so a wildcard admits ordinary
    /// verbs but never a `delete` or `replace` of something stateful,
    /// nor a change nothing has priced. Either requires the verb
    /// spelled out. This is the
    /// facet's half of "an `IrreversibleConsequential` command is refused
    /// by construction unless the grant bounds it".
    pub fn admits(&self, effect: &Effect, gravity: Gravity) -> Result<(), Denial> {
        let qualified = effect.qualified();
        let parsed = Pattern::parse(&qualified).ok_or_else(|| {
            Denial::Unreadable(format!(
                "`{qualified}` is not a readable provider.service.verb \
                 (resource type `{}` gave no service)",
                effect.provider
            ))
        })?;

        let mut wildcard_match: Option<String> = None;
        for entry in &self.allow {
            let Some(pattern) = Pattern::parse(entry) else {
                // A malformed allow entry grants nothing. Refuse, don't
                // downgrade — and don't silently treat it as a match.
                continue;
            };
            if pattern.admits(&parsed) {
                if !gravity.needs_the_verb_named() || !pattern.has_wildcard() {
                    return Ok(());
                }
                wildcard_match.get_or_insert_with(|| entry.clone());
            }
        }

        Err(match wildcard_match {
            Some(matched) => Denial::WildcardIsNotEnough {
                matched,
                why: gravity,
            },
            None => Denial::NotGranted,
        })
    }

    /// Allow entries that are not parseable. A manifest carrying one is
    /// not silently accepted: the caller surfaces these, because an
    /// operator who wrote `aws.*` believing it granted something is in a
    /// worse position than one who wrote nothing.
    pub fn malformed_entries(&self) -> Vec<&str> {
        self.allow
            .iter()
            .filter(|e| Pattern::parse(e).is_none())
            .map(String::as_str)
            .collect()
    }
}

impl Facet for InfraFacet {
    const NAME: &'static str = "infra";

    fn validate_narrowing(parent: &Self, child: &Self) -> Result<(), FacetError> {
        // Every child pattern must be covered by some parent pattern.
        for entry in &child.allow {
            let Some(c) = Pattern::parse(entry) else {
                return Err(FacetError::new(
                    Self::NAME,
                    format!("allow: `{entry}` is not a provider.service.verb pattern"),
                ));
            };
            let covered = parent
                .allow
                .iter()
                .filter_map(|p| Pattern::parse(p))
                .any(|p| p.covers(&c));
            if !covered {
                return Err(FacetError::new(
                    Self::NAME,
                    format!("allow: child claims `{entry}`, which the parent does not grant"),
                ));
            }
        }

        // A child may not redenominate its budget: the ceiling is an
        // integer, so changing the unit changes the ceiling.
        if !parent.currency.eq_ignore_ascii_case(&child.currency) {
            return Err(FacetError::new(
                Self::NAME,
                format!(
                    "currency: child denominates its budget in `{}`, parent in `{}` \
                     — the ceiling is a bare integer, so the unit is part of it",
                    child.currency, parent.currency
                ),
            ));
        }

        // Scope narrows: a child may pin an account the parent pinned or
        // left open, and may only keep regions the parent listed.
        match (&parent.scope.account, &child.scope.account) {
            (Some(p), Some(c)) if p != c => {
                return Err(FacetError::new(
                    Self::NAME,
                    format!("scope.account: child claims `{c}`, parent is pinned to `{p}`"),
                ));
            }
            (Some(p), None) => {
                return Err(FacetError::new(
                    Self::NAME,
                    format!(
                        "scope.account: parent is pinned to `{p}`, child leaves it unconstrained"
                    ),
                ));
            }
            _ => {}
        }
        if !parent.scope.region.is_empty() {
            narrow_allowlist(
                Self::NAME,
                "scope.region",
                parent.scope.region.iter().map(String::as_str),
                child.scope.region.iter().map(String::as_str),
            )?;
            if child.scope.region.is_empty() {
                return Err(FacetError::new(
                    Self::NAME,
                    "scope.region: parent restricts regions, child leaves them unconstrained",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Verb;

    fn effect(t: &str, v: Verb) -> Effect {
        Effect::new(t, v, "addr")
    }

    #[test]
    fn an_exact_entry_admits_only_that_verb() {
        let f = InfraFacet::new(["aws.iam.read"]);
        assert!(f
            .admits(&effect("aws_iam_role", Verb::Read), Gravity::Routine)
            .is_ok());
        assert_eq!(
            f.admits(&effect("aws_iam_role", Verb::Update), Gravity::Routine),
            Err(Denial::NotGranted)
        );
    }

    #[test]
    fn a_wildcard_admits_ordinary_verbs() {
        let f = InfraFacet::new(["aws.ecs.*"]);
        assert!(f
            .admits(&effect("aws_ecs_service", Verb::Update), Gravity::Routine)
            .is_ok());
        assert!(f
            .admits(&effect("aws_ecs_service", Verb::Create), Gravity::Routine)
            .is_ok());
    }

    /// The rule that gives the facet its teeth.
    #[test]
    fn a_wildcard_never_authorises_destroying_state() {
        let f = InfraFacet::new(["aws.rds.*"]);
        let e = effect("aws_db_instance", Verb::Replace);
        assert_eq!(
            f.admits(&e, Gravity::DestroysState),
            Err(Denial::WildcardIsNotEnough {
                matched: "aws.rds.*".into(),
                why: Gravity::DestroysState,
            })
        );
        // Spelled out, it is authorised.
        let explicit = InfraFacet::new(["aws.rds.replace"]);
        assert!(explicit.admits(&e, Gravity::DestroysState).is_ok());
    }

    /// The same rule, for the other reason (#4) — and the refusal must
    /// say which. Telling an operator that creating an ECS service
    /// destroys stateful infrastructure is a lie they have to spend
    /// time disproving.
    #[test]
    fn an_unpriced_change_is_refused_for_its_own_reason() {
        let f = InfraFacet::new(["aws.ecs.*"]);
        let e = effect("aws_ecs_service", Verb::Create);

        assert!(f.admits(&e, Gravity::Routine).is_ok(), "priced, it passes");

        let denial = f.admits(&e, Gravity::Unpriced).unwrap_err();
        assert_eq!(
            denial,
            Denial::WildcardIsNotEnough {
                matched: "aws.ecs.*".into(),
                why: Gravity::Unpriced,
            }
        );
        let said = denial.to_string();
        assert!(said.contains("priced"), "{said}");
        assert!(
            !said.contains("destruction"),
            "a create destroys nothing: {said}"
        );

        // Naming the verb authorises it unpriced — the operator saying
        // they accept this one without an estimate.
        assert!(InfraFacet::new(["aws.ecs.create"])
            .admits(&e, Gravity::Unpriced)
            .is_ok());
    }

    #[test]
    fn a_wildcard_still_covers_destruction_of_stateless_things() {
        let f = InfraFacet::new(["aws.ecs.*"]);
        assert!(f
            .admits(&effect("aws_ecs_service", Verb::Delete), Gravity::Routine)
            .is_ok());
    }

    #[test]
    fn an_unreadable_effect_is_denied_not_guessed() {
        let f = InfraFacet::new(["*.*.*"]);
        // A type with no underscore yields an empty service.
        let e = Effect::new("weird", Verb::Delete, "addr");
        assert!(matches!(
            f.admits(&e, Gravity::DestroysState),
            Err(Denial::Unreadable(_))
        ));
    }

    #[test]
    fn malformed_allow_entries_grant_nothing_and_are_surfaced() {
        let f = InfraFacet::new(["aws.*", "aws.ecs.update"]);
        assert_eq!(f.malformed_entries(), vec!["aws.*"]);
        // The two-segment entry admits nothing at all.
        assert!(f
            .admits(&effect("aws_iam_role", Verb::Update), Gravity::Routine)
            .is_err());
        assert!(f
            .admits(&effect("aws_ecs_service", Verb::Update), Gravity::Routine)
            .is_ok());
    }

    // ---- narrowing ---------------------------------------------------

    #[test]
    fn a_child_may_tighten_a_wildcard_to_a_verb() {
        let parent = InfraFacet::new(["aws.ecs.*", "aws.iam.read"]);
        let child = InfraFacet::new(["aws.ecs.update"]);
        assert!(InfraFacet::validate_narrowing(&parent, &child).is_ok());
    }

    #[test]
    fn a_child_may_not_widen_a_verb_to_a_wildcard() {
        let parent = InfraFacet::new(["aws.ecs.update"]);
        let child = InfraFacet::new(["aws.ecs.*"]);
        let err = InfraFacet::validate_narrowing(&parent, &child).unwrap_err();
        assert_eq!(err.facet, "infra");
        assert!(err.detail.contains("aws.ecs.*"), "{}", err.detail);
    }

    #[test]
    fn a_child_may_not_claim_a_service_the_parent_never_granted() {
        let parent = InfraFacet::new(["aws.ecs.*"]);
        let child = InfraFacet::new(["aws.rds.delete"]);
        assert!(InfraFacet::validate_narrowing(&parent, &child).is_err());
    }

    #[test]
    fn scope_narrows_on_account_and_region() {
        let parent = InfraFacet {
            allow: vec!["aws.ecs.*".into()],
            scope: Scope {
                account: Some("123456789012".into()),
                region: vec!["eu-west-1".into(), "eu-west-2".into()],
            },
            ..InfraFacet::default()
        };

        let ok = InfraFacet {
            allow: vec!["aws.ecs.update".into()],
            scope: Scope {
                account: Some("123456789012".into()),
                region: vec!["eu-west-1".into()],
            },
            ..InfraFacet::default()
        };
        assert!(InfraFacet::validate_narrowing(&parent, &ok).is_ok());

        // Another account.
        let other_account = InfraFacet {
            scope: Scope {
                account: Some("999999999999".into()),
                ..ok.scope.clone()
            },
            ..ok.clone()
        };
        assert!(InfraFacet::validate_narrowing(&parent, &other_account).is_err());

        // A region the parent never allowed.
        let other_region = InfraFacet {
            scope: Scope {
                region: vec!["us-east-1".into()],
                ..ok.scope.clone()
            },
            ..ok.clone()
        };
        assert!(InfraFacet::validate_narrowing(&parent, &other_region).is_err());

        // Dropping the constraint entirely is widening, not narrowing.
        let unconstrained = InfraFacet {
            allow: vec!["aws.ecs.update".into()],
            scope: Scope::default(),
            ..InfraFacet::default()
        };
        assert!(InfraFacet::validate_narrowing(&parent, &unconstrained).is_err());
    }
}
