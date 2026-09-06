//! The gate: plan in, verdict out, with the record written first.
//!
//! ```text
//! plan_requested                       ← logged BEFORE any gate decides
//!   → effects        plan → effect rows                        (#2)
//!   → narrowing      every effect ⊆ the infra facet
//!   → reversibility  destroying state needs the verb named
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
//! **A verdict is `Allow`, `Deny` or `Inconclusive`.** The third is
//! borrowed from `lex-guard`, which had it right: something the gate
//! cannot *read* is not thereby harmless. Inconclusive refuses, and
//! carries why — "refuse, don't downgrade" in the type rather than in a
//! comment.

use lex_os_audit::{Chain, ChainPayload};
use lex_os_manifest::{Manifest, ManifestError, Reversibility};
use serde::{Deserialize, Serialize};

use crate::{
    compile_str, manifest::infra_facet, CompiledPlan, Denial, EffectRow, InfraFacet, PlanError,
};

/// What this gate records. lex-os knows nothing about any of it — which
/// is why `Chain<E>` is generic (lex-os#67).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanEvent {
    /// Written before anything is decided. `plan_sha256` is the identity
    /// of the exact bytes; an acceptance authorises only these.
    PlanRequested {
        plan_sha256: String,
        manifest: String,
        goal: String,
        effects: Vec<String>,
    },
    PlanAccepted {
        plan_sha256: String,
        manifest: String,
    },
    /// Refused, naming the single effect that tripped the wall — the
    /// operator needs one line to look at, not a verdict on the plan.
    PlanRefused {
        plan_sha256: String,
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
}

/// Which wall a refusal hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Wall {
    /// The effect is outside the grant.
    Narrowing,
    /// The effect destroys state the grant does not name explicitly.
    Reversibility,
    /// The gate could not read the effect well enough to check it.
    Unreadable,
}

impl Wall {
    pub fn as_str(self) -> &'static str {
        match self {
            Wall::Narrowing => "narrowing",
            Wall::Reversibility => "reversibility",
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
/// The only error is a plan that will not parse; a plan that parses but
/// over-reaches is a `Deny`, not an `Err`. That distinction matters: a
/// refusal is a normal, recorded outcome, and conflating it with a
/// malfunction is how refusals end up unlogged.
pub fn check(plan_json: &str, manifest: &Manifest) -> Result<Decision, GateError> {
    let plan = compile_str(plan_json)?;
    // Read the authority before writing anything: a manifest whose
    // facet will not parse means the gate cannot run, and a request
    // record would claim it did.
    let infra = infra_facet(manifest)?;

    let mut audit: Chain<PlanEvent> = Chain::new();
    let manifest_id = manifest.content_id().0;

    // Logged before any gate runs.
    audit.append(PlanEvent::PlanRequested {
        plan_sha256: plan.plan_sha256.clone(),
        manifest: manifest_id.clone(),
        goal: manifest.goal.description.clone(),
        effects: plan.required_effects(),
    });

    let refusals: Vec<Refusal> = plan
        .rows
        .iter()
        .filter(|row| row.effect.verb.mutates())
        .filter_map(|row| refuse(row, &infra))
        .collect();

    let verdict = match refusals.split_first() {
        None => {
            audit.append(PlanEvent::PlanAccepted {
                plan_sha256: plan.plan_sha256.clone(),
                manifest: manifest_id,
            });
            Verdict::Allow
        }
        Some((first, _)) => {
            audit.append(PlanEvent::PlanRefused {
                plan_sha256: plan.plan_sha256.clone(),
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
    })
}

/// Is this row refused, and why?
fn refuse(row: &EffectRow, infra: &InfraFacet) -> Option<Refusal> {
    let destroys = row.reversibility == Reversibility::IrreversibleConsequential;
    match infra.admits(&row.effect, destroys) {
        Ok(()) => None,
        Err(denial) => {
            let wall = match &denial {
                Denial::NotGranted => Wall::Narrowing,
                Denial::WildcardCannotAuthoriseDestruction { .. } => Wall::Reversibility,
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
        let d = check(ROTATE, &manifest(&["aws.ecs.*"])).unwrap();
        assert!(d.verdict.allowed());
        assert_eq!(d.exit_code(), 0);
        assert_eq!(d.audit.len(), 2);
        d.audit.verify().expect("the chain verifies");
    }

    /// The headline case: a broad grant does not silently cover
    /// destroying a database.
    #[test]
    fn a_wildcard_grant_does_not_authorise_the_hidden_replace() {
        let d = check(REPLACE_DB, &manifest(&["aws.ecs.*", "aws.rds.*"])).unwrap();
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
        let d = check(REPLACE_DB, &manifest(&["aws.ecs.*", "aws.rds.replace"])).unwrap();
        assert!(d.verdict.allowed(), "{:?}", d.verdict);
    }

    #[test]
    fn an_effect_outside_the_grant_hits_the_narrowing_wall() {
        let d = check(ROTATE, &manifest(&["aws.iam.read"])).unwrap();
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
        let d = check(REPLACE_DB, &manifest(&["aws.ecs.*"])).unwrap();
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
        let d = check(REPLACE_DB, &manifest(&["gcp.sql.create"])).unwrap();
        let Verdict::Deny { all, .. } = &d.verdict else {
            panic!("expected a refusal");
        };
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn an_empty_plan_is_allowed() {
        let d = check(r#"{"resource_changes":[]}"#, &manifest(&[])).unwrap();
        assert!(d.verdict.allowed());
    }

    #[test]
    fn a_malformed_plan_is_an_error_not_a_verdict() {
        assert!(check("{not json", &manifest(&["aws.ecs.*"])).is_err());
    }

    /// A refusal pins the same bytes the request did, so an accepted
    /// plan cannot be swapped for another after the fact.
    #[test]
    fn the_audit_record_pins_the_plan_bytes() {
        let d = check(ROTATE, &manifest(&["aws.ecs.*"])).unwrap();
        let PlanEvent::PlanRequested { plan_sha256, .. } = &d.audit.entries()[0].event else {
            panic!("expected plan_requested");
        };
        assert_eq!(plan_sha256, &d.plan.plan_sha256);
        assert_eq!(plan_sha256.len(), 64);
    }
}
