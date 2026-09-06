//! The grant manifest a run is authorised by.
//!
//! Reuses lex-os's [`Grant`] (the trust lattice) and [`Budget`] rather
//! than restating them, and carries the [`InfraFacet`] as its authority
//! over infrastructure.
//!
//! # Why this is not `lex_os_manifest::Manifest`
//!
//! It should be. The ADR's rule is "a facet lives on the same manifest,
//! folds into the same `ManifestId`, and is narrowed by the same wall",
//! and lex-os#66 delivered the [`Facet`] trait, the lattice primitives
//! and the narrowing wiring — but not an open slot on `Manifest` for
//! facets it does not itself know about. `Manifest` has a concrete
//! `actuation` field and nowhere to put `infra`.
//!
//! So this type exists as the near-miss it is, tracked by
//! alpibrusl/lex-os#71. It deliberately mirrors the same shape and uses
//! the same primitives, so collapsing it into `Manifest` later is a
//! move rather than a rewrite. Until then, "one manifest, many facets"
//! is true of the *mechanism* and not yet of the type.

use lex_os_manifest::{Budget, Facet, Grant, ManifestError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::InfraFacet;

/// Goal, grant, budget, and the infra facet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfraManifest {
    /// What the run is for. Free text; carried into the audit record so
    /// a refusal can be read against its intent.
    #[serde(default)]
    pub goal: String,
    /// The trust lattice, governing the *apply* step itself rather than
    /// the plan's contents — network and exec reach when the apply
    /// eventually runs in a box (milestone 6).
    pub grant: Grant,
    pub budget: Budget,
    pub infra: InfraFacet,
}

impl InfraManifest {
    pub fn from_json(src: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(src)
    }

    /// Canonical JSON, then SHA-256. The handle an audit record pins.
    pub fn content_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"lex.iac.manifest.v1");
        h.update(
            serde_json::to_string(self)
                .expect("manifest is serializable")
                .as_bytes(),
        );
        hex::encode(h.finalize())
    }

    /// Is `child` a well-formed narrowing of `parent` across every
    /// dimension it could try to widen?
    ///
    /// The same three walls lex-os applies — the trust lattice, the
    /// budget ceilings, and the facets — with the infra facet standing
    /// where actuation stands there.
    pub fn validate_narrowing(parent: &Self, child: &Self) -> Result<(), ManifestError> {
        Grant::narrow(&parent.grant, &child.grant)?;

        let checks: [(&'static str, u64, u64); 4] = [
            (
                "wall_clock_secs",
                parent.budget.wall_clock_secs,
                child.budget.wall_clock_secs,
            ),
            (
                "max_commands",
                parent.budget.max_commands,
                child.budget.max_commands,
            ),
            (
                "max_money_cents",
                parent.budget.max_money_cents,
                child.budget.max_money_cents,
            ),
            (
                "max_api_calls",
                parent.budget.max_api_calls,
                child.budget.max_api_calls,
            ),
        ];
        for (field, p, c) in checks {
            if c > p {
                return Err(ManifestError::BudgetWidens {
                    field,
                    parent: p,
                    requested: c,
                });
            }
        }

        InfraFacet::validate_narrowing(&parent.infra, &child.infra)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::Level;

    fn manifest(allow: &[&str], cents: u64) -> InfraManifest {
        InfraManifest {
            goal: "rotate the payments API".into(),
            grant: Grant::new(Level::None, Level::Allowlist, Level::None),
            budget: Budget {
                wall_clock_secs: 900,
                max_commands: 50,
                max_money_cents: cents,
                max_api_calls: 200,
            },
            infra: InfraFacet::new(allow.iter().copied()),
        }
    }

    #[test]
    fn a_tighter_child_is_accepted() {
        let parent = manifest(&["aws.ecs.*", "aws.iam.read"], 5000);
        let child = manifest(&["aws.ecs.update"], 1000);
        assert!(InfraManifest::validate_narrowing(&parent, &child).is_ok());
    }

    #[test]
    fn a_ci_job_cannot_mint_itself_rds() {
        let parent = manifest(&["aws.ecs.*"], 5000);
        let child = manifest(&["aws.ecs.*", "aws.rds.delete"], 5000);
        let err = InfraManifest::validate_narrowing(&parent, &child).unwrap_err();
        assert!(
            matches!(&err, ManifestError::Facet(f) if f.facet == "infra"),
            "expected an infra facet refusal, got {err}"
        );
    }

    #[test]
    fn budgets_and_the_lattice_narrow_too() {
        let parent = manifest(&["aws.ecs.*"], 5000);

        let richer = manifest(&["aws.ecs.*"], 999_999);
        assert!(matches!(
            InfraManifest::validate_narrowing(&parent, &richer).unwrap_err(),
            ManifestError::BudgetWidens { .. }
        ));

        let mut wider_grant = manifest(&["aws.ecs.*"], 5000);
        wider_grant.grant = Grant::new(Level::Full, Level::Full, Level::Full);
        assert!(matches!(
            InfraManifest::validate_narrowing(&parent, &wider_grant).unwrap_err(),
            ManifestError::Trust(_)
        ));
    }

    #[test]
    fn the_content_id_changes_with_the_grant() {
        let a = manifest(&["aws.ecs.*"], 5000);
        let b = manifest(&["aws.ecs.*", "aws.rds.replace"], 5000);
        assert_ne!(a.content_id(), b.content_id());
        assert_eq!(a.content_id().len(), 64);
    }
}
