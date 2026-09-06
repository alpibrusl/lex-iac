//! The grant manifest a run is authorised by — which is
//! [`lex_os_manifest::Manifest`], not a type of this crate's own.
//!
//! # One manifest, many facets
//!
//! Milestone 2 shipped a parallel `InfraManifest` here, because lex-os
//! had the [`Facet`] trait and the lattice primitives but no open slot
//! on `Manifest` for a facet it did not itself know about. That was a
//! near-miss against the ADR's rule — *a facet lives on the same
//! manifest, folds into the same `ManifestId`, and is narrowed by the
//! same wall* — and it is now closed: lex-os#71 added
//! `Manifest::facets`, and this module is what remains of the parallel
//! type.
//!
//! What remains is deliberately small. This crate contributes the
//! *rule* for its own domain ([`InfraFacet`]'s [`Facet`] impl) and the
//! [`registry`] that teaches lex-os how to narrow it. It contributes no
//! manifest, no content-addressing scheme, and no second budget or
//! trust-lattice comparison — those exist once, in lex-os, and a gate
//! that restated them would be a gate that could drift from them.
//!
//! A grant file here is therefore a lex-os manifest and nothing else:
//! the same JSON `lex-os run` would take, carrying one extra facet.
//!
//! ```
//! use lex_iac::{manifest, InfraFacet};
//! use lex_os_manifest::{Budget, Goal, Grant, Level, Manifest};
//!
//! let parent = Manifest::new(
//!     Goal::new("manage the payments stack"),
//!     Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
//!     Budget::research_default(),
//! )
//! .with_facet(&InfraFacet::new(["aws.ecs.*", "aws.iam.read"]))
//! .unwrap();
//!
//! let child = parent
//!     .clone()
//!     .with_facet(&InfraFacet::new(["aws.rds.delete"]))
//!     .unwrap();
//!
//! assert!(manifest::narrow(&parent, &child).is_err());
//! ```

use lex_os_manifest::{facet::FacetRegistry, Manifest, ManifestError};

use crate::InfraFacet;

/// The facets this gate knows how to narrow.
///
/// lex-os's slot is type-erased on purpose — it must not learn what
/// Terraform is — so narrowing `infra` needs the decision procedure
/// supplied from here. A facet lex-os does *not* find in this registry
/// is not thereby waved through: it has to be byte-identical between
/// parent and child.
pub fn registry() -> FacetRegistry {
    FacetRegistry::new().with::<InfraFacet>()
}

/// Is `child` a well-formed narrowing of `parent`?
///
/// Every wall is lex-os's: the trust lattice, the budget ceilings, the
/// egress allowlist, actuation, and — through [`registry`] — this
/// crate's `infra` facet. The gate adds a domain, not a second opinion
/// about what narrowing means.
pub fn narrow(parent: &Manifest, child: &Manifest) -> Result<(), ManifestError> {
    Manifest::validate_narrowing_with(parent, child, &registry())
}

/// The infrastructure authority a manifest carries.
///
/// Three cases, and the middle one is the one worth stating:
///
/// - **absent** — an empty facet. The manifest authorises no
///   infrastructure effect at all, so every mutating row is refused
///   with a reason naming an empty allow-list. That is a *decision*,
///   recorded like any other, not an error.
/// - **present and readable** — the facet.
/// - **present and unreadable** — an error. A manifest that declares
///   authority in a shape this build cannot parse must not be read as
///   granting nothing *or* as granting everything; the gate cannot run.
///   Refuse, don't downgrade.
pub fn infra_facet(m: &Manifest) -> Result<InfraFacet, ManifestError> {
    m.facet::<InfraFacet>()
        .unwrap_or_else(|| Ok(InfraFacet::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{facet::FacetError, Budget, Goal, Grant, Level};

    fn manifest(allow: &[&str], cents: u64) -> Manifest {
        Manifest::new(
            Goal::new("rotate the payments API"),
            Grant::new(Level::None, Level::Allowlist, Level::None),
            Budget {
                wall_clock_secs: 900,
                max_commands: 50,
                max_money_cents: cents,
                max_api_calls: 200,
            },
        )
        .with_facet(&InfraFacet::new(allow.iter().copied()))
        .expect("the facet serialises")
    }

    #[test]
    fn a_tighter_child_is_accepted() {
        let parent = manifest(&["aws.ecs.*", "aws.iam.read"], 5000);
        let child = manifest(&["aws.ecs.update"], 1000);
        assert!(narrow(&parent, &child).is_ok());
    }

    #[test]
    fn a_ci_job_cannot_mint_itself_rds() {
        let parent = manifest(&["aws.ecs.*"], 5000);
        let child = manifest(&["aws.ecs.*", "aws.rds.delete"], 5000);
        let err = narrow(&parent, &child).unwrap_err();
        assert!(
            matches!(&err, ManifestError::Facet(f) if f.facet == "infra"),
            "expected an infra facet refusal, got {err}"
        );
    }

    /// The walls this crate does *not* implement still hold, because
    /// they are lex-os's and we call into them rather than restating
    /// them. This test exists to catch the collapse having quietly
    /// dropped one.
    #[test]
    fn budgets_and_the_lattice_narrow_too() {
        let parent = manifest(&["aws.ecs.*"], 5000);

        let richer = manifest(&["aws.ecs.*"], 999_999);
        assert!(matches!(
            narrow(&parent, &richer).unwrap_err(),
            ManifestError::BudgetWidens { .. }
        ));

        let mut wider_grant = manifest(&["aws.ecs.*"], 5000);
        wider_grant.grant = Grant::new(Level::Full, Level::Full, Level::Full);
        assert!(matches!(
            narrow(&parent, &wider_grant).unwrap_err(),
            ManifestError::Trust(_)
        ));
    }

    /// Without the registry, lex-os has no procedure for `infra` — and
    /// refuses a child that differs at all, rather than guessing. Safe,
    /// not permissive: it refuses even this genuinely *narrower* child.
    #[test]
    fn without_the_registry_a_differing_facet_is_refused_not_waved_through() {
        let parent = manifest(&["aws.ecs.*", "aws.iam.read"], 5000);
        let child = manifest(&["aws.ecs.update"], 1000);
        assert!(narrow(&parent, &child).is_ok());
        assert!(matches!(
            Manifest::validate_narrowing(&parent, &child).unwrap_err(),
            ManifestError::Facet(FacetError { .. })
        ));
    }

    #[test]
    fn the_manifest_id_folds_the_facet_in() {
        let a = manifest(&["aws.ecs.*"], 5000);
        let b = manifest(&["aws.ecs.*", "aws.rds.replace"], 5000);
        assert_ne!(
            a.content_id(),
            b.content_id(),
            "a manifest granting more infrastructure authority is not the same manifest"
        );
    }

    #[test]
    fn a_manifest_without_the_facet_authorises_nothing() {
        let bare = Manifest::new(
            Goal::new("no infrastructure authority at all"),
            Grant::new(Level::None, Level::None, Level::None),
            Budget::research_default(),
        );
        assert!(infra_facet(&bare).unwrap().allow.is_empty());
    }

    #[test]
    fn a_facet_this_build_cannot_read_is_an_error_not_an_empty_grant() {
        let mut m = manifest(&["aws.ecs.*"], 5000);
        m.facets
            .insert("infra".into(), serde_json::json!({ "allow": "aws.ecs.*" }));
        assert!(
            infra_facet(&m).is_err(),
            "an unreadable facet must not read as granting nothing, nor as granting everything"
        );
    }
}
