//! **lex-iac** — a capability gate between `terraform plan` and
//! `terraform apply`.
//!
//! Infrastructure-as-code already has an effect system. It has no type
//! checker. This is the type checker's front half: a plan compiles to a
//! set of typed effect rows, each classified by blast radius, so a later
//! stage can check them against the grant that authorises the run.
//!
//! [`compile_str`] is the front half: a pure function over plan JSON —
//! no cloud access, no credentials, no state backend. [`check`] is the
//! back half, holding those rows against a [`Manifest`]'s `infra` facet.
//!
//! ```
//! use lex_iac::compile_str;
//!
//! let plan = r#"{
//!   "resource_changes": [
//!     { "address": "aws_db_instance.main", "type": "aws_db_instance",
//!       "mode": "managed", "change": { "actions": ["delete", "create"] } }
//!   ]
//! }"#;
//!
//! let compiled = compile_str(plan).unwrap();
//! assert_eq!(compiled.rows[0].effect.qualified(), "aws.rds.replace");
//! assert!(compiled.has_consequential());
//! ```

pub mod apply;
pub mod classify;
pub mod cost;
pub mod effect;
pub mod facet;
pub mod gate;
pub mod ledger;
pub mod manifest;
pub mod plan;
pub mod pulumi;
pub mod resource;
pub mod state;
pub mod trust;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use apply::{
    apply_argv, artifact_matches, derive_plan_json, permits_apply, resolve_box_path, Approval,
    BoxSpec,
};
pub use classify::classify;
pub use cost::{CostError, CostReport};
pub use effect::Effect;
pub use facet::{Denial, Gravity, InfraFacet, Scope};
pub use gate::{
    check, check_sealed, Decision, GateError, PlanEvent, Refusal, Verdict, Wall, PLAN_AUDIT_DOMAIN,
};
pub use manifest::{infra_facet, narrow, registry};
pub use plan::{Plan, PlanError, Verb};
pub use resource::ResourceKey;
pub use trust::{Keyring, Standing, Submitter, TrustError};

/// The manifest a run is authorised by is lex-os's, not this crate's.
/// Re-exported so a consumer needs one dependency, not two, and so the
/// identity of the type is unambiguous: there is exactly one.
pub use lex_os_manifest::{Manifest, Reversibility};
// Re-exported so a consumer sealing this gate's logs needs no direct
// dependency on ed25519 — two crates on two versions of it would stop
// verifying each other's records.
pub use lex_os_audit::{Chain, Checkpoint, SigningKey, VerifyingKey};

/// Re-exported so a consumer inspecting the audit chain needs one
/// dependency, not two.
pub use lex_os_audit;

/// One resource change, compiled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectRow {
    pub effect: Effect,
    pub reversibility: Reversibility,
    /// The plan address, kept alongside the scoped effect so a refusal
    /// can name the exact line an operator has to look at.
    pub address: String,
    /// The raw Terraform type, before the provider/service split.
    pub resource_type: String,
    /// The provider's Terraform source address, as the plan reports it
    /// — `registry.terraform.io/hetznercloud/hcloud`.
    ///
    /// Carried because a provider is code the run *executes* with the
    /// credentials, so which one it is is a provenance fact the mandate
    /// may want to bound. Empty when the plan does not say, which is
    /// treated as unreadable rather than as any particular provider.
    #[serde(default)]
    pub provider: String,
    /// True when this build has no opinion about `resource_type`.
    ///
    /// Its destruction was already classified consequential; this flag
    /// exists so a policy can also escalate on *creating* one, and so a
    /// refusal can distinguish "we classified this" from "we have never
    /// seen this".
    pub unknown_type: bool,
}

/// A whole plan, compiled: the effect rows plus the identity of the
/// bytes they came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPlan {
    /// Hex SHA-256 of the exact plan JSON compiled.
    ///
    /// An acceptance is only ever an acceptance of *these* bytes. A
    /// substituted plan must not inherit it — the same rule the capsule
    /// contract applies to an archive.
    pub plan_sha256: String,
    pub terraform_version: String,
    pub rows: Vec<EffectRow>,
}

impl CompiledPlan {
    /// Every distinct `provider.service.verb` this plan needs, sorted.
    /// This is the set a grant is checked against.
    pub fn required_effects(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .rows
            .iter()
            .filter(|r| r.effect.verb.mutates())
            .map(|r| r.effect.qualified())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Rows at the given class, worst-first order being the caller's
    /// business.
    pub fn rows_at(&self, class: Reversibility) -> Vec<&EffectRow> {
        self.rows
            .iter()
            .filter(|r| r.reversibility == class)
            .collect()
    }

    /// Does anything here destroy state that re-running cannot restore?
    ///
    /// `IrreversibleConsequential` is refused by construction unless the
    /// grant bounds it, so this is the question a gate asks first.
    pub fn has_consequential(&self) -> bool {
        self.rows
            .iter()
            .any(|r| r.reversibility == Reversibility::IrreversibleConsequential)
    }

    /// Rows whose resource type this build does not recognise.
    pub fn unknown_types(&self) -> Vec<&EffectRow> {
        self.rows.iter().filter(|r| r.unknown_type).collect()
    }
}

/// Which tool produced a plan document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    Terraform,
    Pulumi,
}

/// Recognise the frontend from the shape of the document.
///
/// Detection rather than a `--format` flag, because the two shapes are
/// unambiguous and a flag is one more thing to get wrong in a pipeline
/// — with the failure mode being that the gate reads the wrong half of
/// a document. A file carrying *both* marker fields is refused rather
/// than resolved by precedence: see [`PlanError::Ambiguous`].
pub fn detect(src: &str) -> Result<Frontend, PlanError> {
    let raw: serde_json::Value = serde_json::from_str(src)?;
    match (
        raw.get("resource_changes").is_some(),
        raw.get("steps").is_some(),
    ) {
        (true, false) => Ok(Frontend::Terraform),
        (false, true) => Ok(Frontend::Pulumi),
        (true, true) => Err(PlanError::Ambiguous),
        (false, false) => Err(PlanError::NotAPlan),
    }
}

/// Compile a plan from whichever frontend produced it.
///
/// This is the whole of what milestone 5 added to the gate's path: one
/// dispatch. `check`, `InfraFacet` and the grant format were not
/// touched, which is the claim the milestone existed to test.
pub fn compile_any(src: &str) -> Result<CompiledPlan, PlanError> {
    match detect(src)? {
        Frontend::Terraform => compile_str(src),
        Frontend::Pulumi => pulumi::compile_str(src),
    }
}

/// Compile plan JSON to effect rows.
///
/// Pure: no network, no filesystem, no cloud credentials. The only
/// failure mode is JSON that will not parse.
pub fn compile_str(src: &str) -> Result<CompiledPlan, PlanError> {
    let plan = Plan::from_json(src)?;
    Ok(compile(&plan, src))
}

/// Compile an already-parsed plan, pinning `raw` as the identity of the
/// bytes. Prefer [`compile_str`] unless you parsed the plan yourself.
pub fn compile(plan: &Plan, raw: &str) -> CompiledPlan {
    let rows = plan
        .resource_changes
        .iter()
        .map(|rc| {
            let verb = rc.verb();
            let key = ResourceKey::from_terraform(&rc.r#type);
            EffectRow {
                effect: Effect::new(&rc.r#type, verb, &rc.address),
                reversibility: classify(&key, verb, &rc.mode),
                address: rc.address.clone(),
                resource_type: rc.r#type.clone(),
                provider: rc.provider_name.clone(),
                unknown_type: !classify::is_known(&key),
            }
        })
        .collect();

    CompiledPlan {
        plan_sha256: sha256_hex(raw),
        terraform_version: plan.terraform_version.clone(),
        rows,
    }
}

/// The digest an approval records for the mandate it was judged against.
///
/// Its own function so both the writer and the reader of an approval
/// spell it the same way; a mismatch here would silently refuse every
/// apply, which is a bad failure to debug.
pub fn manifest_digest(src: &str) -> String {
    sha256_hex(src)
}

pub(crate) fn sha256_hex(src: &str) -> String {
    sha256_bytes(src.as_bytes())
}

/// The same digest over bytes rather than text.
///
/// A saved terraform plan is a binary artifact, not a document, so the
/// text-shaped helper cannot hash the thing that actually gets applied.
pub(crate) fn sha256_bytes(src: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(src);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plan_hash_pins_the_exact_bytes() {
        let a = compile_str(r#"{"resource_changes":[]}"#).unwrap();
        let b = compile_str(r#"{"resource_changes":[] }"#).unwrap();
        assert_ne!(
            a.plan_sha256, b.plan_sha256,
            "a byte difference must change the identity, even when the plans are equivalent"
        );
    }

    #[test]
    fn required_effects_ignores_reads_and_noops() {
        let plan = r#"{"resource_changes":[
            {"address":"a","type":"aws_s3_bucket","mode":"managed","change":{"actions":["no-op"]}},
            {"address":"b","type":"aws_iam_role","mode":"data","change":{"actions":["read"]}},
            {"address":"c","type":"aws_ecs_service","mode":"managed","change":{"actions":["update"]}}
        ]}"#;
        let c = compile_str(plan).unwrap();
        assert_eq!(c.required_effects(), vec!["aws.ecs.update"]);
    }

    #[test]
    fn effects_are_deduplicated() {
        let plan = r#"{"resource_changes":[
            {"address":"a","type":"aws_ecs_service","mode":"managed","change":{"actions":["update"]}},
            {"address":"b","type":"aws_ecs_service","mode":"managed","change":{"actions":["update"]}}
        ]}"#;
        let c = compile_str(plan).unwrap();
        assert_eq!(c.required_effects(), vec!["aws.ecs.update"]);
    }

    #[test]
    fn an_empty_plan_needs_no_authority() {
        let c = compile_str(r#"{"resource_changes":[]}"#).unwrap();
        assert!(c.required_effects().is_empty());
        assert!(!c.has_consequential());
    }
}
