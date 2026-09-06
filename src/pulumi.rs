//! The second frontend: `pulumi preview --json` (alpibrusl/lex-iac#10).
//!
//! This module exists to falsify a claim. The epic says the effect model
//! is not Terraform-shaped; nothing had tested that, because Terraform
//! was the only frontend. So: compile a Pulumi preview to the **same**
//! [`CompiledPlan`](crate::CompiledPlan) and hand it to the **same**
//! [`check`](crate::check).
//!
//! # What the test found
//!
//! The **effect vocabulary survived unchanged.** `provider.service.verb`
//! needed no new variants, no escape hatch and no Pulumi-specific
//! branch, and `check`, `InfraFacet` and the grant file format were not
//! touched. Better than that: Pulumi reaches `aws.rds.replace` from the
//! opposite direction — its types name the service outright, where
//! Terraform's `aws_db_instance` had to be told through an alias table.
//! Two spellings meeting on one effect is the actual evidence.
//!
//! The **classification tables did not survive.** They were lists of
//! Terraform type strings, so every Pulumi type missed and every
//! teardown classified consequential. That is recorded in
//! [`crate::resource`], which is the fix: a canonical key both frontends
//! map onto.
//!
//! # Pulumi spells a replacement three ways
//!
//! One logical replacement can appear as `replace`, and *also* as
//! `create-replacement` and `delete-replaced` for the same URN — the
//! engine reports both the summary and the two halves. Compiling those
//! to a create, a delete and a replace would triple-count the authority
//! a plan needs and, worse, let `create-replacement` read as a plain
//! create if the summary step were missing.
//!
//! So steps are folded per URN, worst verb winning. That is the same
//! collapse `["delete","create"]` already gets in the Terraform reader,
//! arrived at independently — which is its own small piece of evidence
//! that the model is not accidental.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::plan::{PlanError, Verb};
use crate::resource::ResourceKey;
use crate::{classify, CompiledPlan, Effect, EffectRow};

/// A `pulumi preview --json` document, reduced to what carries
/// authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preview {
    /// The proposed changes. Deliberately **not** `#[serde(default)]`:
    /// a document without it is not a preview with nothing in it. Same
    /// rule as the Terraform reader (#8).
    pub steps: Vec<Step>,
    #[serde(default)]
    pub change_summary: BTreeMap<String, i64>,
}

/// One engine step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// `create`, `update`, `delete`, `replace`, `same`, … See
    /// [`verb_of`].
    #[serde(default)]
    pub op: Option<String>,
    /// `urn:pulumi:<stack>::<project>::<parent$>type::<name>`.
    #[serde(default)]
    pub urn: String,
    #[serde(default)]
    pub new_state: Option<State>,
    #[serde(default)]
    pub old_state: Option<State>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// `aws:rds/instance:Instance`.
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub urn: String,
}

impl Preview {
    /// Parse `pulumi preview --json` output.
    ///
    /// The `steps` membership test runs before deserialising, so the
    /// refusal speaks the caller's vocabulary rather than serde's, and
    /// so a top-level JSON array lands there too.
    pub fn from_json(src: &str) -> Result<Self, PlanError> {
        let raw: serde_json::Value = serde_json::from_str(src)?;
        if raw.get("steps").is_none() {
            return Err(PlanError::NotAPlan);
        }
        Ok(serde_json::from_value(raw)?)
    }
}

impl Step {
    /// The resource type, wherever this step carries it.
    ///
    /// A delete step has only `oldState`; a create has only `newState`.
    /// Falling back to the URN matters more than it looks: a step whose
    /// states are elided still names its type there, and a reader that
    /// gave up would classify it unknown and refuse the whole plan.
    pub fn resource_type(&self) -> String {
        for state in [self.new_state.as_ref(), self.old_state.as_ref()]
            .into_iter()
            .flatten()
        {
            if !state.r#type.is_empty() {
                return state.r#type.clone();
            }
        }
        type_from_urn(&self.urn)
    }

    /// The last `::`-delimited segment: Pulumi's resource name.
    pub fn name(&self) -> String {
        self.urn
            .rsplit("::")
            .next()
            .unwrap_or(&self.urn)
            .to_string()
    }
}

/// `urn:pulumi:dev::proj::aws:rds/instance:Instance::payments` → the
/// type segment.
///
/// The URN's second-to-last `::` field is the type, optionally prefixed
/// by a `$`-separated parent chain when the resource is a child.
fn type_from_urn(urn: &str) -> String {
    let fields: Vec<&str> = urn.split("::").collect();
    if fields.len() < 2 {
        return String::new();
    }
    let typed = fields[fields.len() - 2];
    // `aws:s3/bucket:Bucket$aws:s3/bucketObject:BucketObject` — the
    // resource's own type is the last link in the parent chain.
    typed.rsplit('$').next().unwrap_or(typed).to_string()
}

/// Map a Pulumi op to the shared [`Verb`].
///
/// The three replacement spellings all collapse to `Replace`. `same`
/// and `refresh` change nothing and must not consume authority.
/// Anything unrecognised is `Unknown`, which `classify` already treats
/// as consequential — refuse, don't downgrade.
pub fn verb_of(op: &str) -> Verb {
    match op {
        "same" => Verb::NoOp,
        "read" | "refresh" | "read-replacement" => Verb::Read,
        "create" => Verb::Create,
        "update" => Verb::Update,
        "delete" | "remove-pending-replace" => Verb::Delete,
        // All three faces of one replacement.
        "replace" | "create-replacement" | "delete-replaced" => Verb::Replace,
        // `import` brings an existing resource under management without
        // changing it, but `import-replacement` does replace.
        "import" => Verb::Read,
        "import-replacement" => Verb::Replace,
        _ => Verb::Unknown,
    }
}

/// How much authority a verb implies, for folding several steps on one
/// URN into the one that governs.
///
/// Ordering, not the lattice: `Unknown` outranks everything because a
/// step we cannot read must not be masked by a `same` on the same
/// resource.
fn gravity(v: Verb) -> u8 {
    match v {
        Verb::NoOp => 0,
        Verb::Read => 1,
        Verb::Update => 2,
        Verb::Create => 3,
        Verb::Delete => 4,
        Verb::Replace => 5,
        Verb::Unknown => 6,
    }
}

/// Compile a Pulumi preview to effect rows.
///
/// Pure, like its Terraform counterpart: no cloud access, no state
/// backend, no engine.
pub fn compile_str(src: &str) -> Result<CompiledPlan, PlanError> {
    let preview = Preview::from_json(src)?;
    Ok(compile(&preview, src))
}

/// Compile an already-parsed preview, pinning `raw` as the identity of
/// the bytes.
pub fn compile(preview: &Preview, raw: &str) -> CompiledPlan {
    // Fold per URN, worst verb winning, so a replacement reported as
    // three steps stays one effect.
    let mut folded: BTreeMap<String, (Verb, String)> = BTreeMap::new();
    for step in &preview.steps {
        let verb = step.op.as_deref().map(verb_of).unwrap_or(Verb::Unknown);
        let ty = step.resource_type();
        folded
            .entry(step.urn.clone())
            .and_modify(|(seen, seen_ty)| {
                if gravity(verb) > gravity(*seen) {
                    *seen = verb;
                }
                if seen_ty.is_empty() {
                    *seen_ty = ty.clone();
                }
            })
            .or_insert((verb, ty));
    }

    let rows = folded
        .iter()
        .map(|(urn, (verb, pulumi_type))| {
            let key = ResourceKey::from_pulumi(pulumi_type);
            let address = short_address(urn, pulumi_type);
            EffectRow {
                effect: Effect::from_key(&key, *verb, &address),
                // Pulumi has no `mode` field: a `read`/`import` step is
                // how it spells a data source, and `verb_of` has
                // already mapped those, so "managed" is right here.
                reversibility: classify::classify(&key, *verb, "managed"),
                address,
                resource_type: pulumi_type.clone(),
                unknown_type: !classify::is_known(&key),
            }
        })
        .collect();

    CompiledPlan {
        plan_sha256: crate::sha256_hex(raw),
        // Pulumi previews carry no engine version in the shape this
        // reads. Empty rather than invented.
        terraform_version: String::new(),
        rows,
    }
}

/// A URN is 100+ characters and an operator has to read this. Reduce it
/// to `type::name`, which is the part that identifies the resource.
fn short_address(urn: &str, pulumi_type: &str) -> String {
    let name = urn.rsplit("::").next().unwrap_or(urn);
    if pulumi_type.is_empty() {
        return name.to_string();
    }
    format!("{pulumi_type}::{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPLACE_DB: &str = r#"{
      "steps": [
        { "op": "same",
          "urn": "urn:pulumi:prod::payments::aws:ecs/cluster:Cluster::main",
          "newState": { "type": "aws:ecs/cluster:Cluster" } },
        { "op": "update",
          "urn": "urn:pulumi:prod::payments::aws:ecs/service:Service::api",
          "newState": { "type": "aws:ecs/service:Service" } },
        { "op": "replace",
          "urn": "urn:pulumi:prod::payments::aws:rds/instance:Instance::payments",
          "oldState": { "type": "aws:rds/instance:Instance" },
          "newState": { "type": "aws:rds/instance:Instance" } },
        { "op": "create-replacement",
          "urn": "urn:pulumi:prod::payments::aws:rds/instance:Instance::payments",
          "newState": { "type": "aws:rds/instance:Instance" } },
        { "op": "delete-replaced",
          "urn": "urn:pulumi:prod::payments::aws:rds/instance:Instance::payments",
          "oldState": { "type": "aws:rds/instance:Instance" } }
      ],
      "changeSummary": { "same": 1, "update": 1, "replace": 1 }
    }"#;

    /// The headline: one logical replacement reported three ways is one
    /// effect, not three.
    #[test]
    fn the_three_faces_of_a_replacement_fold_into_one() {
        let c = compile_str(REPLACE_DB).unwrap();
        assert_eq!(c.rows.len(), 3, "three resources, not five steps");
        assert_eq!(
            c.required_effects(),
            vec!["aws.ecs.update", "aws.rds.replace"]
        );

        let db = c
            .rows
            .iter()
            .find(|r| r.effect.verb == Verb::Replace)
            .expect("the database is replaced");
        assert_eq!(
            db.reversibility,
            lex_os_manifest::Reversibility::IrreversibleConsequential
        );
        assert!(!db.unknown_type, "aws.rds.instance is a known type");
    }

    /// `same` is not a change, and must not consume authority.
    #[test]
    fn same_and_refresh_ask_for_nothing() {
        let src = r#"{"steps":[
            {"op":"same","urn":"urn:pulumi:p::q::aws:s3/bucket:Bucket::data",
             "newState":{"type":"aws:s3/bucket:Bucket"}},
            {"op":"refresh","urn":"urn:pulumi:p::q::aws:ecs/service:Service::api",
             "newState":{"type":"aws:ecs/service:Service"}}
        ]}"#;
        let c = compile_str(src).unwrap();
        assert!(c.required_effects().is_empty());
        assert!(!c.has_consequential());
    }

    /// An op from a future Pulumi is not a licence to guess.
    #[test]
    fn an_unrecognised_op_is_consequential() {
        let src = r#"{"steps":[
            {"op":"quantum-entangle","urn":"urn:pulumi:p::q::aws:s3/bucket:Bucket::data",
             "newState":{"type":"aws:s3/bucket:Bucket"}}
        ]}"#;
        let c = compile_str(src).unwrap();
        assert!(c.has_consequential());
        assert_eq!(c.rows[0].effect.verb, Verb::Unknown);
    }

    /// ...and a step with no op at all is the same answer, for the same
    /// reason as a Terraform row with no `actions` (#8).
    #[test]
    fn a_step_with_no_op_is_unknown_not_harmless() {
        let src = r#"{"steps":[
            {"urn":"urn:pulumi:p::q::aws:s3/bucket:Bucket::data"}
        ]}"#;
        let c = compile_str(src).unwrap();
        assert_eq!(c.rows[0].effect.verb, Verb::Unknown);
        assert!(c.has_consequential());
    }

    /// A delete step carries only `oldState`; a reader that looked only
    /// at `newState` would lose the type and classify it unknown.
    #[test]
    fn a_delete_reads_its_type_from_the_old_state() {
        let src = r#"{"steps":[
            {"op":"delete","urn":"urn:pulumi:p::q::aws:ecs/service:Service::api",
             "oldState":{"type":"aws:ecs/service:Service"}}
        ]}"#;
        let c = compile_str(src).unwrap();
        assert_eq!(c.rows[0].effect.qualified(), "aws.ecs.delete");
        assert!(!c.rows[0].unknown_type);
        assert_eq!(
            c.rows[0].reversibility,
            lex_os_manifest::Reversibility::IrreversibleBounded,
            "ECS holds no durable state"
        );
    }

    /// ...and with both states elided, the URN still names the type.
    #[test]
    fn the_urn_is_the_fallback_for_the_type() {
        assert_eq!(
            type_from_urn("urn:pulumi:dev::proj::aws:rds/instance:Instance::payments"),
            "aws:rds/instance:Instance"
        );
        // A child resource carries its parent chain; its own type is
        // the last link.
        assert_eq!(
            type_from_urn(
                "urn:pulumi:dev::proj::aws:s3/bucket:Bucket$aws:s3/bucketObject:BucketObject::obj"
            ),
            "aws:s3/bucketObject:BucketObject"
        );
        assert_eq!(type_from_urn("nonsense"), "");

        let src = r#"{"steps":[
            {"op":"delete","urn":"urn:pulumi:p::q::aws:rds/instance:Instance::payments"}
        ]}"#;
        let c = compile_str(src).unwrap();
        assert_eq!(c.rows[0].effect.qualified(), "aws.rds.delete");
        assert!(!c.rows[0].unknown_type, "recovered from the URN");
    }

    /// The #8 rule, in the second frontend: a document that omits the
    /// field carrying authority is not a preview with nothing in it.
    #[test]
    fn a_document_without_steps_is_not_a_preview() {
        for not_a_preview in [
            r#"{}"#,
            r#"[]"#,
            r#"{"changeSummary":{"same":3}}"#,
            r#"{"resource_changes":[]}"#,
        ] {
            assert!(
                matches!(compile_str(not_a_preview), Err(PlanError::NotAPlan)),
                "{not_a_preview} must not read as an empty preview"
            );
        }
        // An explicitly empty preview is a real answer.
        let c = compile_str(r#"{"steps":[]}"#).unwrap();
        assert!(c.required_effects().is_empty());
    }

    #[test]
    fn the_address_is_something_an_operator_can_read() {
        let c = compile_str(REPLACE_DB).unwrap();
        let db = c
            .rows
            .iter()
            .find(|r| r.effect.verb == Verb::Replace)
            .unwrap();
        assert_eq!(db.address, "aws:rds/instance:Instance::payments");
    }

    #[test]
    fn malformed_input_never_panics() {
        for case in [
            "",
            "{",
            "null",
            "3",
            r#"{"steps":null}"#,
            r#"{"steps":"nope"}"#,
            r#"{"steps":[{}]}"#,
            r#"{"steps":[{"op":"","urn":""}]}"#,
            r#"{"steps":[{"op":"replace","urn":"::"}]}"#,
        ] {
            let _ = compile_str(case);
        }
    }
}
