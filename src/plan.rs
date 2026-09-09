//! The slice of Terraform / OpenTofu plan JSON this gate reads.
//!
//! `terraform show -json <planfile>` emits a large document. Almost all
//! of it is the *content* of the change — attribute values, sensitivity
//! marks, provider schemas — and none of that is authority. What decides
//! blast radius is which resource types are touched and which actions
//! are taken against them, so that is all this models.
//!
//! Unknown fields are ignored rather than rejected, and a plan from a
//! future Terraform version must parse or fail cleanly — never panic.
//! This is a gate over someone else's evolving format, and refusing to
//! read a plan is not the same as refusing to apply it.
//!
//! # Tolerant of shape, never of absence
//!
//! Tolerance stops at the two fields that carry authority. A document
//! with no `resource_changes`, or a row with no `actions`, is **not** a
//! plan with nothing in it — it is a document this gate cannot vouch
//! for, and the difference is the whole point:
//!
//! ```text
//! {"resource_changes": []}   an empty plan          → nothing to authorise
//! {}                          not a plan             → refuse
//! ```
//!
//! The realistic case is mundane and is why this matters: `terraform
//! show -json` fails, the redirect leaves a short or empty file, and a
//! gate that read absence as emptiness would answer "approved". Absent
//! evidence is not evidence of absence — the same rule this crate
//! applies to an unpriced create and to a resource type it has never
//! seen.

use serde::{Deserialize, Serialize};

/// A parsed plan: just the resource changes, plus the version strings
/// worth carrying into the audit record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    #[serde(default)]
    pub format_version: String,
    #[serde(default)]
    pub terraform_version: String,
    /// The rows that carry authority. Deliberately **not**
    /// `#[serde(default)]`: see the module docs. [`Plan::from_json`]
    /// refuses a document that omits it rather than reading it as a
    /// plan with nothing in it.
    pub resource_changes: Vec<ResourceChange>,
}

/// One resource the plan proposes to touch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceChange {
    /// e.g. `aws_s3_bucket.data` or `module.db.aws_db_instance.main`.
    #[serde(default)]
    pub address: String,
    /// e.g. `aws_s3_bucket`. The single most load-bearing field here.
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub name: String,
    /// `managed` or `data`. A `data` block reads; it never mutates.
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub provider_name: String,
    /// Absent yields a `Change` with no `actions`, which reads as
    /// [`Verb::Unknown`] — not as a no-op.
    #[serde(default)]
    pub change: Change,
}

impl ResourceChange {
    /// The single verb this row proposes.
    ///
    /// `None` and `[]` both mean "this row does not say", which
    /// [`Verb::from_actions`] answers as [`Verb::Unknown`] rather than
    /// [`Verb::NoOp`] — a truncated row must not read as harmless. Kept
    /// here rather than at each call site so the two walls that ask
    /// (the effect rows and the state wall) cannot come to different
    /// answers about the same row.
    pub fn verb(&self) -> Verb {
        Verb::from_actions(self.change.actions.as_deref().unwrap_or(&[]))
    }
}

/// The proposed transition. Only `actions` matters for authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// `None` when the plan does not say. Terraform always emits at
    /// least one action, so a row without them is a row this build
    /// cannot read — [`Verb::from_actions`] answers `Unknown`, which
    /// `classify` treats as consequential.
    #[serde(default)]
    pub actions: Option<Vec<String>>,
}

/// Why a plan could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("plan is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Valid JSON, but not a Terraform plan: no `resource_changes` at
    /// all. Distinct from an *empty* plan, and refused rather than
    /// approved — a truncated `terraform show -json`, the wrong file,
    /// or output from another tool entirely all land here.
    #[error(
        "not a Terraform plan: no `resource_changes` field. An empty plan says \
         `\"resource_changes\": []`; a document that omits it may be truncated, \
         from another tool, or from a failed `terraform show -json` — this gate \
         will not approve what it cannot read"
    )]
    NotAPlan,
    /// The document declares both a Terraform `resource_changes` and a
    /// Pulumi `steps`. Picking one would mean deciding, on a coin
    /// flip, which half of a document to enforce — so neither is
    /// enforced. Refuse, don't downgrade.
    #[error(
        "ambiguous plan: the document carries both `resource_changes` (Terraform) and \
         `steps` (Pulumi), and this gate will not guess which one governs"
    )]
    Ambiguous,
}

impl Plan {
    /// Parse `terraform show -json` output.
    ///
    /// Tolerant of every field that does not carry authority, and of
    /// none that does. `resource_changes` must be *present* — an
    /// explicit `[]` is an empty plan and fine; its absence is a
    /// document this gate cannot vouch for.
    ///
    /// The membership test runs before deserialising so the refusal can
    /// say what is wrong in the caller's vocabulary rather than serde's,
    /// and so a top-level JSON array — which serde would otherwise
    /// happily read as a struct with every field defaulted — lands here
    /// too.
    pub fn from_json(src: &str) -> Result<Self, PlanError> {
        let raw: serde_json::Value = serde_json::from_str(src)?;
        if raw.get("resource_changes").is_none() {
            return Err(PlanError::NotAPlan);
        }
        Ok(serde_json::from_value(raw)?)
    }

    /// Whether this plan proposes no changes at all.
    pub fn is_empty(&self) -> bool {
        self.resource_changes.is_empty()
    }
}

/// Everything a resource change proposes, reduced to one verb.
///
/// Terraform spells a replacement as a two-element `actions` array —
/// `["delete","create"]`, or `["create","delete"]` when the lifecycle is
/// create-before-destroy. Both are a *replace*, and collapsing them here
/// is what stops a replacement from being read as a mere create.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verb {
    NoOp,
    Read,
    Create,
    Update,
    Delete,
    Replace,
    /// An `actions` array this version does not recognise. Never treated
    /// as harmless — see `classify`.
    Unknown,
}

impl Verb {
    /// Collapse an `actions` array to a single verb.
    ///
    /// An **empty or absent** array is `Unknown`, not `NoOp`. Terraform
    /// always emits at least one action, so nothing here is a row this
    /// build cannot read — and reading it as "no change" would let a
    /// truncated row through the gate unexamined.
    pub fn from_actions(actions: &[String]) -> Verb {
        let a: Vec<&str> = actions.iter().map(String::as_str).collect();
        match a.as_slice() {
            ["no-op"] => Verb::NoOp,
            ["read"] => Verb::Read,
            ["create"] => Verb::Create,
            ["update"] => Verb::Update,
            ["delete"] => Verb::Delete,
            // Either ordering is a replacement.
            ["delete", "create"] | ["create", "delete"] => Verb::Replace,
            _ => Verb::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verb::NoOp => "no-op",
            Verb::Read => "read",
            Verb::Create => "create",
            Verb::Update => "update",
            Verb::Delete => "delete",
            Verb::Replace => "replace",
            Verb::Unknown => "unknown",
        }
    }

    /// Does this verb change anything in the world?
    pub fn mutates(self) -> bool {
        !matches!(self, Verb::NoOp | Verb::Read)
    }

    /// Does this verb destroy existing state?
    pub fn destroys(self) -> bool {
        matches!(self, Verb::Delete | Verb::Replace)
    }
}

impl std::fmt::Display for Verb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn both_replace_orderings_collapse_to_replace() {
        assert_eq!(
            Verb::from_actions(&actions(&["delete", "create"])),
            Verb::Replace
        );
        // create-before-destroy lifecycle — same blast radius.
        assert_eq!(
            Verb::from_actions(&actions(&["create", "delete"])),
            Verb::Replace
        );
    }

    #[test]
    fn single_actions_map_directly() {
        assert_eq!(Verb::from_actions(&actions(&["no-op"])), Verb::NoOp);
        assert_eq!(Verb::from_actions(&actions(&["read"])), Verb::Read);
        assert_eq!(Verb::from_actions(&actions(&["create"])), Verb::Create);
        assert_eq!(Verb::from_actions(&actions(&["update"])), Verb::Update);
        assert_eq!(Verb::from_actions(&actions(&["delete"])), Verb::Delete);
    }

    #[test]
    fn an_empty_or_unrecognised_action_list_is_not_silently_harmless() {
        // This assertion used to read `NoOp`, under a test with this
        // name — the property was claimed and not checked. Terraform
        // always emits at least one action, so an empty list is a row
        // this build cannot read, and `classify` treats `Unknown` as
        // consequential.
        assert_eq!(Verb::from_actions(&actions(&[])), Verb::Unknown);
        // A shape this version does not know must not read as no-op.
        assert_eq!(Verb::from_actions(&actions(&["forget"])), Verb::Unknown);
        assert_eq!(
            Verb::from_actions(&actions(&["create", "update", "delete"])),
            Verb::Unknown
        );
        // Only an explicit no-op is a no-op.
        assert_eq!(Verb::from_actions(&actions(&["no-op"])), Verb::NoOp);
    }

    /// An *explicitly* empty plan is a plan: there is nothing in it to
    /// authorise, and saying so is a real answer.
    #[test]
    fn an_explicitly_empty_plan_is_a_plan() {
        let p = Plan::from_json(r#"{"format_version":"1.2","resource_changes":[]}"#).unwrap();
        assert!(p.is_empty());
    }

    /// A document that merely *omits* `resource_changes` is not. This
    /// used to parse as an empty plan and be approved with exit 0,
    /// which is the failure this gate exists to prevent: absence read
    /// as benignity.
    #[test]
    fn a_document_without_resource_changes_is_not_a_plan() {
        for not_a_plan in [
            // A truncated or failed `terraform show -json`.
            r#"{"format_version":"1.2"}"#,
            r#"{"format_version":"1.2","errored":true}"#,
            r#"{}"#,
            // serde will read a struct from a sequence, defaulting every
            // field, unless something stops it. Something does.
            r#"[]"#,
            // Another tool's output entirely.
            r#"{"Resources":{"db":{"Type":"AWS::RDS::DBInstance"}}}"#,
        ] {
            assert!(
                matches!(Plan::from_json(not_a_plan), Err(PlanError::NotAPlan)),
                "{not_a_plan} must not read as an empty plan"
            );
        }
    }

    /// A row that does not say what it does is a row this build cannot
    /// read, whether the key is absent or the list is empty.
    #[test]
    fn a_row_that_does_not_say_what_it_does_is_unknown() {
        for row in [
            r#"{"address":"db","type":"aws_db_instance","mode":"managed"}"#,
            r#"{"address":"db","type":"aws_db_instance","mode":"managed","change":{}}"#,
            r#"{"address":"db","type":"aws_db_instance","mode":"managed","change":{"actions":[]}}"#,
        ] {
            let p = Plan::from_json(&format!(r#"{{"resource_changes":[{row}]}}"#)).unwrap();
            let verb = Verb::from_actions(
                p.resource_changes[0]
                    .change
                    .actions
                    .as_deref()
                    .unwrap_or(&[]),
            );
            assert_eq!(verb, Verb::Unknown, "{row}");
            assert!(verb.mutates(), "an unreadable row must still be checked");
        }
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        let p = Plan::from_json(
            r#"{"format_version":"1.2","some_future_field":{"a":1},
                "resource_changes":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket",
                "change":{"actions":["create"],"before":null,"after":{"x":1}}}]}"#,
        )
        .unwrap();
        assert_eq!(p.resource_changes.len(), 1);
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        assert!(Plan::from_json("{not json").is_err());
        assert!(Plan::from_json("").is_err());
    }
}
