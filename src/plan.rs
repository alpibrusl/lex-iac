//! The slice of Terraform / OpenTofu plan JSON this gate reads.
//!
//! `terraform show -json <planfile>` emits a large document. Almost all
//! of it is the *content* of the change — attribute values, sensitivity
//! marks, provider schemas — and none of that is authority. What decides
//! blast radius is which resource types are touched and which actions
//! are taken against them, so that is all this models.
//!
//! Everything is `#[serde(default)]` or optional. A plan from a future
//! Terraform version, or a hand-rolled one, must parse or fail cleanly —
//! never panic. Unknown fields are ignored rather than rejected: this is
//! a gate over someone else's evolving format, and refusing to parse a
//! plan is not the same as refusing to apply it.

use serde::{Deserialize, Serialize};

/// A parsed plan: just the resource changes, plus the version strings
/// worth carrying into the audit record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    #[serde(default)]
    pub format_version: String,
    #[serde(default)]
    pub terraform_version: String,
    #[serde(default)]
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
    #[serde(default)]
    pub change: Change,
}

/// The proposed transition. Only `actions` matters for authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    #[serde(default)]
    pub actions: Vec<String>,
}

/// Why a plan could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("plan is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl Plan {
    /// Parse `terraform show -json` output.
    ///
    /// Deliberately tolerant of shape and intolerant of nothing else: a
    /// document that parses as JSON but carries no `resource_changes`
    /// yields an empty plan, which downstream reads as "no effects" —
    /// correct, and distinct from a parse failure.
    pub fn from_json(src: &str) -> Result<Self, PlanError> {
        Ok(serde_json::from_str(src)?)
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
    pub fn from_actions(actions: &[String]) -> Verb {
        let a: Vec<&str> = actions.iter().map(String::as_str).collect();
        match a.as_slice() {
            ["no-op"] | [] => Verb::NoOp,
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
        assert_eq!(Verb::from_actions(&actions(&[])), Verb::NoOp);
        // A shape this version does not know must not read as no-op.
        assert_eq!(Verb::from_actions(&actions(&["forget"])), Verb::Unknown);
        assert_eq!(
            Verb::from_actions(&actions(&["create", "update", "delete"])),
            Verb::Unknown
        );
    }

    #[test]
    fn a_plan_with_no_changes_parses_as_empty() {
        let p = Plan::from_json(r#"{"format_version":"1.2"}"#).unwrap();
        assert!(p.is_empty());
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
