//! The state wall: what the box wrote back must be what the plan said
//! it would write.
//!
//! Every other wall in this gate asks whether a *plan* is within its
//! mandate. This one asks a different question, and it sits upstream of
//! all of them:
//!
//! > A plan is a function of configuration **and state**. A box that can
//! > write state can forge the input to every future decision this gate
//! > makes — and the gate is then reasoning about a document rather than
//! > about reality.
//!
//! So the box never holds a backend credential. It receives prior state
//! as a file, applies, and emits a *candidate* successor. The host
//! decides whether to commit it, and the decision is checkable because
//! the gate already parsed the plan into `(address, verb)` pairs: the
//! resources that differ between prior and candidate must be the ones
//! the gated plan declared, with verbs that agree.
//!
//! ## Two limits, stated here rather than discovered later
//!
//! **The check is structural, not semantic.** Terraform marks
//! provider-computed attributes as *known after apply*, so an id or an
//! ARN cannot be predicted from the plan and cannot be verified against
//! it. This wall sees *which* resources changed and *how*; it does not
//! see whether the values written were the right ones. A malicious
//! provider can still write a wrong value into a resource the plan
//! legitimately touched.
//!
//! **The check is one-directional.** It refuses a change the plan did
//! not declare. It does *not* require every declared change to have
//! happened: an apply that fails halfway leaves a state that is missing
//! changes, and that is a legitimate outcome to commit — the operator
//! needs the record of what did happen. Unplanned change is the attack;
//! partial application is an accident, and refusing to record it would
//! lose the very evidence an operator needs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::plan::{Plan, Verb};

/// A Terraform state file, read only as far as this wall needs it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct State {
    /// Terraform's state format version (4 at time of writing). Read so
    /// a format this build has never seen is refused rather than
    /// silently half-understood.
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub resources: Vec<StateResource>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct StateResource {
    /// `managed` or `data`. A `data` block is a read; it addresses as
    /// `data.<type>.<name>`.
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub name: String,
    /// Present when the resource lives in a module, e.g. `module.db`.
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub instances: Vec<StateInstance>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct StateInstance {
    /// `count`/`for_each` key, if any. Part of the address.
    #[serde(default)]
    pub index_key: Option<serde_json::Value>,
    #[serde(default)]
    pub attributes: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Valid JSON, but not a Terraform state. Distinct from an *empty*
    /// state, which says `"resources": []`, and refused for the same
    /// reason `Plan::from_json` refuses a document with no
    /// `resource_changes`: this gate will not reason about a file it
    /// cannot read.
    #[error(
        "not a Terraform state: no `resources` field. An empty state says \
         `\"resources\": []`; a document that omits it may be truncated, from \
         another tool, or the wrong file entirely"
    )]
    NotAState,
    /// A state format this build has not been taught to read. Refuse
    /// rather than guess: a newer layout could move or rename the fields
    /// this wall compares, and comparing the wrong fields would report
    /// "nothing changed" for a state that changed.
    #[error(
        "state format version {found} is not one this gate can read (expected {expected}); \
         refusing rather than comparing fields it may not understand"
    )]
    UnsupportedVersion { found: u64, expected: u64 },
}

/// The only state format this wall claims to understand.
const SUPPORTED_STATE_VERSION: u64 = 4;

impl State {
    pub fn from_json(src: &str) -> Result<Self, StateError> {
        let raw: serde_json::Value = serde_json::from_str(src)?;
        if raw.get("resources").is_none() {
            return Err(StateError::NotAState);
        }
        let s: State = serde_json::from_value(raw)?;
        if s.version != SUPPORTED_STATE_VERSION {
            return Err(StateError::UnsupportedVersion {
                found: s.version,
                expected: SUPPORTED_STATE_VERSION,
            });
        }
        Ok(s)
    }

    /// Every instance in the state, keyed by its Terraform address.
    ///
    /// The address is built the way Terraform spells one, so it can be
    /// compared with a plan row's `address` directly: an optional
    /// `module.` prefix, `data.` for a data source, `type.name`, and an
    /// `["key"]` suffix for a `count`/`for_each` instance.
    pub fn instances(&self) -> BTreeMap<String, &serde_json::Value> {
        let mut out = BTreeMap::new();
        for r in &self.resources {
            for i in &r.instances {
                out.insert(instance_address(r, i), &i.attributes);
            }
        }
        out
    }
}

fn instance_address(r: &StateResource, i: &StateInstance) -> String {
    let mut a = String::new();
    if let Some(m) = r.module.as_deref().filter(|m| !m.is_empty()) {
        a.push_str(m);
        a.push('.');
    }
    if r.mode == "data" {
        a.push_str("data.");
    }
    a.push_str(&r.r#type);
    a.push('.');
    a.push_str(&r.name);
    match &i.index_key {
        Some(serde_json::Value::String(s)) => a.push_str(&format!("[\"{s}\"]")),
        Some(serde_json::Value::Number(n)) => a.push_str(&format!("[{n}]")),
        _ => {}
    }
    a
}

/// How one address differs between prior and candidate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateChange {
    Created,
    Deleted,
    Updated,
}

impl StateChange {
    pub fn as_str(self) -> &'static str {
        match self {
            StateChange::Created => "created",
            StateChange::Deleted => "deleted",
            StateChange::Updated => "updated",
        }
    }

    /// Does a plan row promising `verb` account for this change?
    ///
    /// `Replace` admits all three: in state a replacement may surface as
    /// a delete-then-create of the same address, which reads as an
    /// attribute change, or genuinely as one or the other when the
    /// address moves. `Unknown` admits nothing — `classify` already
    /// treats an unreadable verb as consequential, and this wall must
    /// not be the one place it becomes harmless.
    pub fn admitted_by(self, verb: Verb) -> bool {
        match verb {
            Verb::Replace => true,
            Verb::Create => self == StateChange::Created,
            Verb::Delete => self == StateChange::Deleted,
            Verb::Update => self == StateChange::Updated,
            Verb::NoOp | Verb::Read | Verb::Unknown => false,
        }
    }
}

/// Whether a resource's recorded attributes changed.
///
/// Only `attributes` is compared, which is narrower than it looks and
/// deliberately so. `schema_version` sits beside it on the instance and
/// is a provider-internal migration marker: upgrading a provider
/// rewrites it across every resource of that type, including ones no
/// plan mentions. Comparing it would refuse every apply after a provider
/// upgrade — a false refusal, and a false refusal is the failure mode
/// that gets a gate switched off rather than fixed.
fn attributes_differ(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a != b
}

/// One resource that changed without the plan saying it would.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRefusal {
    pub address: String,
    pub change: StateChange,
    /// The verb the plan declared for this address, if it named it at
    /// all. `None` means the plan never mentioned this resource, which
    /// is the sharper case.
    pub planned: Option<Verb>,
    pub reason: String,
}

/// Compare prior and candidate state and report what changed.
pub fn diff(prior: &State, candidate: &State) -> BTreeMap<String, StateChange> {
    let (p, c) = (prior.instances(), candidate.instances());
    let mut out = BTreeMap::new();

    let addresses: BTreeSet<&String> = p.keys().chain(c.keys()).collect();
    for addr in addresses {
        match (p.get(addr), c.get(addr)) {
            (None, Some(_)) => {
                out.insert(addr.clone(), StateChange::Created);
            }
            (Some(_), None) => {
                out.insert(addr.clone(), StateChange::Deleted);
            }
            (Some(before), Some(after)) => {
                if attributes_differ(before, after) {
                    out.insert(addr.clone(), StateChange::Updated);
                }
            }
            (None, None) => unreachable!("address came from one of the two maps"),
        }
    }
    out
}

/// Does the candidate state record only what the gated plan declared?
///
/// Returns the refusals rather than the first one: an operator fixing
/// this needs the whole picture, and a wall that reports one problem per
/// run teaches people to stop reading it.
pub fn admits(plan: &Plan, prior: &State, candidate: &State) -> Result<(), Vec<StateRefusal>> {
    let planned: BTreeMap<&str, Verb> = plan
        .resource_changes
        .iter()
        .map(|rc| (rc.address.as_str(), rc.verb()))
        .collect();

    let mut refusals = Vec::new();
    for (address, change) in diff(prior, candidate) {
        match planned.get(address.as_str()) {
            Some(&verb) if change.admitted_by(verb) => {}
            Some(&verb) => refusals.push(StateRefusal {
                address: address.clone(),
                change,
                planned: Some(verb),
                reason: format!(
                    "state records `{}` for `{address}`, but the plan declared `{}`",
                    change.as_str(),
                    verb_str(verb)
                ),
            }),
            None => refusals.push(StateRefusal {
                address: address.clone(),
                change,
                planned: None,
                reason: format!(
                    "state records `{}` for `{address}`, which the gated plan never mentions",
                    change.as_str()
                ),
            }),
        }
    }

    if refusals.is_empty() {
        Ok(())
    } else {
        Err(refusals)
    }
}

fn verb_str(v: Verb) -> &'static str {
    match v {
        Verb::NoOp => "no-op",
        Verb::Read => "read",
        Verb::Create => "create",
        Verb::Update => "update",
        Verb::Delete => "delete",
        Verb::Replace => "replace",
        Verb::Unknown => "an action this build cannot read",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(resources: &str) -> State {
        State::from_json(&format!(
            r#"{{"version":4,"terraform_version":"1.9.0","resources":[{resources}]}}"#
        ))
        .expect("fixture must parse")
    }

    fn res(ty: &str, name: &str, attrs: &str) -> String {
        format!(
            r#"{{"mode":"managed","type":"{ty}","name":"{name}",
                 "instances":[{{"schema_version":0,"attributes":{attrs}}}]}}"#
        )
    }

    fn plan(rows: &str) -> Plan {
        Plan::from_json(&format!(r#"{{"resource_changes":[{rows}]}}"#)).expect("fixture must parse")
    }

    fn row(address: &str, actions: &str) -> String {
        let (ty, name) = address.split_once('.').unwrap_or(("t", "n"));
        format!(
            r#"{{"address":"{address}","type":"{ty}","name":"{name}","mode":"managed",
                 "change":{{"actions":[{actions}]}}}}"#
        )
    }

    #[test]
    fn an_empty_state_parses_but_a_missing_resources_field_does_not() {
        assert!(State::from_json(r#"{"version":4,"resources":[]}"#).is_ok());
        assert!(matches!(
            State::from_json(r#"{"version":4,"terraform_version":"1.9.0"}"#),
            Err(StateError::NotAState)
        ));
    }

    #[test]
    fn a_state_format_this_build_cannot_read_is_refused() {
        assert!(matches!(
            State::from_json(r#"{"version":5,"resources":[]}"#),
            Err(StateError::UnsupportedVersion { found: 5, .. })
        ));
    }

    #[test]
    fn addresses_are_spelled_the_way_a_plan_spells_them() {
        let s: State = serde_json::from_str(
            r#"{"version":4,"resources":[
                 {"mode":"managed","type":"aws_s3_bucket","name":"data",
                  "instances":[{"attributes":{}}]},
                 {"mode":"data","type":"aws_ami","name":"base",
                  "instances":[{"attributes":{}}]},
                 {"mode":"managed","type":"aws_instance","name":"web","module":"module.app",
                  "instances":[{"index_key":0,"attributes":{}},
                               {"index_key":"blue","attributes":{}}]}]}"#,
        )
        .unwrap();
        let got: Vec<String> = s.instances().keys().cloned().collect();
        assert_eq!(
            got,
            vec![
                "aws_s3_bucket.data".to_string(),
                "data.aws_ami.base".to_string(),
                "module.app.aws_instance.web[\"blue\"]".to_string(),
                "module.app.aws_instance.web[0]".to_string(),
            ]
        );
    }

    #[test]
    fn an_unchanged_state_admits_under_any_plan() {
        let s = state(&res("local_file", "greeting", r#"{"content":"hi"}"#));
        assert!(admits(&plan(""), &s, &s).is_ok());
    }

    /// The decisive test, mirroring `a_different_but_equally_valid_plan_is_refused`.
    ///
    /// The candidate is well-formed, internally consistent, and parses —
    /// it differs only in touching one address the plan never mentions.
    /// It must be refused for that structural reason, not for being
    /// malformed, which is why the fixture is deliberately valid.
    #[test]
    fn a_well_formed_state_changing_an_unplanned_address_is_refused() {
        let prior = state(&res("local_file", "greeting", r#"{"content":"hi"}"#));
        let candidate = state(&format!(
            "{},{}",
            res("local_file", "greeting", r#"{"content":"hi"}"#),
            res("aws_iam_user", "backdoor", r#"{"name":"backdoor"}"#)
        ));
        // The plan is a real plan and passes on its own merits: it just
        // says nothing about aws_iam_user.backdoor.
        let p = plan(&row("local_file.greeting", r#""update""#));

        let refusals = admits(&p, &prior, &candidate).expect_err("must be refused");
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].address, "aws_iam_user.backdoor");
        assert_eq!(refusals[0].change, StateChange::Created);
        assert_eq!(refusals[0].planned, None, "the plan never named it");
        assert!(
            refusals[0].reason.contains("never mentions"),
            "{}",
            refusals[0].reason
        );
    }

    #[test]
    fn a_change_the_plan_declared_is_admitted() {
        let prior = state(&res("local_file", "greeting", r#"{"content":"hi"}"#));
        let candidate = state(&res("local_file", "greeting", r#"{"content":"bye"}"#));
        let p = plan(&row("local_file.greeting", r#""update""#));
        assert!(admits(&p, &prior, &candidate).is_ok());
    }

    #[test]
    fn a_deletion_the_plan_called_a_create_is_refused() {
        let prior = state(&res("local_file", "greeting", r#"{"content":"hi"}"#));
        let candidate = state("");
        let p = plan(&row("local_file.greeting", r#""create""#));

        let refusals = admits(&p, &prior, &candidate).expect_err("must be refused");
        assert_eq!(refusals[0].change, StateChange::Deleted);
        assert_eq!(refusals[0].planned, Some(Verb::Create));
    }

    #[test]
    fn a_replace_admits_a_create_a_delete_or_an_update() {
        for c in [
            StateChange::Created,
            StateChange::Deleted,
            StateChange::Updated,
        ] {
            assert!(c.admitted_by(Verb::Replace), "replace must admit {c:?}");
        }
    }

    /// A row the gate could not read must not become harmless here.
    /// `classify` treats `Unknown` as consequential; so does this.
    #[test]
    fn an_unreadable_verb_admits_nothing() {
        let prior = state("");
        let candidate = state(&res("local_file", "x", r#"{"content":"1"}"#));
        let p = plan(&row("local_file.x", r#""frobnicate""#));

        let refusals = admits(&p, &prior, &candidate).expect_err("must be refused");
        assert_eq!(refusals[0].planned, Some(Verb::Unknown));
    }

    /// A no-op row declares that nothing happens. If state says
    /// otherwise, the state is wrong.
    #[test]
    fn a_no_op_row_does_not_license_a_change() {
        let prior = state(&res("local_file", "x", r#"{"content":"1"}"#));
        let candidate = state(&res("local_file", "x", r#"{"content":"2"}"#));
        let p = plan(&row("local_file.x", r#""no-op""#));
        assert!(admits(&p, &prior, &candidate).is_err());
    }

    /// A half-finished apply leaves changes undone. That is a legitimate
    /// thing to commit — the operator needs the record of what actually
    /// happened — so the wall is one-directional by design.
    #[test]
    fn a_partial_apply_is_not_refused() {
        let prior = state(&res("local_file", "a", r#"{"content":"1"}"#));
        let candidate = state(&res("local_file", "a", r#"{"content":"2"}"#));
        // The plan promised two changes; only one landed.
        let p = plan(&format!(
            "{},{}",
            row("local_file.a", r#""update""#),
            row("local_file.b", r#""create""#)
        ));
        assert!(
            admits(&p, &prior, &candidate).is_ok(),
            "an apply that stopped early must still be recordable"
        );
    }

    /// Every unplanned change is reported, not just the first: an
    /// operator fixing this needs the whole picture.
    #[test]
    fn all_unplanned_changes_are_reported() {
        let prior = state("");
        let candidate = state(&format!(
            "{},{}",
            res("local_file", "one", r#"{"content":"1"}"#),
            res("local_file", "two", r#"{"content":"2"}"#)
        ));
        let refusals = admits(&plan(""), &prior, &candidate).expect_err("must be refused");
        assert_eq!(refusals.len(), 2);
    }
}
