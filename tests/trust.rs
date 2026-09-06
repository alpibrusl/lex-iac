//! Milestone 4: earned trust narrows the grant, and a decision becomes
//! promotable evidence (alpibrusl/lex-iac#1, alpibrusl/lex-lang#794).
//!
//! Two things are pinned here, and they are opposite halves of one
//! loop. **What the keyring does to a decision**: a submitter nobody
//! has scored is held to the narrower reading of the same grant. And
//! **what a decision leaves behind**: an audit log shaped so
//! `lex attest import-apply` can promote it, which is where the next
//! keyring comes from.
//!
//! The promotion-contract tests assert against the *serialised* log
//! rather than the Rust enum on purpose. lex-lang reads this as JSON
//! and knows nothing about `PlanEvent`; a rename that kept the enum
//! compiling and broke the field names would break promotion silently,
//! and silence is the failure mode worth spending a test on.

use lex_iac::{check, Keyring, Manifest, Standing, Submitter, Verdict, Wall};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn manifest(name: &str) -> Manifest {
    Manifest::from_json(&fixture(name)).unwrap_or_else(|e| panic!("parsing manifest {name}: {e}"))
}

fn keyring() -> Keyring {
    Keyring::new(["ci@payments"])
}

/// One routine ECS update, and nothing else.
///
/// The plans here are inline and single-rowed on purpose, where the
/// rest of the suite runs whole fixtures. A refusal reports the first
/// row that tripped a wall, in row order — so a multi-row plan would
/// let a test pass because some *other* row was refused for some other
/// reason. One row, one wall, one thing under test.
const ROTATE: &str = r#"{"resource_changes":[
    {"address":"aws_ecs_service.api","type":"aws_ecs_service","mode":"managed",
     "change":{"actions":["update"]}}
]}"#;

/// One database replacement. Destroys state whoever asks.
const REPLACE_DB: &str = r#"{"resource_changes":[
    {"address":"aws_db_instance.payments","type":"aws_db_instance","mode":"managed",
     "change":{"actions":["delete","create"]}}
]}"#;

/// A grant that admits [`ROTATE`], and only through a wildcard.
const ECS_WILDCARD: &str = "grant_ecs_only.json";

/// A grant that admits [`ROTATE`] by naming the verb.
const ECS_NAMED: &str = "grant_names_the_creates.json";

/// A grant that admits [`REPLACE_DB`] only through `aws.rds.*`.
const RDS_WILDCARD: &str = "grant_with_rds_wildcard.json";

// ---------------------------------------------------------------- the wall

/// The headline: the same plan, the same grant, refused for one reason
/// only — nobody has scored the submitter, so the wildcard does not
/// carry it.
#[test]
fn an_unscored_submitter_cannot_ride_a_wildcard() {
    let stranger = Submitter::against("ci@billing", &keyring());
    assert_eq!(stranger.standing, Standing::Unknown);

    let d = check(ROTATE, &manifest(ECS_WILDCARD), None, Some(&stranger)).unwrap();

    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(first.wall, Wall::Trust);
    assert_eq!(d.exit_code(), 8);
    assert!(
        first.reason.contains("not in the trusted keyring"),
        "the refusal has to say which of the three reasons applies: {}",
        first.reason
    );
    // The remedy is named, and it is not "widen the grant".
    assert!(first.reason.contains("name the verb explicitly"));
}

/// The same call, by a submitter with a record. Nothing else changes.
#[test]
fn a_scored_submitter_is_carried_by_the_same_wildcard() {
    let known = Submitter::against("ci@payments", &keyring());
    assert_eq!(known.standing, Standing::Trusted);

    let d = check(ROTATE, &manifest(ECS_WILDCARD), None, Some(&known)).unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.exit_code(), 0);
}

/// Not consulting the keyring is not the same as consulting it and
/// finding nothing. A run with no keyring behaves exactly as it did
/// before this milestone — otherwise every existing caller would have
/// silently tightened on upgrade.
#[test]
fn an_unconsulted_submitter_is_not_an_unknown_one() {
    let d = check(
        ROTATE,
        &manifest(ECS_WILDCARD),
        None,
        Some(&Submitter::unconsulted("ci@billing")),
    )
    .unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.standing, Standing::NotConsulted);

    // And no submitter at all is the same again.
    let d = check(ROTATE, &manifest(ECS_WILDCARD), None, None).unwrap();
    assert!(d.verdict.allowed());
    assert_eq!(d.standing, Standing::NotConsulted);
    assert_eq!(d.signer, None);
}

/// The narrower grant is still a grant. An unscored submitter is not
/// locked out — it acts through verbs somebody wrote down.
#[test]
fn the_narrower_grant_still_authorises_named_verbs() {
    let d = check(
        ROTATE,
        &manifest(ECS_NAMED),
        None,
        Some(&Submitter::against("ci@billing", &keyring())),
    )
    .unwrap();
    assert!(
        d.verdict.allowed(),
        "a named verb carries an unscored submitter: {:?}",
        d.verdict
    );
}

/// The direction that must never invert: standing narrows, it never
/// widens. An effect outside the grant is refused whoever asks, and the
/// wall it hits is the narrowing one either way — a trusted submitter
/// does not get a different answer, only the same one.
#[test]
fn trust_never_widens_the_grant() {
    for (who, standing) in [
        (Submitter::against("ci@payments", &keyring()), "trusted"),
        (Submitter::against("ci@billing", &keyring()), "unscored"),
    ] {
        // `grant_ecs_only` names no RDS verb at all, so this is outside
        // the grant rather than merely outside a wildcard's reach.
        let d = check(REPLACE_DB, &manifest(ECS_WILDCARD), None, Some(&who)).unwrap();
        let Verdict::Deny { first, .. } = &d.verdict else {
            panic!("a {standing} submitter must not reach outside the grant: {d:?}");
        };
        assert_eq!(
            first.wall,
            Wall::Narrowing,
            "a {standing} submitter hits the narrowing wall, not the trust one"
        );
    }
}

/// Three reasons a wildcard will not do, and the gravest is the one
/// reported. Telling an operator their database replacement was refused
/// for want of a trust score would send them to the wrong remedy — and
/// earning a score would not have fixed it.
#[test]
fn destroying_state_outranks_an_unscored_submitter() {
    // One row, and both reasons apply to it: the submitter is unscored
    // *and* the change destroys state.
    let d = check(
        REPLACE_DB,
        &manifest(RDS_WILDCARD),
        None,
        Some(&Submitter::against("ci@billing", &keyring())),
    )
    .unwrap();
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal");
    };
    assert_eq!(first.wall, Wall::Reversibility);
    assert!(first.reason.contains("stateful infrastructure"));
}

// -------------------------------------------------- the promotion contract

/// Parse the log the way lex-lang does: as JSON, with no knowledge of
/// this crate's types.
fn as_json(d: &lex_iac::Decision) -> Vec<serde_json::Value> {
    let raw = d.audit.to_json().expect("the chain serialises");
    serde_json::from_str(&raw).expect("the log is a JSON array")
}

fn event_of<'a>(entries: &'a [serde_json::Value], kind: &str) -> &'a serde_json::Value {
    entries
        .iter()
        .map(|e| &e["event"])
        .find(|e| e["kind"] == kind)
        .unwrap_or_else(|| panic!("no `{kind}` event in the log"))
}

/// What `lex attest import-apply` requires of a promotable event:
/// `artifact_sha256` (lowercase hex, 64 chars), `manifest`, `signer`.
fn assert_promotable(event: &serde_json::Value, signer: &str) {
    let sha = event["artifact_sha256"]
        .as_str()
        .expect("a promotable event names the decided bytes");
    assert_eq!(sha.len(), 64, "artifact_sha256 must be a full SHA-256");
    assert!(
        sha.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "artifact_sha256 must be lowercase hex, got `{sha}`"
    );
    assert!(
        event["manifest"].as_str().is_some_and(|m| !m.is_empty()),
        "a promotable event names the ceiling it was checked against"
    );
    assert_eq!(
        event["signer"].as_str(),
        Some(signer),
        "a promotable event names who authorised it"
    );
}

#[test]
fn an_acceptance_is_promotable() {
    let d = check(
        ROTATE,
        &manifest(ECS_WILDCARD),
        None,
        Some(&Submitter::against("ci@payments", &keyring())),
    )
    .unwrap();
    assert!(d.verdict.allowed());

    let entries = as_json(&d);
    assert_promotable(event_of(&entries, "plan_accepted"), "ci@payments");
    // The request record carries it too, so a log truncated to its
    // first entry still says who asked.
    assert_promotable(event_of(&entries, "plan_requested"), "ci@payments");
}

/// The half that keeps producer trust meaningful. Trust is
/// `passed / (passed + failed)`; a gate that only made its acceptances
/// promotable would score every submitter 1.0 for ever.
#[test]
fn a_refusal_is_promotable_and_carries_why() {
    let d = check(
        REPLACE_DB,
        &manifest(RDS_WILDCARD),
        None,
        Some(&Submitter::against("ci@payments", &keyring())),
    )
    .unwrap();
    assert!(!d.verdict.allowed());

    let entries = as_json(&d);
    let refused = event_of(&entries, "plan_refused");
    assert_promotable(refused, "ci@payments");
    // `import-apply` reads `reason` into `Failed { detail }`, so the
    // record says why, not merely that.
    assert!(
        refused["reason"]
            .as_str()
            .is_some_and(|r| r.contains("stateful infrastructure")),
        "a refusal's detail has to survive promotion: {refused}"
    );
}

/// A gate that invented an identity would attribute one submitter's
/// record to another. It declines: the field is absent, and
/// `import-apply` then asks for `--signer` rather than being handed a
/// guess.
#[test]
fn an_unattributed_decision_carries_no_signer_at_all() {
    let d = check(ROTATE, &manifest(ECS_WILDCARD), None, None).unwrap();
    let entries = as_json(&d);
    let accepted = event_of(&entries, "plan_accepted");
    assert!(
        accepted.get("signer").is_none(),
        "an absent signer is absent, not empty: {accepted}"
    );
    // The rest of the contract is still satisfied, so `--signer` on the
    // command line is enough to promote it.
    assert_eq!(accepted["artifact_sha256"].as_str().unwrap().len(), 64);
    assert!(accepted["manifest"].as_str().is_some());
}

/// What the keyring said is in the record, not only in its effect. An
/// operator reading the log a month later can tell a decision made
/// under a consulted keyring from one made without.
#[test]
fn the_log_records_what_the_keyring_said() {
    for (who, expected) in [
        (Submitter::against("ci@payments", &keyring()), "trusted"),
        (Submitter::against("ci@billing", &keyring()), "unknown"),
        (Submitter::unconsulted("ci@billing"), "not-consulted"),
    ] {
        let d = check(ROTATE, &manifest(ECS_NAMED), None, Some(&who)).unwrap();
        assert_eq!(
            event_of(&as_json(&d), "plan_requested")["trust"].as_str(),
            Some(expected)
        );
    }
}

/// Promotion reads the log; it does not re-verify the chain. That makes
/// it this gate's job to write one that verifies — and to keep writing
/// the request before the decision, so a refusal is exactly as legible
/// as an approval.
#[test]
fn the_promotable_log_is_still_a_verifying_chain() {
    let d = check(
        REPLACE_DB,
        &manifest(RDS_WILDCARD),
        None,
        Some(&Submitter::against("ci@payments", &keyring())),
    )
    .unwrap();
    d.audit.verify().expect("the chain verifies");

    let entries = as_json(&d);
    assert_eq!(entries[0]["event"]["kind"], "plan_requested");
    assert_eq!(
        entries.last().unwrap()["event"]["kind"],
        "plan_refused",
        "the decision is the last word in the log"
    );
    // Every entry commits to its predecessor, and the log a promoter
    // reads is the log the gate hashed.
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e["seq"].as_u64(), Some(i as u64));
    }
}
