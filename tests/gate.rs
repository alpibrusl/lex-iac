//! Conformance for the gate (alpibrusl/lex-iac#3), over the same plan
//! fixtures the compiler suite uses plus real grant manifests.
//!
//! The point of running the *fixtures* rather than inline JSON here is
//! that the grant files are what an operator actually writes. A gate
//! that works on hand-built structs and not on the file format is not a
//! gate anyone can use.
//!
//! The grant files are lex-os manifests — the same JSON `lex-os run`
//! takes, carrying one extra facet. That they deserialise through
//! `Manifest::from_json` with no adapter is the acceptance test for
//! lex-os#71.

use lex_iac::{check, narrow, Manifest, Verdict, Wall};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn manifest(name: &str) -> Manifest {
    Manifest::from_json(&fixture(name)).unwrap_or_else(|e| panic!("parsing manifest {name}: {e}"))
}

/// The demo. A plan that reads as three tag edits, under a grant that
/// looks generous — `aws.rds.*` — is still refused, because a wildcard
/// does not authorise destroying a database.
#[test]
fn a_wildcard_grant_refuses_the_hidden_replace() {
    let d = check(
        &fixture("harmless_tag_change.json"),
        &manifest("grant_with_rds_wildcard.json"),
    )
    .unwrap();

    assert_eq!(d.exit_code(), 8);
    let Verdict::Deny { first, all } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(all.len(), 1, "only the database change is refused");
    assert_eq!(first.wall, Wall::Reversibility);
    assert_eq!(first.effect, "aws.rds.replace");
    assert_eq!(first.address, "aws_db_instance.payments");
}

/// ...and naming the verb authorises it. The gate must not be
/// unconditionally obstructive: a planned migration has to be
/// expressible, or operators route around the gate entirely.
#[test]
fn naming_the_verb_in_the_grant_authorises_the_replace() {
    let d = check(
        &fixture("harmless_tag_change.json"),
        &manifest("grant_names_the_replace.json"),
    )
    .unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.exit_code(), 0);
}

#[test]
fn a_benign_rotation_passes_an_ecs_only_grant() {
    let d = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_ecs_only.json"),
    )
    .unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
}

/// An unknown resource type is classified consequential on destroy, so
/// no wildcard covers it — and the grant here has none for `acme`
/// anyway.
#[test]
fn an_unknown_provider_is_refused_under_a_normal_grant() {
    let d = check(
        &fixture("unknown_provider.json"),
        &manifest("grant_ecs_only.json"),
    )
    .unwrap();
    let Verdict::Deny { all, .. } = &d.verdict else {
        panic!("expected a refusal");
    };
    assert_eq!(all.len(), 2, "both the delete and the create are outside");
    assert!(all.iter().all(|r| r.wall == Wall::Narrowing));
}

/// A plan shape the compiler cannot read classifies consequential, and
/// the gate refuses it rather than guessing.
#[test]
fn an_unreadable_plan_shape_is_refused() {
    let d = check(
        &fixture("future_shape.json"),
        &manifest("grant_ecs_only.json"),
    )
    .unwrap();
    assert!(!d.verdict.allowed());
}

/// The narrowing wall on the manifests themselves: a CI job cannot mint
/// itself authority its parent never held.
#[test]
fn a_child_manifest_cannot_mint_itself_rds() {
    let parent = manifest("grant_org_parent.json");
    let child = manifest("grant_child_mints_rds.json");
    let err = narrow(&parent, &child).unwrap_err();
    assert!(
        err.to_string().contains("aws.rds.delete"),
        "the refusal should name the entry that widened: {err}"
    );
}

/// Every decision is recorded, and the record is written before the
/// verdict — an approval and a refusal are equally legible.
#[test]
fn both_outcomes_are_recorded_and_the_chain_verifies() {
    for (plan, grant, expect_allowed) in [
        (
            "harmless_tag_change.json",
            "grant_names_the_replace.json",
            true,
        ),
        (
            "harmless_tag_change.json",
            "grant_with_rds_wildcard.json",
            false,
        ),
    ] {
        let d = check(&fixture(plan), &manifest(grant)).unwrap();
        assert_eq!(d.verdict.allowed(), expect_allowed);
        assert_eq!(d.audit.len(), 2, "request then decision");
        d.audit
            .verify()
            .unwrap_or_else(|e| panic!("{plan}/{grant}: chain broken: {e}"));

        // The decision entry chains onto the request entry.
        assert_eq!(d.audit.entries()[1].prev_hash, d.audit.entries()[0].hash);
    }
}

/// The accepted bytes are pinned, so an acceptance cannot be carried
/// over to a different plan.
#[test]
fn the_record_pins_the_plan_that_was_checked() {
    let a = check(
        &fixture("harmless_tag_change.json"),
        &manifest("grant_names_the_replace.json"),
    )
    .unwrap();
    let b = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_ecs_only.json"),
    )
    .unwrap();
    assert_ne!(a.plan.plan_sha256, b.plan.plan_sha256);
    assert_ne!(a.audit.head(), b.audit.head());
}

/// A grant file is a lex-os manifest, not a shape of this crate's own.
/// If that ever stops being true the whole "one manifest, many facets"
/// claim goes with it, so it is asserted rather than assumed.
#[test]
fn a_grant_file_is_a_lex_os_manifest_carrying_one_facet() {
    let m = manifest("grant_ecs_only.json");
    assert!(m.has_facet("infra"));
    assert_eq!(
        m.goal.description, "rotate the payments API deployment",
        "the goal is lex-os's `Goal`, not a bare string"
    );
    assert_eq!(
        lex_iac::infra_facet(&m).unwrap().allow,
        ["aws.ecs.*", "aws.cloudwatch.*", "aws.iam.read"]
    );

    // The facet folds into the one `ManifestId` the ADR promises: this
    // manifest is not the same manifest as one granting RDS as well.
    assert_ne!(
        m.content_id(),
        manifest("grant_with_rds_wildcard.json").content_id()
    );
}

/// A manifest with no `infra` facet grants no infrastructure authority
/// — and that is a recorded refusal, not a crash and not a pass.
#[test]
fn a_manifest_without_the_facet_refuses_every_change() {
    let mut m = manifest("grant_ecs_only.json");
    m.facets.remove("infra");

    let d = check(&fixture("rotate_deployment.json"), &m).unwrap();
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(first.wall, Wall::Narrowing);
    assert!(first.grant_allows.is_empty());
    assert_eq!(d.audit.len(), 2, "refused, and recorded like any decision");
}

/// ...whereas a facet that is *present* and unreadable is a gate that
/// cannot run. Neither "grants nothing" nor "grants everything" is a
/// safe reading of it, so neither is guessed.
#[test]
fn an_unreadable_facet_stops_the_gate_rather_than_being_guessed_at() {
    let mut m = manifest("grant_ecs_only.json");
    m.facets
        .insert("infra".into(), serde_json::json!({ "allow": "aws.ecs.*" }));

    let err = check(&fixture("rotate_deployment.json"), &m).unwrap_err();
    assert!(
        matches!(err, lex_iac::GateError::Manifest(_)),
        "expected the gate to refuse to run, got {err}"
    );
}
