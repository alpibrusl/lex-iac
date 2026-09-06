//! Conformance over real-shaped plan fixtures (alpibrusl/lex-iac#2).
//!
//! Each fixture is a `terraform show -json` document. The suite asserts
//! what the compiler must never get wrong, rather than snapshotting its
//! whole output — a snapshot would pass on a wrong answer as readily as
//! a right one.

use lex_iac::{compile_str, Reversibility};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

/// The demo this project exists for: a plan that reads as a routine
/// tagging change, with a database replacement buried in it.
///
/// Two of the three changes are innocuous. The third destroys and
/// recreates a production database — and `actions: ["delete","create"]`
/// is the only place the plan says so.
#[test]
fn a_replace_hidden_in_a_tag_change_is_surfaced() {
    let c = compile_str(&fixture("harmless_tag_change.json")).unwrap();
    assert_eq!(c.rows.len(), 3);

    assert!(
        c.has_consequential(),
        "a plan that replaces a production database must not read as harmless"
    );

    let consequential = c.rows_at(Reversibility::IrreversibleConsequential);
    assert_eq!(consequential.len(), 1);
    let row = consequential[0];
    assert_eq!(row.address, "aws_db_instance.payments");
    assert_eq!(row.effect.qualified(), "aws.rds.replace");

    // The other two are ordinary bounded updates, so the refusal points
    // at one line rather than condemning the whole plan.
    assert_eq!(c.rows_at(Reversibility::IrreversibleBounded).len(), 2);

    // And the grant this plan actually requires names the replace.
    assert_eq!(
        c.required_effects(),
        vec!["aws.cloudwatch.update", "aws.ecs.update", "aws.rds.replace"]
    );
}

/// The benign counterpart: rotating a service needs no consequential
/// authority at all. If this ever went red, the gate would be refusing
/// routine work and operators would widen their grants to compensate.
#[test]
fn a_routine_rotation_needs_no_consequential_authority() {
    let c = compile_str(&fixture("rotate_deployment.json")).unwrap();
    assert!(!c.has_consequential());
    assert_eq!(
        c.required_effects(),
        vec!["aws.ecs.create", "aws.ecs.update"],
        "the data-source read and the no-op require no authority"
    );
}

/// Refuse, don't downgrade: a type this build has never seen is not
/// assumed safe to destroy.
#[test]
fn an_unknown_resource_type_defaults_to_consequential_on_destroy() {
    let c = compile_str(&fixture("unknown_provider.json")).unwrap();
    assert_eq!(c.unknown_types().len(), 2, "both types are unrecognised");

    let consequential = c.rows_at(Reversibility::IrreversibleConsequential);
    assert_eq!(consequential.len(), 1);
    assert_eq!(consequential[0].address, "acme_widget_cluster.main");

    // Creating one stays bounded — see classify.rs for why escalating
    // it would push operators toward meaningless grants.
    let created = c
        .rows
        .iter()
        .find(|r| r.address == "acme_widget_config.main")
        .unwrap();
    assert_eq!(created.reversibility, Reversibility::IrreversibleBounded);
    assert!(
        created.unknown_type,
        "still flagged for a policy that cares"
    );
}

#[test]
fn providers_and_services_are_named_the_way_grants_are_written() {
    let c = compile_str(&fixture("multi_provider.json")).unwrap();
    assert_eq!(
        c.required_effects(),
        vec![
            "aws.s3.create",
            "azure.storage.delete",
            "gcp.sql.replace",
            "k8s.deployment.update",
        ]
    );

    // Two of these destroy stateful resources: the Cloud SQL replace
    // and the storage-account delete.
    assert_eq!(c.rows_at(Reversibility::IrreversibleConsequential).len(), 2);
}

/// A plan from a future Terraform, with fields and an action shape this
/// build does not know. It must parse, and the unreadable action must
/// not be waved through.
#[test]
fn an_unreadable_plan_shape_is_refused_not_guessed() {
    let c = compile_str(&fixture("future_shape.json")).unwrap();
    assert_eq!(c.terraform_version, "99.0.0");
    assert_eq!(c.rows.len(), 1);
    assert_eq!(
        c.rows[0].reversibility,
        Reversibility::IrreversibleConsequential,
        "an actions array this build cannot read is not a licence to guess"
    );
}

/// Every fixture pins its own bytes, and re-compiling is deterministic.
#[test]
fn compilation_is_deterministic_and_hash_pinned() {
    for name in [
        "harmless_tag_change.json",
        "rotate_deployment.json",
        "unknown_provider.json",
        "multi_provider.json",
        "future_shape.json",
    ] {
        let src = fixture(name);
        let a = compile_str(&src).unwrap();
        let b = compile_str(&src).unwrap();
        assert_eq!(a, b, "{name} compiled differently on a second run");
        assert_eq!(a.plan_sha256.len(), 64);
    }
}

/// Hostile and malformed input must produce an error, never a panic.
/// Stands in for the fuzz target until one is wired up.
#[test]
fn malformed_input_never_panics() {
    let cases = [
        "",
        "{",
        "[]",
        "null",
        "3",
        r#""a string""#,
        r#"{"resource_changes":null}"#,
        r#"{"resource_changes":"not an array"}"#,
        r#"{"resource_changes":[{}]}"#,
        r#"{"resource_changes":[{"type":"","change":{"actions":[]}}]}"#,
        r#"{"resource_changes":[{"type":"_","change":{"actions":["create"]}}]}"#,
        r#"{"resource_changes":[{"type":"aws_","change":{"actions":["delete"]}}]}"#,
    ];
    for case in cases {
        // Either outcome is fine; a panic is not.
        let _ = compile_str(case);
    }

    // The shapes that *do* parse still classify sanely.
    let c = compile_str(r#"{"resource_changes":[{}]}"#).unwrap();
    assert_eq!(c.rows.len(), 1);
    assert_eq!(c.rows[0].reversibility, Reversibility::ReversibleCheap);
}
