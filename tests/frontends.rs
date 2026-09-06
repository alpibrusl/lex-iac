//! Is the effect model Terraform-shaped? (alpibrusl/lex-iac#10)
//!
//! The epic claimed it was not. This suite is the falsification test,
//! and it is written to fail loudly if the claim stops holding: the same
//! plan, expressed by two tools that share no syntax, has to reach the
//! same effects, the same verdict and the same refusal text — through a
//! `check` that neither frontend knows about.
//!
//! The Terraform and Pulumi fixtures here are the *same change*: two
//! tag edits and a database replacement, the second of which is what an
//! operator would miss.

use lex_iac::{check, detect, Frontend, Manifest, Reversibility, Verdict, Wall};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn manifest(name: &str) -> Manifest {
    Manifest::from_json(&fixture(name)).unwrap_or_else(|e| panic!("parsing manifest {name}: {e}"))
}

const TERRAFORM: &str = "harmless_tag_change.json";
const PULUMI: &str = "pulumi_harmless_tag_change.json";

/// The claim, stated as an assertion. Two tools, no shared syntax, one
/// set of effects.
#[test]
fn both_frontends_compile_the_same_change_to_the_same_effects() {
    let tf = lex_iac::compile_any(&fixture(TERRAFORM)).unwrap();
    let pulumi = lex_iac::compile_any(&fixture(PULUMI)).unwrap();

    assert_eq!(
        tf.required_effects(),
        pulumi.required_effects(),
        "the whole milestone is this line"
    );
    assert_eq!(
        tf.required_effects(),
        vec!["aws.cloudwatch.update", "aws.ecs.update", "aws.rds.replace"]
    );

    // ...and agree on blast radius, not just on names.
    assert!(tf.has_consequential() && pulumi.has_consequential());
    assert_eq!(
        tf.rows_at(Reversibility::IrreversibleConsequential).len(),
        pulumi
            .rows_at(Reversibility::IrreversibleConsequential)
            .len()
    );
    assert!(tf.unknown_types().is_empty() && pulumi.unknown_types().is_empty());
}

/// The demo, run twice. `aws.rds.*` does not authorise destroying a
/// database — and the refusal is identical, including its wording,
/// because nothing in the wall knows which tool it is reading.
#[test]
fn the_same_wall_refuses_the_same_overreach_in_both() {
    let grant = manifest("grant_with_rds_wildcard.json");

    let tf = check(&fixture(TERRAFORM), &grant, None).unwrap();
    let pulumi = check(&fixture(PULUMI), &grant, None).unwrap();

    let (
        Verdict::Deny {
            first: a,
            all: all_a,
        },
        Verdict::Deny {
            first: b,
            all: all_b,
        },
    ) = (&tf.verdict, &pulumi.verdict)
    else {
        panic!("both must refuse: {:?} / {:?}", tf.verdict, pulumi.verdict);
    };

    assert_eq!(a.wall, Wall::Reversibility);
    assert_eq!(a.wall, b.wall);
    assert_eq!(a.effect, b.effect, "aws.rds.replace, from both");
    assert_eq!(a.reason, b.reason, "the same sentence, word for word");
    assert_eq!(a.grant_allows, b.grant_allows);
    assert_eq!(all_a.len(), all_b.len(), "one refusal each");
    assert_eq!(tf.exit_code(), 8);
    assert_eq!(pulumi.exit_code(), 8);

    // The address is the one thing that legitimately differs: each tool
    // names its own resources.
    assert_eq!(a.address, "aws_db_instance.payments");
    assert_eq!(b.address, "aws:rds/instance:Instance::payments");
}

/// ...and naming the verb authorises it in both. A gate that could only
/// be satisfied on one frontend would not be one gate.
#[test]
fn naming_the_verb_authorises_it_in_both() {
    let grant = manifest("grant_names_the_replace.json");
    for plan in [TERRAFORM, PULUMI] {
        let d = check(&fixture(plan), &grant, None).unwrap();
        assert!(d.verdict.allowed(), "{plan}: {:?}", d.verdict);
        assert_eq!(d.exit_code(), 0);
    }
}

/// The grant file is not per-frontend. This is the same bytes, and the
/// same `ManifestId`, governing both.
#[test]
fn one_grant_file_governs_both_frontends() {
    let grant = manifest("grant_with_rds_wildcard.json");
    let tf = check(&fixture(TERRAFORM), &grant, None).unwrap();
    let pulumi = check(&fixture(PULUMI), &grant, None).unwrap();

    let tf_id = tf.audit.entries()[0].clone();
    let pulumi_id = pulumi.audit.entries()[0].clone();
    let manifest_of = |e: &lex_os_audit::Entry<lex_iac::PlanEvent>| match &e.event {
        lex_iac::PlanEvent::PlanRequested { manifest, .. } => manifest.clone(),
        other => panic!("the first entry is always the request: {other:?}"),
    };
    assert_eq!(manifest_of(&tf_id), manifest_of(&pulumi_id));
}

/// The plans are different bytes, so they must pin different identities
/// — an acceptance of one is not an acceptance of the other.
#[test]
fn each_frontends_acceptance_pins_its_own_bytes() {
    let grant = manifest("grant_names_the_replace.json");
    let tf = check(&fixture(TERRAFORM), &grant, None).unwrap();
    let pulumi = check(&fixture(PULUMI), &grant, None).unwrap();

    assert_ne!(tf.plan.plan_sha256, pulumi.plan.plan_sha256);
    assert_ne!(tf.audit.head(), pulumi.audit.head());
    tf.audit.verify().expect("chain verifies");
    pulumi.audit.verify().expect("chain verifies");
}

#[test]
fn the_frontend_is_recognised_from_the_document() {
    assert_eq!(detect(&fixture(TERRAFORM)).unwrap(), Frontend::Terraform);
    assert_eq!(detect(&fixture(PULUMI)).unwrap(), Frontend::Pulumi);
    assert_eq!(
        detect(r#"{"resource_changes":[]}"#).unwrap(),
        Frontend::Terraform
    );
    assert_eq!(detect(r#"{"steps":[]}"#).unwrap(), Frontend::Pulumi);
}

/// A document claiming to be both is refused rather than resolved by
/// precedence. Picking one would mean enforcing half a document on a
/// coin flip.
#[test]
fn a_document_claiming_to_be_both_is_refused() {
    let both = r#"{"resource_changes":[],"steps":[]}"#;
    assert!(matches!(detect(both), Err(lex_iac::PlanError::Ambiguous)));

    let err = check(both, &manifest("grant_ecs_only.json"), None).unwrap_err();
    assert!(
        matches!(err, lex_iac::GateError::Plan(lex_iac::PlanError::Ambiguous)),
        "the gate must not run on it: {err}"
    );
}

/// The #8 rule holds across both readers: absence is not benignity.
#[test]
fn neither_frontend_reads_absence_as_an_empty_plan() {
    for not_a_plan in [
        r#"{}"#,
        r#"[]"#,
        r#"{"format_version":"1.2"}"#,
        r#"{"changeSummary":{"same":3}}"#,
        r#"{"Resources":{"db":{"Type":"AWS::RDS::DBInstance"}}}"#,
    ] {
        assert!(
            lex_iac::compile_any(not_a_plan).is_err(),
            "{not_a_plan} must not compile to an empty, approvable plan"
        );
    }

    // ...while an explicitly empty plan is a real answer in either.
    for empty in [r#"{"resource_changes":[]}"#, r#"{"steps":[]}"#] {
        let c = lex_iac::compile_any(empty).unwrap();
        assert!(c.required_effects().is_empty());
    }
}

/// What did *not* generalise, pinned so the honesty survives a refactor.
///
/// The classification tables were lists of Terraform type strings. Had
/// they stayed that way, every Pulumi type would miss and every
/// teardown would classify consequential — safe, and useless. This
/// asserts the rekeying actually took: a stateless Pulumi resource is
/// recognised as stateless, not merely unrecognised.
#[test]
fn the_classification_tables_are_no_longer_terraform_shaped() {
    let pulumi = lex_iac::compile_any(&fixture(PULUMI)).unwrap();

    let ecs = pulumi
        .rows
        .iter()
        .find(|r| r.effect.service == "ecs")
        .expect("the ECS service is in the plan");
    assert!(
        !ecs.unknown_type,
        "aws:ecs/service:Service must be recognised, not merely unmatched"
    );
    assert_eq!(ecs.reversibility, Reversibility::IrreversibleBounded);

    let rds = pulumi
        .rows
        .iter()
        .find(|r| r.effect.service == "rds")
        .expect("the database is in the plan");
    assert!(!rds.unknown_type);
    assert_eq!(rds.reversibility, Reversibility::IrreversibleConsequential);

    // And the kind is load-bearing: a bucket holds data, its policy
    // does not, and keying on the service alone would conflate them.
    use lex_iac::ResourceKey;
    assert!(lex_iac::classify::is_stateful(&ResourceKey::from_pulumi(
        "aws:s3/bucket:Bucket"
    )));
    assert!(!lex_iac::classify::is_stateful(&ResourceKey::from_pulumi(
        "aws:s3/bucketPolicy:BucketPolicy"
    )));
}
