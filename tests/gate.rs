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

fn cost(name: &str) -> lex_iac::CostReport {
    lex_iac::CostReport::from_infracost_json(&fixture(name))
        .unwrap_or_else(|e| panic!("parsing cost report {name}: {e}"))
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
        None,
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
        None,
    )
    .unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.exit_code(), 0);
}

/// The rule from #4, on a plan that is otherwise entirely benign: with
/// no estimator output, the `create` has no known price, and an unknown
/// price is not a price of zero. `aws.ecs.*` does not cover it.
#[test]
fn an_unpriced_create_is_not_covered_by_a_wildcard() {
    let d = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_ecs_only.json"),
        None,
    )
    .unwrap();
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(
        first.wall,
        Wall::Budget,
        "it is the budget that could not be checked, not reversibility"
    );
    assert_eq!(first.effect, "aws.ecs.create");
    assert!(
        !first.reason.contains("destruction"),
        "a create destroys nothing: {}",
        first.reason
    );
    assert_eq!(d.charged, None, "unpriced is None, never Some(0)");
}

/// ...and pricing it makes the same plan pass. Two ways out, both of
/// them deliberate: supply the estimate, or name the verb.
#[test]
fn a_benign_rotation_passes_an_ecs_only_grant_once_it_is_priced() {
    let d = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_ecs_only.json"),
        Some(&cost("cost_rotation.json")),
    )
    .unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.charged, Some(1240));
}

#[test]
fn naming_the_verb_also_authorises_an_unpriced_create() {
    let d = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_names_the_creates.json"),
        None,
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
        None,
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
        None,
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
        let d = check(&fixture(plan), &manifest(grant), None).unwrap();
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
        None,
    )
    .unwrap();
    let b = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_ecs_only.json"),
        None,
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

    let d = check(&fixture("rotate_deployment.json"), &m, None).unwrap();
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

    let err = check(&fixture("rotate_deployment.json"), &m, None).unwrap_err();
    assert!(
        matches!(err, lex_iac::GateError::Manifest(_)),
        "expected the gate to refuse to run, got {err}"
    );
}

/// The budget wall (#4). A plan inside its grant on every other axis is
/// still refused when the forecast spend exceeds `max_money_cents`.
#[test]
fn a_plan_over_the_money_budget_is_refused_and_the_charge_recorded() {
    let d = check(
        &fixture("harmless_tag_change.json"),
        &manifest("grant_names_the_replace.json"),
        Some(&cost("cost_over_budget.json")),
    )
    .unwrap();

    assert_eq!(d.exit_code(), 8);
    assert_eq!(d.charged, Some(41290));
    let Verdict::Deny { first, all } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(all.len(), 1, "only the budget wall trips");
    assert_eq!(first.wall, Wall::Budget);
    assert_eq!(
        first.address, "aws_db_instance.payments",
        "the refusal names the resource that dominates the delta"
    );
    assert!(first.reason.contains("412.90") && first.reason.contains("50.00"));

    // The charge is in the record whether or not it fit.
    assert_eq!(d.audit.len(), 3, "requested, charged, refused");
    d.audit.verify().expect("the chain verifies");
}

/// The same charge is recorded on an approval. A budget you can only
/// see when it was exceeded is not a budget anyone can plan against.
#[test]
fn the_charge_is_recorded_on_an_approval_too() {
    let d = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_ecs_only.json"),
        Some(&cost("cost_rotation.json")),
    )
    .unwrap();
    assert!(d.verdict.allowed());
    assert_eq!(d.audit.len(), 3, "requested, charged, accepted");
    d.audit.verify().expect("the chain verifies");
}

/// A teardown is a saving, not a spend. Charging it against the budget
/// would refuse exactly the changes an operator most wants to make.
#[test]
fn a_saving_is_never_refused_by_the_budget() {
    let d = check(
        &fixture("harmless_tag_change.json"),
        &manifest("grant_names_the_replace.json"),
        Some(&cost("cost_teardown.json")),
    )
    .unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(d.charged, Some(-38000));
}

/// `max_money_cents` is a bare integer, so the currency is part of the
/// ceiling. Charging a EUR estimate against a USD budget is wrong by
/// whatever the rate is that day — the gate refuses to run rather than
/// guess.
#[test]
fn a_differently_denominated_estimate_stops_the_gate() {
    let err = check(
        &fixture("rotate_deployment.json"),
        &manifest("grant_ecs_only.json"),
        Some(&cost("cost_in_euros.json")),
    )
    .unwrap_err();
    assert!(
        matches!(err, lex_iac::GateError::Cost(_)),
        "expected the gate to refuse to run, got {err}"
    );
}

/// ...and a child cannot redenominate its way to a bigger ceiling.
#[test]
fn a_child_cannot_redenominate_the_budget() {
    let parent = manifest("grant_ecs_only.json");
    let mut child = parent.clone();
    let mut infra = lex_iac::infra_facet(&child).unwrap();
    infra.currency = "JPY".into();
    child = child.with_facet(&infra).unwrap();

    let err = narrow(&parent, &child).unwrap_err();
    assert!(
        err.to_string().contains("JPY"),
        "the refusal should name the unit that changed: {err}"
    );
}

/// `Budget::research_default()` is `max_money_cents: 0`, and zero is a
/// real ceiling rather than an absent one: a run that may not spend
/// refuses any positive forecast. Worth pinning, because a zero that
/// quietly meant "unlimited" would be the most expensive default a
/// budget could have.
#[test]
fn a_zero_budget_refuses_any_spend() {
    let mut m = manifest("grant_names_the_creates.json");
    m.budget.max_money_cents = 0;

    let d = check(
        &fixture("rotate_deployment.json"),
        &m,
        Some(&cost("cost_rotation.json")),
    )
    .unwrap();
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(first.wall, Wall::Budget);
    assert_eq!(d.charged, Some(1240));
}

/// A zero-delta estimate is still an estimate. The run is priced, so
/// nothing escalates and nothing is charged over.
#[test]
fn a_zero_delta_estimate_is_an_estimate() {
    let mut m = manifest("grant_ecs_only.json");
    m.budget.max_money_cents = 0;

    let free = lex_iac::CostReport::from_infracost_json(
        r#"{"currency":"USD","diffTotalMonthlyCost":"0.00"}"#,
    )
    .unwrap();
    let d = check(&fixture("rotate_deployment.json"), &m, Some(&free)).unwrap();
    assert!(d.verdict.allowed(), "{:?}", d.verdict);
    assert_eq!(
        d.charged,
        Some(0),
        "Some(0) is priced at zero; None is unpriced. They are not the same."
    );
}

/// The hole this suite did not have: six shapes that are JSON but are
/// not a plan the gate can vouch for, each of which used to be
/// **ACCEPTED with exit 0**.
///
/// The realistic case is mundane. `terraform show -json` fails, the
/// redirect leaves a short file, the pipeline runs the gate on it, and
/// a gate that read absence as emptiness answers "approved". Exit 2 —
/// the gate could not run — is the honest answer, and is why 8 and 2
/// are kept apart.
#[test]
fn a_document_that_is_not_a_plan_stops_the_gate_rather_than_passing_it() {
    let m = manifest("grant_ecs_only.json");
    for not_a_plan in [
        r#"{}"#,
        r#"[]"#,
        r#"{"format_version":"1.2","errored":true}"#,
        r#"{"Resources":{"db":{"Type":"AWS::RDS::DBInstance"}}}"#,
        "",
    ] {
        let err = check(not_a_plan, &m, None).unwrap_err();
        assert!(
            matches!(err, lex_iac::GateError::Plan(_)),
            "{not_a_plan} must refuse to run, not approve: got {err}"
        );
    }

    // ...while an explicitly empty plan is a real answer: there is
    // nothing in it to authorise.
    let d = check(r#"{"resource_changes":[]}"#, &m, None).unwrap();
    assert!(d.verdict.allowed());
    assert_eq!(d.exit_code(), 0);
}

/// A row that does not say what it does is checked, not skipped. It
/// used to compile to a no-op, which meant `mutates()` was false and no
/// wall ever saw it.
#[test]
fn a_row_with_no_actions_is_checked_not_skipped() {
    let plan = r#"{"resource_changes":[
        {"address":"module.data.aws_db_instance.payments","type":"aws_db_instance",
         "mode":"managed","change":{}}
    ]}"#;

    // Under a grant that is generous by any reading.
    let mut m = manifest("grant_ecs_only.json");
    let mut infra = lex_iac::infra_facet(&m).unwrap();
    infra.allow = vec!["aws.rds.*".into(), "aws.ecs.*".into()];
    m = m.with_facet(&infra).unwrap();

    let d = check(plan, &m, None).unwrap();
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    assert_eq!(first.effect, "aws.rds.unknown");
    assert_eq!(d.exit_code(), 8);
}
