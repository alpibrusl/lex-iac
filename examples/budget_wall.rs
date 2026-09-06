//! Milestone 3 (alpibrusl/lex-iac#4), as something you can run.
//!
//! ```sh
//! cargo run --example budget_wall
//! ```
//!
//! Cloud spend is the one place where lex-os's "budget in integer
//! cents" is literally true. A plan's forecast delta is charged against
//! `Budget::max_money_cents` like any other mediated spend — and the
//! charge is recorded whether or not it fits.
//!
//! The case worth watching is the last one: **no estimate is not an
//! estimate of zero.**

use lex_iac::{check, cost::parse_cents, CostReport, InfraFacet, Manifest, Verdict, Wall};
use lex_os_manifest::{Budget, Goal, Grant, Level};

/// Two ECS changes and a database replacement.
const PLAN: &str = r#"{"resource_changes":[
    {"address":"aws_ecs_service.api","type":"aws_ecs_service","mode":"managed",
     "change":{"actions":["update"]}},
    {"address":"aws_ecs_task_definition.api","type":"aws_ecs_task_definition","mode":"managed",
     "change":{"actions":["create"]}},
    {"address":"aws_db_instance.payments","type":"aws_db_instance","mode":"managed",
     "change":{"actions":["delete","create"]}}
]}"#;

/// What `infracost breakdown --format json` gives you.
const EXPENSIVE: &str = r#"{
  "currency": "USD",
  "projects": [{ "diff": {
    "totalMonthlyCost": "412.90",
    "resources": [
      { "name": "aws_db_instance.payments",     "monthlyCost": "380.00" },
      { "name": "aws_ecs_task_definition.api",  "monthlyCost": "32.90"  }
    ]
  }}],
  "diffTotalMonthlyCost": "412.90"
}"#;

const CHEAP: &str = r#"{"currency":"USD","diffTotalMonthlyCost":"12.40"}"#;
const TEARDOWN: &str = r#"{"currency":"USD","diffTotalMonthlyCost":"-380.00"}"#;

fn money(minor: i64) -> String {
    let sign = if minor < 0 { "-" } else { "" };
    let n = minor.unsigned_abs();
    format!("{sign}{}.{:02}", n / 100, n % 100)
}

/// A grant naming every verb the plan needs, so nothing but the budget
/// can be what refuses it.
fn grant(max_money_cents: u64) -> Manifest {
    Manifest::new(
        Goal::new("planned database migration, approved change CR-4127"),
        Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        Budget {
            wall_clock_secs: 900,
            max_commands: 50,
            max_money_cents,
            max_api_calls: 200,
        },
    )
    .with_facet(&InfraFacet::new([
        "aws.ecs.update",
        "aws.ecs.create",
        "aws.rds.replace",
    ]))
    .expect("the facet serialises")
}

fn report(src: &str) -> CostReport {
    CostReport::from_infracost_json(src).expect("a readable estimate")
}

fn main() {
    // Integer cents, never floats. `1.15` has no exact binary form, so
    // the obvious `(x * 100.0) as i64` reads it as 114 — a budget wall
    // off by one in the permissive direction, silently, on an ordinary
    // input.
    println!("money never touches a float");
    println!("  \"1.15\" via f64:  {} cents", (1.15_f64 * 100.0) as i64);
    println!(
        "  \"1.15\" here:      {} cents",
        parse_cents("1.15").unwrap()
    );
    println!();

    // 1. Over the ceiling. The refusal names the resource that
    //    dominates the delta, not just the total.
    let d = check(PLAN, &grant(5_000), Some(&report(EXPENSIVE))).unwrap();
    let Verdict::Deny { first, all } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    println!("$412.90/month against a $50.00 ceiling");
    println!("  refused by:  {}", first.wall.as_str());
    println!("  names:       {}", first.address);
    println!("  charged:     {}", money(d.charged.unwrap()));
    println!("  walls hit:   {}", all.len());
    assert_eq!(first.wall, Wall::Budget);

    // 2. The same plan under a ceiling that accommodates it.
    let d = check(PLAN, &grant(50_000), Some(&report(EXPENSIVE))).unwrap();
    println!();
    println!("...and against a $500.00 ceiling");
    println!("  allowed:     {}", d.verdict.allowed());
    println!(
        "  recorded:    {} entries (requested, charged, accepted)",
        d.audit.len()
    );
    assert!(d.verdict.allowed());
    // The charge is in the record on an approval too. A budget you can
    // only see when it was exceeded is not one anyone can plan against.
    assert_eq!(d.audit.len(), 3);
    d.audit.verify().expect("the chain verifies");

    // 3. A saving is not a spend. Charging a teardown against the
    //    budget would refuse exactly the changes an operator most wants
    //    to make.
    let d = check(PLAN, &grant(5_000), Some(&report(TEARDOWN))).unwrap();
    println!();
    println!("a teardown is a saving, not a spend");
    println!("  charged:     {}", money(d.charged.unwrap()));
    println!("  allowed:     {}", d.verdict.allowed());
    assert!(d.verdict.allowed());

    // 4. The case the issue exists for. With no estimate, the create
    //    has no known price — and "we did not measure it" must not read
    //    as "it is free". Those rows become consequential: a wildcard
    //    will not authorise them.
    println!();
    println!("no estimate is not an estimate of zero");
    let mut wildcard = grant(5_000);
    wildcard = wildcard
        .with_facet(&InfraFacet::new(["aws.ecs.*", "aws.rds.*"]))
        .unwrap();

    // Just the ECS half of the plan, so the database replacement — which
    // a wildcard would refuse for its *own* reason — is not what we are
    // looking at here.
    const ECS_ONLY: &str = r#"{"resource_changes":[
        {"address":"aws_ecs_service.api","type":"aws_ecs_service","mode":"managed",
         "change":{"actions":["update"]}},
        {"address":"aws_ecs_task_definition.api","type":"aws_ecs_task_definition","mode":"managed",
         "change":{"actions":["create"]}}
    ]}"#;

    let priced = check(ECS_ONLY, &wildcard, Some(&report(CHEAP))).unwrap();
    let unpriced = check(ECS_ONLY, &wildcard, None).unwrap();
    println!("  charged, unpriced:   {:?}", unpriced.charged);
    println!("  with an estimate:    {}", priced.verdict.allowed());
    println!("  without one:         {}", unpriced.verdict.allowed());
    assert_eq!(unpriced.charged, None, "unpriced is None, never Some(0)");
    assert!(priced.verdict.allowed());
    assert!(!unpriced.verdict.allowed());

    // ...and the refusal says why. Two reasons a wildcard is not
    // enough, kept apart: an operator told their `aws.ecs.create`
    // "destroys stateful infrastructure" loses the time it takes to
    // find out it does not.
    if let Verdict::Deny { first, .. } = &unpriced.verdict {
        println!("  wall:                {}", first.wall.as_str());
        println!("  because:             {}", first.reason);
        assert_eq!(first.wall, Wall::Budget);
        assert!(!first.reason.contains("destruction"));
    }

    // Naming the verb is the other way out: the operator saying, in the
    // grant, that they accept this one unpriced.
    let named = check(PLAN, &grant(5_000), None).unwrap();
    println!("  ...or name the verb: {}", named.verdict.allowed());
    assert!(named.verdict.allowed());
}
