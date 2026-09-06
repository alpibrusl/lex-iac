//! The acceptance test for lex-os#71, as something you can run.
//!
//! ```sh
//! cargo run --example one_manifest
//! ```
//!
//! Milestone 2 of this repo carried its own `InfraManifest`, because
//! lex-os had the `Facet` trait but no slot on `Manifest` for a facet it
//! did not itself know about. Two manifest types is two content-addressing
//! schemes, two budget comparisons and two chances for the walls to drift
//! apart. This example is the demonstration that there is now one.
//!
//! Everything below operates on `lex_os_manifest::Manifest`. lex-iac
//! contributes exactly two things: the `infra` facet's own narrowing
//! rule, and the registry that hands that rule to lex-os.

use lex_iac::{check, infra_facet, narrow, InfraFacet, Manifest, Verdict};
use lex_os_manifest::{Budget, Goal, Grant, Level};

const ROTATE: &str = r#"{"resource_changes":[
    {"address":"aws_ecs_service.api","type":"aws_ecs_service","mode":"managed",
     "change":{"actions":["update"]}},
    {"address":"aws_db_instance.payments","type":"aws_db_instance","mode":"managed",
     "change":{"actions":["delete","create"]}}
]}"#;

fn main() {
    // A plain lex-os manifest — the same one `lex-os run` would take —
    // with one facet attached.
    let org = Manifest::new(
        Goal::new("manage the payments stack"),
        Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        Budget {
            wall_clock_secs: 3600,
            max_commands: 500,
            max_money_cents: 100_000,
            max_api_calls: 5000,
        },
    )
    .with_facet(&InfraFacet::new(["aws.ecs.*", "aws.rds.*"]))
    .expect("the facet serialises");

    println!("one manifest, two authority domains");
    println!("  id:       {}", org.content_id());
    println!("  grant:    {:?}", org.grant);
    println!("  infra:    {:?}", infra_facet(&org).unwrap().allow);
    println!();

    // 1. The facet folds into the manifest's identity. A manifest that
    //    grants RDS is not the same manifest as one that does not — the
    //    whole point of putting the facet *on* the manifest rather than
    //    beside it.
    let narrower = org
        .clone()
        .with_facet(&InfraFacet::new(["aws.ecs.*"]))
        .unwrap();
    println!("the facet folds into the ManifestId");
    println!("  with rds: {}", org.content_id());
    println!("  without:  {}", narrower.content_id());
    assert_ne!(org.content_id(), narrower.content_id());
    println!();

    // 2. One narrowing wall, covering both domains. The trust lattice
    //    and the budget are lex-os's; `infra` is ours, reached through
    //    the registry.
    println!("one narrowing wall");
    println!(
        "  tighter infra:  {:?}",
        narrow(&org, &narrower).map(|_| "ok")
    );

    // Narrowing is *subsumption*, not string equality: `narrower` grants
    // `aws.ecs.*`, so a child asking for `aws.ecs.update` alone is inside
    // it. Note what this does not mean — see (3): the parent granting
    // `aws.rds.*` lets a child inherit `aws.rds.delete`, and neither of
    // them thereby authorises destroying a database. Inheriting a
    // pattern and being admitted by it are different questions.
    let tighter = narrower
        .clone()
        .with_facet(&InfraFacet::new(["aws.ecs.update"]))
        .unwrap();
    println!(
        "  subsumed verb:  {:?}",
        narrow(&narrower, &tighter).map(|_| "ok")
    );

    let mints_rds = narrower
        .clone()
        .with_facet(&InfraFacet::new(["aws.ecs.*", "aws.rds.delete"]))
        .unwrap();
    println!(
        "  wider infra:    {}",
        narrow(&narrower, &mints_rds).unwrap_err()
    );

    let mut wider_grant = narrower.clone();
    wider_grant.grant = Grant::new(Level::Full, Level::Full, Level::Full);
    println!(
        "  wider grant:    {}",
        narrow(&org, &wider_grant).unwrap_err()
    );

    let mut richer = narrower.clone();
    richer.budget.max_money_cents = 999_999;
    println!("  wider budget:   {}", narrow(&org, &richer).unwrap_err());
    println!();

    // 3. And the gate reads its authority off that same manifest.
    //    `org` grants `aws.rds.*` and still does not authorise
    //    destroying the database — the reversibility wall, which is a
    //    different question from whether a child may inherit the
    //    pattern.
    let d = check(ROTATE, &org, None, None).expect("the gate runs");
    let Verdict::Deny { first, .. } = &d.verdict else {
        panic!("expected a refusal, got {:?}", d.verdict);
    };
    println!("the gate reads the same manifest");
    println!(
        "  {} [{}] — {}",
        first.effect,
        first.wall.as_str(),
        first.reason
    );
    println!("  audit head: sha256:{}", &d.audit.head()[..16]);

    // 4. A manifest with no `infra` facet grants no infrastructure
    //    authority. Refused, and recorded — not a crash, not a pass.
    let bare = Manifest::new(
        Goal::new("a research agent, with no business touching infrastructure"),
        Grant::new(Level::ReadOnly, Level::None, Level::None),
        Budget::research_default(),
    );
    let d = check(ROTATE, &bare, None, None).expect("the gate still runs");
    println!();
    println!("no facet means no infrastructure authority");
    println!(
        "  refused rows: {}",
        match &d.verdict {
            Verdict::Deny { all, .. } => all.len(),
            Verdict::Allow => 0,
        }
    );
    println!("  recorded:     {} entries", d.audit.len());
    assert!(!d.verdict.allowed());
}
