//! Is the effect model Terraform-shaped? (alpibrusl/lex-iac#10)
//!
//! ```sh
//! cargo run --example two_frontends
//! ```
//!
//! The epic claimed it was not, and nothing had tested that. This runs
//! the same change through two tools that share no syntax, against one
//! grant file, and prints what came out.

use lex_iac::{check, compile_any, detect, Manifest, ResourceKey, Verdict};

const TERRAFORM: &str = include_str!("../tests/fixtures/harmless_tag_change.json");
const PULUMI: &str = include_str!("../tests/fixtures/pulumi_harmless_tag_change.json");
const WILDCARD: &str = include_str!("../tests/fixtures/grant_with_rds_wildcard.json");
const NAMED: &str = include_str!("../tests/fixtures/grant_names_the_replace.json");

fn main() {
    let wildcard = Manifest::from_json(WILDCARD).expect("fixture parses");
    let named = Manifest::from_json(NAMED).expect("fixture parses");

    // 1. Two documents with nothing in common but the change they
    //    describe: two tag edits and a database replacement.
    println!("the same change, described by two tools\n");
    for (tool, src) in [("terraform", TERRAFORM), ("pulumi", PULUMI)] {
        let plan = compile_any(src).expect("fixture compiles");
        println!("  {tool:<10} detected as {:?}", detect(src).unwrap());
        for row in &plan.rows {
            println!("    {:<44} {}", row.address, row.effect.qualified());
        }
        println!("    required: {:?}\n", plan.required_effects());
    }

    let tf = compile_any(TERRAFORM).unwrap();
    let pl = compile_any(PULUMI).unwrap();
    assert_eq!(tf.required_effects(), pl.required_effects());
    println!("  ...and they agree. That is the milestone.\n");

    // 2. Pulumi reaches `rds` from the opposite direction: its types
    //    name the service, where Terraform's had to be told.
    println!("how each one gets to `aws.rds`");
    println!(
        "  terraform  aws_db_instance            -> {}   (via the (\"aws\",\"db\") alias)",
        ResourceKey::from_terraform("aws_db_instance")
    );
    println!(
        "  pulumi     aws:rds/instance:Instance  -> {}   (says it outright)",
        ResourceKey::from_pulumi("aws:rds/instance:Instance")
    );
    println!();

    // 3. One grant file. `aws.rds.*` does not authorise destroying a
    //    database, in either.
    println!("one grant file, `aws.rds.*`, against both");
    for (tool, src) in [("terraform", TERRAFORM), ("pulumi", PULUMI)] {
        let d = check(src, &wildcard, None, None).expect("the gate runs");
        match &d.verdict {
            Verdict::Allow => println!("  {tool:<10} ACCEPTED"),
            Verdict::Deny { first, .. } => {
                println!(
                    "  {tool:<10} REFUSED  {} [{}]",
                    first.effect,
                    first.wall.as_str()
                );
                println!("             at {}", first.address);
            }
        }
    }

    let a = check(TERRAFORM, &wildcard, None, None).unwrap();
    let b = check(PULUMI, &wildcard, None, None).unwrap();
    let (Verdict::Deny { first: fa, .. }, Verdict::Deny { first: fb, .. }) =
        (&a.verdict, &b.verdict)
    else {
        panic!("both refuse");
    };
    assert_eq!(fa.reason, fb.reason);
    println!("\n  the same refusal, word for word:");
    println!("    {}\n", fa.reason);

    // 4. And naming the verb satisfies it in both — a gate that could
    //    only be satisfied on one frontend would not be one gate.
    println!("naming the verb authorises it in both");
    for (tool, src) in [("terraform", TERRAFORM), ("pulumi", PULUMI)] {
        let d = check(src, &named, None, None).expect("the gate runs");
        println!(
            "  {tool:<10} {}",
            if d.verdict.allowed() {
                "ACCEPTED"
            } else {
                "REFUSED"
            }
        );
        assert!(d.verdict.allowed());
    }

    // 5. What did not generalise, said out loud.
    println!(
        "\nwhat had to change: the classification tables were lists of Terraform\n\
         type strings, so every Pulumi type missed and every teardown classified\n\
         consequential — safe, and useless. They key on provider.service.kind now.\n\
         What did not change: `check`, `InfraFacet`, and the grant file format."
    );
}
