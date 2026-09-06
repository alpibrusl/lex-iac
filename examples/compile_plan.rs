//! Compile a Terraform plan to effect rows and print what it needs.
//!
//! ```sh
//! cargo run --example compile_plan                       # the bundled demo fixture
//! cargo run --example compile_plan -- path/to/plan.json
//! ```
//!
//! Produce the input with:
//!
//! ```sh
//! terraform plan -out=p.tfplan && terraform show -json p.tfplan > plan.json
//! ```

use lex_iac::{compile_str, Reversibility};

const DEMO: &str = include_str!("../tests/fixtures/harmless_tag_change.json");

fn main() {
    let (label, src) = match std::env::args().nth(1) {
        Some(path) => {
            let body = match std::fs::read_to_string(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("could not read {path}: {e}");
                    std::process::exit(2);
                }
            };
            (path, body)
        }
        None => (
            "tests/fixtures/harmless_tag_change.json (bundled demo)".to_string(),
            DEMO.to_string(),
        ),
    };

    let compiled = match compile_str(&src) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not read the plan: {e}");
            std::process::exit(2);
        }
    };

    println!("plan:      {label}");
    println!("sha256:    {}", compiled.plan_sha256);
    if !compiled.terraform_version.is_empty() {
        println!("terraform: {}", compiled.terraform_version);
    }
    println!();

    println!("{:<34}  {:<28}  CLASS", "ADDRESS", "EFFECT");
    for row in &compiled.rows {
        let class = match row.reversibility {
            Reversibility::ReversibleCheap => "cheap",
            Reversibility::IrreversibleBounded => "bounded",
            Reversibility::IrreversibleConsequential => "CONSEQUENTIAL",
        };
        let unknown = if row.unknown_type {
            "  (unknown type)"
        } else {
            ""
        };
        println!(
            "{:<34}  {:<28}  {}{}",
            row.address,
            row.effect.qualified(),
            class,
            unknown
        );
    }

    println!("\nauthority this plan requires:");
    for e in compiled.required_effects() {
        println!("  {e}");
    }

    println!();
    if compiled.has_consequential() {
        println!("VERDICT: contains irreversible, consequential changes.");
        println!("Refused by construction unless the grant bounds each one:");
        for row in compiled.rows_at(Reversibility::IrreversibleConsequential) {
            println!("  {}  ← {}", row.effect, row.resource_type);
        }
        // Milestone 1 only compiles and classifies; the grant check and
        // the exit-8 refusal arrive with `lex-iac check` (#3).
    } else {
        println!("VERDICT: nothing consequential. Within a bounded grant, this applies.");
    }
}
