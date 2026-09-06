//! `lex-iac` — the gate, on the command line.
//!
//! ```sh
//! terraform plan -out=p.tfplan && terraform show -json p.tfplan > plan.json
//! lex-iac check --grant env.json --plan plan.json
//! lex-iac manifest narrow --parent org.json --child env.json
//! ```
//!
//! Exit codes follow lex-os: `0` allowed, `8` refused, `2` the gate
//! could not run (bad usage, unreadable file). The distinction between
//! 8 and 2 is the point — a refusal is a decision, not a malfunction,
//! and a pipeline that treats them alike will eventually treat a broken
//! gate as an approval.

use std::process::ExitCode;

use lex_iac::{check, InfraManifest, Verdict, Wall};

const USAGE: &str = "\
usage:
  lex-iac check --grant <manifest.json> --plan <plan.json> [--json]
  lex-iac manifest narrow --parent <manifest.json> --child <manifest.json>

exit: 0 allowed, 8 refused, 2 could not run";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match refs.as_slice() {
        ["check", rest @ ..] => cmd_check(rest),
        ["manifest", "narrow", rest @ ..] => cmd_narrow(rest),
        ["--help"] | ["-h"] | [] => {
            println!("{USAGE}");
            ExitCode::from(0)
        }
        other => {
            eprintln!("unknown command: {}\n\n{USAGE}", other.join(" "));
            ExitCode::from(2)
        }
    }
}

/// Pull `--name value` out of an argument list.
fn flag<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| *a == name)
        .and_then(|i| args.get(i + 1))
        .copied()
}

fn read(path: &str) -> Result<String, ExitCode> {
    std::fs::read_to_string(path).map_err(|e| {
        eprintln!("could not read {path}: {e}");
        ExitCode::from(2)
    })
}

fn cmd_check(args: &[&str]) -> ExitCode {
    let (Some(grant_path), Some(plan_path)) = (flag(args, "--grant"), flag(args, "--plan")) else {
        eprintln!("check needs --grant and --plan\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let as_json = args.contains(&"--json");

    let (grant_src, plan_src) = match (read(grant_path), read(plan_path)) {
        (Ok(g), Ok(p)) => (g, p),
        (Err(c), _) | (_, Err(c)) => return c,
    };

    let manifest = match InfraManifest::from_json(&grant_src) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("could not read the grant manifest {grant_path}: {e}");
            return ExitCode::from(2);
        }
    };

    // An allow entry that does not parse grants nothing. Say so loudly:
    // an operator who wrote `aws.*` believing it granted something is in
    // a worse position than one who wrote nothing at all.
    for bad in manifest.infra.malformed_entries() {
        eprintln!(
            "warning: allow entry `{bad}` is not a provider.service.verb pattern \
             and grants nothing"
        );
    }

    let decision = match check(&plan_src, &manifest) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("could not read the plan {plan_path}: {e}");
            return ExitCode::from(2);
        }
    };

    if as_json {
        print_json(&decision, &manifest);
    } else {
        print_human(&decision, &manifest);
    }
    ExitCode::from(decision.exit_code() as u8)
}

fn print_human(decision: &lex_iac::Decision, manifest: &InfraManifest) {
    println!("goal:      {}", manifest.goal);
    println!("plan:      sha256:{}", decision.plan.plan_sha256);
    println!("manifest:  sha256:{}", manifest.content_id());
    println!();

    match &decision.verdict {
        Verdict::Allow => {
            println!("ACCEPTED — every effect is inside the grant.");
            for e in decision.plan.required_effects() {
                println!("  {e}");
            }
            println!("\nApply exactly these bytes:");
            println!("  terraform apply p.tfplan");
        }
        Verdict::Deny { all, .. } => {
            println!("REFUSED — {} effect(s) outside the grant:", all.len());
            for r in all {
                println!("\n  {}  [{}]", r.effect, r.wall.as_str());
                println!("    at:     {}", r.address);
                println!("    reason: {}", r.reason);
            }
            println!("\nthe grant allows:");
            for a in &manifest.infra.allow {
                println!("  {a}");
            }
            if all.iter().any(|r| r.wall == Wall::Reversibility) {
                println!(
                    "\nA wildcard does not authorise destroying stateful infrastructure.\n\
                     Name the verb in the grant if that is genuinely intended."
                );
            }
        }
    }

    println!(
        "\naudit: {} entries, head sha256:{}",
        decision.audit.len(),
        decision.audit.head()
    );
}

fn print_json(decision: &lex_iac::Decision, manifest: &InfraManifest) {
    let refusals = match &decision.verdict {
        Verdict::Allow => Vec::new(),
        Verdict::Deny { all, .. } => all.clone(),
    };
    let out = serde_json::json!({
        "refused": !decision.verdict.allowed(),
        "plan_sha256": decision.plan.plan_sha256,
        "manifest": manifest.content_id(),
        "required_effects": decision.plan.required_effects(),
        "refusals": refusals,
        "audit_head": decision.audit.head(),
        "audit_entries": decision.audit.len(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialisable")
    );
}

fn cmd_narrow(args: &[&str]) -> ExitCode {
    let (Some(parent_path), Some(child_path)) = (flag(args, "--parent"), flag(args, "--child"))
    else {
        eprintln!("manifest narrow needs --parent and --child\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let (parent_src, child_src) = match (read(parent_path), read(child_path)) {
        (Ok(p), Ok(c)) => (p, c),
        (Err(c), _) | (_, Err(c)) => return c,
    };

    let (parent, child) = match (
        InfraManifest::from_json(&parent_src),
        InfraManifest::from_json(&child_src),
    ) {
        (Ok(p), Ok(c)) => (p, c),
        (Err(e), _) => {
            eprintln!("could not read {parent_path}: {e}");
            return ExitCode::from(2);
        }
        (_, Err(e)) => {
            eprintln!("could not read {child_path}: {e}");
            return ExitCode::from(2);
        }
    };

    match InfraManifest::validate_narrowing(&parent, &child) {
        Ok(()) => {
            println!("ACCEPTED — the child narrows the parent.");
            println!("  parent: sha256:{}", parent.content_id());
            println!("  child:  sha256:{}", child.content_id());
            ExitCode::from(0)
        }
        Err(e) => {
            println!("REFUSED — the child widens its parent.");
            println!("  {e}");
            ExitCode::from(8)
        }
    }
}
