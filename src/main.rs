//! `lex-iac` — the gate, on the command line.
//!
//! ```sh
//! terraform plan -out=p.tfplan && terraform show -json p.tfplan > plan.json
//! infracost breakdown --path p.tfplan --format json > cost.json
//! lex-iac check --grant env.json --plan plan.json --cost cost.json \
//!     --signer ci@payments --trusted-keys trusted.json --audit-out log.json
//! lex-iac manifest narrow --parent org.json --child env.json
//! ```
//!
//! `--audit-out` is what makes a decision outlive the process: the file
//! is the `{seq, prev_hash, event, hash}` array `lex attest
//! import-apply` promotes into the attestation graph, which is where
//! `trusted.json` above comes from in the first place.
//!
//! Exit codes follow lex-os: `0` allowed, `8` refused, `2` the gate
//! could not run (bad usage, unreadable file). The distinction between
//! 8 and 2 is the point — a refusal is a decision, not a malfunction,
//! and a pipeline that treats them alike will eventually treat a broken
//! gate as an approval.

use std::process::ExitCode;

use lex_iac::{
    check, infra_facet, narrow, CostReport, Keyring, Manifest, Standing, Submitter, Verdict, Wall,
};

const USAGE: &str = "\
usage:
  lex-iac check --grant <manifest.json> --plan <plan.json> [--cost <cost.json>]
                [--signer <id>] [--trusted-keys <keyring.json>]
                [--audit-out <log.json>] [--json]
  lex-iac manifest narrow --parent <manifest.json> --child <manifest.json>

--cost takes an estimator's JSON (Infracost today). Without it the spend
is unknown, and an unknown price is not a price of zero: creating or
replacing infrastructure then needs its verb named in the grant.

--signer names who submitted the plan; it is recorded in the audit log so
the decision can be promoted with `lex attest import-apply`.

--trusted-keys takes the `{\"trusted\":[...]}` keyring written by
`lex producer-trust keyring --min-trust N`. A submitter that is not on it
is held to the narrower reading of the same grant: every mutating verb
named, no wildcards. It never widens the grant.

--audit-out writes the hash-chained decision log, which is the input to
`lex attest import-apply`.

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

/// Minor units as a decimal. Integer arithmetic only, matching the
/// house rule that money never touches a float.
fn money(minor: i64) -> String {
    let sign = if minor < 0 { "-" } else { "" };
    let n = minor.unsigned_abs();
    format!("{sign}{}.{:02}", n / 100, n % 100)
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

    let manifest = match Manifest::from_json(&grant_src) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("could not read the grant manifest {grant_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let infra = match infra_facet(&manifest) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("could not read the grant manifest {grant_path}: {e}");
            return ExitCode::from(2);
        }
    };
    if !manifest.has_facet("infra") {
        eprintln!(
            "warning: {grant_path} carries no `infra` facet, so it authorises no \
             infrastructure change at all"
        );
    }

    // An allow entry that does not parse grants nothing. Say so loudly:
    // an operator who wrote `aws.*` believing it granted something is in
    // a worse position than one who wrote nothing at all.
    for bad in infra.malformed_entries() {
        eprintln!(
            "warning: allow entry `{bad}` is not a provider.service.verb pattern \
             and grants nothing"
        );
    }

    let cost = match flag(args, "--cost") {
        None => None,
        Some(path) => {
            let src = match read(path) {
                Ok(s) => s,
                Err(c) => return c,
            };
            match CostReport::from_infracost_json(&src) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!("could not read the cost report {path}: {e}");
                    return ExitCode::from(2);
                }
            }
        }
    };
    if cost.is_none() {
        eprintln!(
            "note: no --cost report, so spend is unknown; creating or replacing \
             infrastructure needs its verb named in the grant"
        );
    }

    // Who is asking, and what their record says. Consulting a keyring
    // about nobody is a usage error rather than a silent no-op: a
    // pipeline that meant to check trust and quietly did not is worse
    // off than one told to name its submitter.
    let submitter = match (flag(args, "--signer"), flag(args, "--trusted-keys")) {
        (None, Some(_)) => {
            eprintln!("--trusted-keys needs --signer: a keyring says nothing about an unnamed submitter\n\n{USAGE}");
            return ExitCode::from(2);
        }
        (None, None) => {
            eprintln!(
                "note: no --signer, so the audit log attributes this decision to nobody; \
                 `lex attest import-apply` will need its own --signer to promote it"
            );
            None
        }
        (Some(signer), None) => Some(Submitter::unconsulted(signer)),
        (Some(signer), Some(path)) => {
            let src = match read(path) {
                Ok(s) => s,
                Err(c) => return c,
            };
            let keyring = match Keyring::from_json(&src) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("could not read the keyring {path}: {e}");
                    return ExitCode::from(2);
                }
            };
            if keyring.trusted.is_empty() {
                eprintln!(
                    "warning: {path} trusts nobody, so every submitter is held to the \
                     narrower grant"
                );
            }
            Some(Submitter::against(signer, &keyring))
        }
    };

    let decision = match check(&plan_src, &manifest, cost.as_ref(), submitter.as_ref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("the gate could not run: {e}");
            return ExitCode::from(2);
        }
    };

    // Written before the verdict is printed and before the exit code is
    // returned: a decision the operator can see but not keep is not a
    // record. A log that cannot be written is a failure of the gate
    // (exit 2), never a quiet success — the whole promotion loop
    // downstream reads this file.
    if let Some(path) = flag(args, "--audit-out") {
        let json = match decision.audit.to_json() {
            Ok(j) => j,
            Err(e) => {
                eprintln!("could not serialise the audit log: {e}");
                return ExitCode::from(2);
            }
        };
        if let Err(e) = std::fs::write(path, json) {
            eprintln!("could not write the audit log {path}: {e}");
            return ExitCode::from(2);
        }
    }

    if as_json {
        print_json(&decision, &manifest, &infra);
    } else {
        print_human(&decision, &manifest, &infra);
    }
    ExitCode::from(decision.exit_code() as u8)
}

fn print_human(decision: &lex_iac::Decision, manifest: &Manifest, infra: &lex_iac::InfraFacet) {
    println!("goal:      {}", manifest.goal.description);
    println!("plan:      sha256:{}", decision.plan.plan_sha256);
    println!("grant:     {}", manifest.content_id());
    match decision.charged {
        Some(minor) => println!(
            "spend:     {} {} / month against a ceiling of {} (forecast, not a meter)",
            infra.currency,
            money(minor),
            money(manifest.budget.max_money_cents as i64)
        ),
        None => println!("spend:     unpriced — no --cost report"),
    }
    match (&decision.signer, decision.standing) {
        (None, _) => println!("submitter: unattributed"),
        (Some(s), Standing::NotConsulted) => println!("submitter: {s} (trust not consulted)"),
        (Some(s), Standing::Trusted) => println!("submitter: {s} (in the trusted keyring)"),
        (Some(s), Standing::Unknown) => {
            println!("submitter: {s} (not in the trusted keyring — held to the narrower grant)")
        }
    }
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
            for a in &infra.allow {
                println!("  {a}");
            }
            if all.iter().any(|r| r.wall == Wall::Budget) {
                // Two different budget refusals want two different
                // remedies, and offering the wrong one costs the reader
                // a round trip: raising a ceiling does nothing for a
                // change nobody has priced.
                match decision.charged {
                    Some(_) => println!(
                        "\nThe budget is a ceiling on *forecast* monthly spend, not a meter.\n\
                         Raise it in the manifest, or narrow the plan."
                    ),
                    None => println!(
                        "\nNo estimate is not an estimate of zero. Pass --cost with your\n\
                         estimator's JSON, or name the verb in the grant to accept it unpriced."
                    ),
                }
            }
            if all.iter().any(|r| r.wall == Wall::Reversibility) {
                println!(
                    "\nA wildcard does not authorise destroying stateful infrastructure.\n\
                     Name the verb in the grant if that is genuinely intended."
                );
            }
            if all.iter().any(|r| r.wall == Wall::Trust) {
                // The remedy that is *not* offered here: widening the
                // grant to get past it. Naming the verb is narrower
                // than the wildcard already granted, and earning a
                // score changes nothing about the ceiling.
                println!(
                    "\nThis submitter has no earned standing, so a wildcard does not carry it.\n\
                     Name the verbs in the grant, or promote its past decisions\n\
                     (`lex attest import-apply`) so it can score above your threshold."
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

fn print_json(decision: &lex_iac::Decision, manifest: &Manifest, infra: &lex_iac::InfraFacet) {
    let refusals = match &decision.verdict {
        Verdict::Allow => Vec::new(),
        Verdict::Deny { all, .. } => all.clone(),
    };
    let out = serde_json::json!({
        "refused": !decision.verdict.allowed(),
        // The report's own name for the hash. The audit log spells the
        // same value `artifact_sha256`, because that is what the
        // promotion contract calls it — see `gate::PlanEvent`.
        "plan_sha256": decision.plan.plan_sha256,
        "signer": decision.signer,
        "trust": decision.standing.as_str(),
        "manifest": manifest.content_id().0,
        "grant_allows": infra.allow,
        "currency": infra.currency,
        "monthly_delta_minor": decision.charged,
        "budget_minor": manifest.budget.max_money_cents,
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
        Manifest::from_json(&parent_src),
        Manifest::from_json(&child_src),
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

    match narrow(&parent, &child) {
        Ok(()) => {
            println!("ACCEPTED — the child narrows the parent.");
            println!("  parent: {}", parent.content_id());
            println!("  child:  {}", child.content_id());
            ExitCode::from(0)
        }
        Err(e) => {
            println!("REFUSED — the child widens its parent.");
            println!("  {e}");
            ExitCode::from(8)
        }
    }
}
