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
    check, infra_facet, narrow, Chain, CostReport, Keyring, Manifest, PlanEvent, SigningKey,
    Standing, Submitter, Verdict, VerifyingKey, Wall,
};

const USAGE: &str = "\
usage:
  lex-iac check --grant <manifest.json> --plan <plan.json> [--cost <cost.json>]
                [--signer <id>] [--trusted-keys <keyring.json>]
                [--audit-out <log.json>] [--json]
                [--audit-key <hex> | --audit-key-file <path>]
  lex-iac manifest narrow --parent <manifest.json> --child <manifest.json>
  lex-iac audit verify --log <log.json> [--trusted-key <hex>]...
  lex-iac audit pubkey [--key <hex> | --key-file <path>]

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

--audit-key/--audit-key-file seals every entry of that log (lex-os#54).
The chain's hashes are derived, so whoever can reach the file can rewrite
a refusal into an acceptance and recompute them; the seal is the part they
cannot forge. `audit verify --trusted-key <public hex>` checks it. Prefer
the file: a secret in argv is a secret in `ps` and in shell history.

Note what a seal does NOT do: it does not make --signer true. That flag is
a claim typed on a command line, and nothing upstream of this gate
authenticates who ran `terraform plan`. Sealing raises the record from
unattributable-and-editable to attributable-to-this-gate and
tamper-evident.

exit: 0 allowed, 8 refused, 2 could not run";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match refs.as_slice() {
        ["check", rest @ ..] => cmd_check(rest),
        ["manifest", "narrow", rest @ ..] => cmd_narrow(rest),
        ["audit", "verify", rest @ ..] => cmd_audit_verify(rest),
        ["audit", "pubkey", rest @ ..] => cmd_audit_pubkey(rest),
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
/// Every value given for a flag, in order.
///
/// Both spellings, `--name value` and `--name=value`, and repeats of
/// either — `--trusted-key` is a list, and an operator should not have
/// to encode one into a single argument.
fn flags<'a>(args: &[&'a str], name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == name {
            if let Some(v) = args.get(i + 1) {
                out.push(*v);
            }
            i += 2;
            continue;
        }
        if let Some(rest) = a.strip_prefix(name) {
            if let Some(v) = rest.strip_prefix('=') {
                out.push(v);
            }
        }
        i += 1;
    }
    out
}

fn flag<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    flags(args, name).into_iter().next()
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

    let audit_key =
        match load_signing_key(flag(args, "--audit-key"), flag(args, "--audit-key-file")) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
    if audit_key.is_none() && flag(args, "--audit-out").is_some() {
        // Said out loud, because the file looks equally trustworthy
        // either way and only one of them is.
        eprintln!(
            "note: writing an UNSEALED audit log — anyone who can reach it can rewrite \
             a verdict and recompute the hashes. Pass --audit-key-file to seal it"
        );
    }

    let decision = match match &audit_key {
        Some(k) => {
            lex_iac::check_sealed(&plan_src, &manifest, cost.as_ref(), submitter.as_ref(), k)
        }
        None => check(&plan_src, &manifest, cost.as_ref(), submitter.as_ref()),
    } {
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
        "\naudit: {} entries, head sha256:{}{}",
        decision.audit.len(),
        decision.audit.head(),
        if !decision.audit.is_empty() && decision.audit.sealed_count() == decision.audit.len() {
            " (sealed)"
        } else {
            " (UNSEALED — anyone who can reach the file can rewrite it)"
        }
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

/// Read a 32-byte hex signing key from a flag or a file.
///
/// The file is the one to reach for: a secret in argv is a secret in
/// `ps` output and in shell history, and an audit key that leaks is an
/// audit log anyone can re-sign.
fn load_signing_key(
    key: Option<&str>,
    key_file: Option<&str>,
) -> Result<Option<SigningKey>, String> {
    let hex_key = match (key, key_file) {
        (None, None) => return Ok(None),
        (Some(k), _) => k.to_string(),
        (None, Some(p)) => std::fs::read_to_string(p)
            .map_err(|e| format!("cannot read {p}: {e}"))?
            .trim()
            .to_string(),
    };
    decode_key32(&hex_key).map(|b| Some(SigningKey::from_bytes(&b)))
}

fn decode_key32(hex_key: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_key.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("`{hex_key}` is not 32 hex-encoded bytes"))
}

/// `audit pubkey` — the public half of an audit signing key.
///
/// Sealing uses the secret and verifying uses the public key, and those
/// are different 32-byte strings. Deriving it here beats an operator
/// tracking a pair by hand — or worse, handing a verifier the secret
/// because it was the one they had.
fn cmd_audit_pubkey(args: &[&str]) -> ExitCode {
    match load_signing_key(flag(args, "--key"), flag(args, "--key-file")) {
        Ok(Some(k)) => {
            println!("{}", hex::encode(k.verifying_key().to_bytes()));
            ExitCode::from(0)
        }
        Ok(None) => {
            eprintln!("audit pubkey needs --key or --key-file\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

/// `audit verify` — the chain always, the seals when given a key.
///
/// Reported separately, because they catch different things and a single
/// `verified` would let a reader believe the log was held to a wall
/// nobody asked for:
///
/// - the **chain** catches an edited payload and a reordered entry, but
///   not a holder who edits and then recomputes every hash;
/// - the **seals** catch exactly that holder.
///
/// Supplying no key checks no seals, and says so rather than passing.
fn cmd_audit_verify(args: &[&str]) -> ExitCode {
    let Some(path) = flag(args, "--log") else {
        eprintln!("audit verify needs --log\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let src = match read(path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let log: Chain<PlanEvent> = match Chain::from_json(&src) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not read the audit log {path}: {e}");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = log.verify() {
        println!("REFUSED — the hash chain is broken.");
        println!("  {e}");
        return ExitCode::from(8);
    }

    let trusted_hex = flags(args, "--trusted-key");
    if trusted_hex.is_empty() {
        println!(
            "chain:  OK — {} entries, head sha256:{}",
            log.len(),
            log.head()
        );
        println!(
            "seals:  NOT CHECKED — {} of {} entries carry one.",
            log.sealed_count(),
            log.len()
        );
        println!("        Pass --trusted-key <hex> to hold them to it.");
        return ExitCode::from(0);
    }

    let mut trusted = Vec::new();
    for h in &trusted_hex {
        match decode_key32(h).and_then(|b| {
            VerifyingKey::from_bytes(&b).map_err(|_| format!("`{h}` is not an Ed25519 public key"))
        }) {
            Ok(k) => trusted.push(k),
            Err(e) => {
                eprintln!("--trusted-key {e}");
                return ExitCode::from(2);
            }
        }
    }

    match log.verify_seals(&trusted) {
        Ok(()) => {
            println!(
                "chain:  OK — {} entries, head sha256:{}",
                log.len(),
                log.head()
            );
            println!("seals:  OK — every entry sealed by a trusted key.");
            ExitCode::from(0)
        }
        Err(e) => {
            println!("REFUSED — the seals do not hold.");
            println!("  {e}");
            println!(
                "\nA broken seal on an intact chain is the interesting case: it means\n\
                 somebody edited the log and recomputed the hashes. That is precisely\n\
                 what the chain alone cannot see."
            );
            ExitCode::from(8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::flags;

    /// Both spellings, and repeats of either.
    #[test]
    fn flags_read_both_spellings() {
        let args = ["--log=log.json", "--trusted-key", "aa", "--trusted-key=bb"];
        assert_eq!(flags(&args, "--log"), vec!["log.json"]);
        assert_eq!(flags(&args, "--trusted-key"), vec!["aa", "bb"]);
        assert!(flags(&args, "--cost").is_empty());
    }

    /// A prefix is not a flag: `--audit` must not match `--audit-out`,
    /// or a typo silently configures something else.
    #[test]
    fn a_prefix_of_a_flag_is_not_that_flag() {
        let args = ["--audit-out=log.json"];
        assert!(flags(&args, "--audit").is_empty());
        assert_eq!(flags(&args, "--audit-out"), vec!["log.json"]);
    }

    #[test]
    fn a_trailing_flag_has_no_value() {
        assert!(flags(&["--log"], "--log").is_empty());
    }
}
