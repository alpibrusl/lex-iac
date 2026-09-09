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
  lex-iac check --grant <manifest.json> (--tfplan <tfplan> | --plan <plan.json>)
                [--cost <cost.json>]
                [--signer <id>] [--trusted-keys <keyring.json>]
                [--audit-out <log.json>] [--checkpoint-out <cp.json>]
                [--ledger <ledger.json>] [--json]
                [--audit-key <hex> | --audit-key-file <path>]
  lex-iac apply --grant <manifest.json> --plan <plan.json> --box-rootfs <box.ext4>
                [--box-kernel <vmlinux>] [--work-dir /work] [--tfplan tfplan]
                [--jail-uid <n>] [--jail-gid <n>] [--lex-os <path>] [--dry-run]
                [--credential-env <NAME>]
                [--state <prior.tfstate>] [--state-out <candidate.tfstate>]
                [every `check` flag too]
  lex-iac state commit --plan <plan.json> --prior <prior.tfstate>
                       --candidate <candidate.tfstate> [--commit-to <path>] [--json]
  lex-iac manifest narrow --parent <manifest.json> --child <manifest.json>
  lex-iac audit reconcile --ledger <ledger.json> --decisions <dir>
                       [--trusted-key <hex>]...
  lex-iac audit verify --log <log.json> [--trusted-key <hex>]...
                       [--checkpoint <cp.json>]
  lex-iac audit pubkey [--key <hex> | --key-file <path>]

--state stages a prior state file into the box before it boots, and
--state-out takes the candidate back out after it halts and decides
whether it may become the record: every resource that differs must be one
the gated plan named, with a verb that agrees. On a refusal nothing is
written, because a state the plan does not account for is the input to
every plan after it. Both use `debugfs` (e2fsprogs) to touch the image
without mounting it — no root, no loop device, and nothing of the guest's
filesystem in the host kernel.

--credential-env names an environment variable whose value is handed to
the box (option A of #17). The value is read from this environment, never
from the command line, and never appears in argv — `ps` is readable by
other users. It travels on the guest's stdin and lands in the manifest
goal, so the audit chain records that goal's hash rather than its text.
A credential is refused when the grant permits no egress: the allowlist
is the only thing bounding where it can be spent.

The box holds the token. Nothing bounds *which* calls it makes at an
allowed endpoint — see docs/threat-model.md, which also lists what would
make the host-side proxy worth building instead.

`state commit` is the wall between an apply and the record every later
plan is computed from. A box that can write state can forge that record,
and a gate reasoning about a plan derived from forged state is reasoning
about a document rather than about reality. So the box gets prior state
as a file and no backend credential; it emits a candidate, and this
decides whether the candidate may become the record: every resource that
differs between prior and candidate must be one the gated plan named,
with a verb that agrees.

It refuses a change the plan did not declare. It does not require every
declared change to have happened — an apply that stopped halfway is a
legitimate thing to record, and refusing it would lose the evidence of
what did happen. The check is structural: it sees which resources
changed and how, never whether the values written were the right ones.

--commit-to writes the candidate there on success. Without it the verdict
is the output and the caller acts on the exit code, which is what a
remote backend needs.

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

`apply` is `check`, and then — only if the gate allowed it — the same plan
applied inside a lex-os microVM whose egress is the grant's own allowlist.
A refusal never reaches the box: nothing is executed, and the exit code is
the gate's.

The box is confined by the SAME manifest the gate checked, byte for byte,
so there is no second declaration to drift. A grant with `exec: None` is
refused up front: a grant may authorise a decision without authorising the
action, which is why `check` and `apply` are separate verbs.

The box applies a *planned document* (`--tfplan`), never a config: it does
not re-plan, and it does not `init`, which would fetch provider code from a
registry the box is not allowed to reach. Build the image with
`demo/build-box.sh`.

exit: 0 allowed, 8 refused, 2 could not run";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match refs.as_slice() {
        ["check", rest @ ..] => cmd_check(rest),
        ["manifest", "narrow", rest @ ..] => cmd_narrow(rest),
        ["apply", rest @ ..] => cmd_apply(rest),
        ["state", "commit", rest @ ..] => cmd_state_commit(rest),
        ["audit", "reconcile", rest @ ..] => cmd_audit_reconcile(rest),
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
    let Some(grant_path) = flag(args, "--grant") else {
        eprintln!("check needs --grant\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let as_json = args.contains(&"--json");

    // Two ways to name the plan, and they are not equivalent.
    //
    // `--tfplan` names the saved binary plan — the artifact terraform
    // will actually apply — and the JSON is *derived* from it here, so
    // the document the gate reasons about is a view of those bytes.
    // `--plan` takes a JSON someone else produced, which is still
    // supported (an estimator or a CI step may already have it) but
    // cannot say anything about what apply will read. Prefer --tfplan.
    let artifact = flag(args, "--tfplan");
    let plan_path_opt = flag(args, "--plan");
    let (plan_src, tfplan_sha256) = match (artifact, plan_path_opt) {
        (Some(tf), _) => match lex_iac::derive_plan_json(std::path::Path::new(tf)) {
            Ok((json, digest)) => (json, Some(digest)),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        },
        (None, Some(p)) => match read(p) {
            Ok(src) => (src, None),
            Err(c) => return c,
        },
        (None, None) => {
            eprintln!("check needs --tfplan (preferred) or --plan\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let grant_src = match read(grant_path) {
        Ok(g) => g,
        Err(c) => return c,
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

    // The witness that survives the file (#18).
    //
    // A checkpoint proves a chain is no shorter than it was. Nothing
    // counts the chains, so deleting a whole decision log leaves no gap
    // — and that is the easier attack. One long-lived ledger, appended
    // to after every decision, turns it into a head with nothing behind
    // it.
    if let Some(path) = flag(args, "--ledger") {
        let event = lex_iac::ledger::LedgerEvent::PlanDecided {
            subject: manifest.goal.description.clone(),
            verdict: match &decision.verdict {
                lex_iac::Verdict::Allow => "accepted".into(),
                _ => "refused".into(),
            },
            decision_head: decision.audit.head(),
            decision_entries: decision.audit.len() as u64,
            plan_sha256: decision.plan.plan_sha256.clone(),
            tfplan_sha256: tfplan_sha256.clone(),
            signer: audit_key
                .as_ref()
                .map(|k| hex::encode(k.verifying_key().to_bytes())),
        };
        match lex_iac::ledger::witness(std::path::Path::new(path), event, audit_key.as_ref()) {
            Ok(head) => println!(
                "ledger:    witnessed in {path}, head sha256:{}",
                &head[..16.min(head.len())]
            ),
            Err(e) => {
                eprintln!("could not witness the decision: {e}");
                return ExitCode::from(2);
            }
        }
    }

    // The commitment that survives a deletion (#21).
    //
    // Kept out of the log deliberately. A checkpoint stored beside the
    // thing it commits to is removed in the same motion as the entry it
    // would have testified about; its whole value is being somewhere the
    // editor of the log does not reach. So it is a separate file the
    // operator is expected to put somewhere else, and the flag is
    // separate from --audit-out to make that a decision rather than a
    // default.
    if let Some(path) = flag(args, "--checkpoint-out") {
        let Some(key) = &audit_key else {
            eprintln!(
                "--checkpoint-out needs --audit-key/--audit-key-file: an unsigned commitment \
                 is one anybody can rewrite, which is the thing it exists to prevent"
            );
            return ExitCode::from(2);
        };
        // The crate reads no clock; the caller supplies the time it can
        // defend. Seconds since the epoch is what an operator can check
        // against everything else in an incident timeline.
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cp = decision.audit.checkpoint(key, at);
        match serde_json::to_string_pretty(&cp)
            .map_err(|e| e.to_string())
            .and_then(|j| std::fs::write(path, j).map_err(|e| e.to_string()))
        {
            Ok(()) => println!(
                "checkpoint: {} entries at head sha256:{} -> {path}",
                cp.len,
                &cp.head[..16.min(cp.head.len())]
            ),
            Err(e) => {
                eprintln!("could not write the checkpoint {path}: {e}");
                return ExitCode::from(2);
            }
        }
    }

    if as_json {
        print_json(&decision, &manifest, &infra);
    } else {
        print_human(&decision, &manifest, &infra, &tfplan_sha256);
    }

    // Write down what was accepted, so a later apply has something to be
    // held to. Only on an acceptance, and only when the artifact is
    // known: an approval that cannot name the bytes it approved is the
    // problem, not a weaker version of the solution.
    if let Some(out) = flag(args, "--approval-out") {
        match (&decision.verdict, &tfplan_sha256) {
            (lex_iac::Verdict::Allow, Some(digest)) => {
                let approval = lex_iac::Approval {
                    verdict: "accepted".into(),
                    tfplan_sha256: digest.clone(),
                    plan_sha256: decision.plan.plan_sha256.clone(),
                    manifest_sha256: lex_iac::manifest_digest(&grant_src),
                    goal: manifest.goal.description.clone(),
                };
                match serde_json::to_string_pretty(&approval)
                    .map_err(|e| e.to_string())
                    .and_then(|j| std::fs::write(out, j).map_err(|e| e.to_string()))
                {
                    Ok(()) => println!("approval:  written to {out}"),
                    Err(e) => {
                        eprintln!("could not write the approval to {out}: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            (lex_iac::Verdict::Allow, None) => {
                eprintln!(
                    "refusing to write an approval: --plan was supplied, so nothing here \
                     names the artifact an apply would run. Use --tfplan."
                );
                return ExitCode::from(2);
            }
            _ => {}
        }
    }
    ExitCode::from(decision.exit_code() as u8)
}

fn print_human(
    decision: &lex_iac::Decision,
    manifest: &Manifest,
    infra: &lex_iac::InfraFacet,
    tfplan_sha256: &Option<String>,
) {
    println!("goal:      {}", manifest.goal.description);
    println!("plan:      sha256:{}", decision.plan.plan_sha256);
    match &tfplan_sha256 {
        Some(d) => println!("artifact:  sha256:{d}  (the saved plan this JSON was read from)"),
        None => println!(
            "artifact:  unbound — the JSON was supplied, not derived; \
             pass --tfplan so apply can prove it is holding the same bytes"
        ),
    }
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

/// Hold a chain to a signed commitment about how long it once was.
///
/// Separate from the seals on purpose. A seal proves an entry is
/// genuine; every entry left after a truncation is genuine, which is
/// why `verify_seals` reports OK on a log somebody shortened. The only
/// evidence that can contradict a deletion is a statement made while
/// the entry still existed.
fn checkpoint_verdict(
    args: &[&str],
    log: &Chain<PlanEvent>,
    trusted: &[VerifyingKey],
) -> Result<String, String> {
    let Some(path) = flag(args, "--checkpoint") else {
        return Ok(
            "length: NOT CHECKED — pass --checkpoint <file> to detect deleted entries.".into(),
        );
    };
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read the checkpoint {path}: {e}"))?;
    let cp: lex_os_audit::Checkpoint = serde_json::from_str(&src)
        .map_err(|e| format!("could not read the checkpoint {path}: {e}"))?;

    // Verified against a key the caller trusts, never taken on its own
    // word: whoever can truncate a log can also write the checkpoint
    // that says the truncated length was right.
    let mut verified = None;
    for k in trusted {
        if let Ok(v) = cp.verify(k) {
            verified = Some(v);
            break;
        }
    }
    let Some(verified) = verified else {
        return Err(format!(
            "the checkpoint is not signed by any --trusted-key.\n  \
             it claims length {} at head sha256:{}\n  \
             signed by: {}",
            cp.len, cp.head, cp.signer
        ));
    };

    log.verify_against(&verified).map_err(|e| {
        format!(
            "{e}\n\n\
             The chain on disk is intact and its seals hold — every entry left in it\n\
             is genuine. That is what makes this the quiet attack: nothing was forged,\n\
             something was removed, and only a commitment made beforehand can say so."
        )
    })?;
    Ok(format!(
        "length: OK — at least {} entries, matching the checkpoint's head.",
        verified.as_checkpoint().len
    ))
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
/// - the **checkpoint** catches a truncation, which neither of the
///   others can: every entry left after a deletion is genuine and the
///   chain that remains is intact (#21).
///
/// Supplying no key checks no seals, and says so rather than passing.
/// Supplying no checkpoint checks no length, and says that too.
/// `audit reconcile` — hold the ledger and the decision files to each
/// other.
///
/// Both directions, because neither is provable from the other side
/// alone: a witnessed head with no file is a deletion, and a file no
/// witness names is a plant — or a ledger that lost its own tail, which
/// is the same evidence read the other way round.
fn cmd_audit_reconcile(args: &[&str]) -> ExitCode {
    let (Some(ledger_path), Some(dir)) = (flag(args, "--ledger"), flag(args, "--decisions")) else {
        eprintln!("audit reconcile needs --ledger and --decisions\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let src = match read(ledger_path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let ledger: lex_iac::ledger::Ledger = match Chain::from_json(&src) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not read the ledger {ledger_path}: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = ledger.verify() {
        println!("REFUSED — the ledger's own chain is broken.");
        println!("  {e}");
        return ExitCode::from(8);
    }

    // A ledger that does not begin with `ledger_opened` has lost its
    // head, whatever its hashes say: the remaining entries chain to each
    // other perfectly well.
    let opened_first = matches!(
        ledger.entries().first().map(|e| &e.event),
        Some(lex_iac::ledger::LedgerEvent::LedgerOpened { .. })
    );
    if !opened_first {
        println!("REFUSED — the ledger does not begin where a ledger begins.");
        println!(
            "  Its first entry is not `ledger_opened`, so entries have been removed from \n               the front. What remains is internally consistent, which is the point."
        );
        return ExitCode::from(8);
    }

    // Every decision chain in the directory, by head.
    let mut heads = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("could not read the decisions directory {dir}: {e}");
            return ExitCode::from(2);
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(chain) = Chain::<PlanEvent>::from_json(&text) {
            heads.push(chain.head());
        }
    }

    let r = lex_iac::ledger::reconcile(&ledger, &heads);
    if r.agrees() {
        println!(
            "ledger:  OK — {} decision(s) witnessed, {} file(s), and they agree.",
            r.witnessed, r.files
        );
        return ExitCode::from(0);
    }
    println!("REFUSED — the ledger and the decision files disagree.");
    for h in &r.missing {
        println!("  witnessed but absent: sha256:{h}");
        println!("    a decision the ledger recorded has no file behind it — it was deleted");
    }
    for h in &r.unwitnessed {
        println!("  present but unwitnessed: sha256:{h}");
        println!("    a decision file no witness names — planted, or the ledger lost its tail");
    }
    ExitCode::from(8)
}

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
            // A ledger is a chain too, and reaching for `audit verify`
            // on one is the obvious mistake. The domain separation that
            // makes the two unmixable also makes the serde error
            // unreadable, so name the likely cause.
            if src.contains("ledger_opened") {
                eprintln!(
                    "{path} is a ledger, not a decision log — its entries are witnesses \
                     rather than verdicts.\n\n  \
                     lex-iac audit reconcile --ledger {path} --decisions <dir>"
                );
                return ExitCode::from(2);
            }
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
        println!(
            "length: NOT CHECKED — without a checkpoint, entries deleted from the end\n\
             \x20       are indistinguishable from entries never written."
        );
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
            // The truncation wall. An intact chain says nothing about
            // entries that are no longer in it: drop the last one and
            // what remains verifies clean, seals and all. Only a
            // commitment made when the log was longer can notice, which
            // is why this is a separate input and not something the log
            // can assert about itself (#21).
            match checkpoint_verdict(args, &log, &trusted) {
                Ok(line) => {
                    println!("{line}");
                    ExitCode::from(0)
                }
                Err(e) => {
                    println!("REFUSED — {e}");
                    ExitCode::from(8)
                }
            }
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

/// `<domain>:<head>` for the decision chain at `path`, if there is one.
///
/// `None` when no chain was written, or when it cannot be read: an
/// unlinked session is the truthful outcome there, and inventing a head
/// would be worse than admitting the pair is unlinked.
fn box_audit_link(path: Option<&str>) -> Option<String> {
    let path = path?;
    let src = std::fs::read_to_string(path).ok()?;
    let chain: Chain<PlanEvent> = Chain::from_json(&src).ok()?;
    Some(format!("{}:{}", lex_iac::PLAN_AUDIT_DOMAIN, chain.head()))
}

/// `apply` — gate the plan, then apply it inside the box.
///
/// The order is the whole point, and it is structural rather than
/// conventional: the gate runs first, a refusal returns before the box
/// is built, and the argv that would boot it is not constructed on that
/// path. There is no branch where a refused plan reaches terraform.
fn cmd_apply(args: &[&str]) -> ExitCode {
    // 1. The gate. Identical to `check` — same inputs, same walls, same
    //    audit — because a plan that `check` refuses must not become
    //    applicable by asking a different way.
    let code = cmd_check(args);
    if code != ExitCode::from(0) {
        eprintln!();
        eprintln!("apply: the gate did not allow this plan, so nothing was executed.");
        eprintln!("       The box was never booted and terraform was never invoked.");
        return code;
    }

    let Some(grant_path) = flag(args, "--grant") else {
        eprintln!("apply needs --grant\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let Some(rootfs) = flag(args, "--box-rootfs") else {
        eprintln!(
            "apply needs --box-rootfs: the guest image carrying terraform and the planned\n\
             working directory. Build one with demo/build-box.sh.\n\n{USAGE}"
        );
        return ExitCode::from(2);
    };

    // 2. Applying is executing, and a grant that never said so does not
    //    authorise it. lex-os refuses this at the perimeter anyway; this
    //    is the same refusal delivered as a sentence rather than as a
    //    booted VM and a denial.
    let manifest = match read(grant_path).and_then(|src| {
        Manifest::from_json(&src).map_err(|e| {
            eprintln!("could not read the grant {grant_path}: {e}");
            ExitCode::from(2)
        })
    }) {
        Ok(m) => m,
        Err(c) => return c,
    };
    if let Err(why) = lex_iac::permits_apply(&manifest) {
        println!();
        println!("REFUSED — {why}");
        return ExitCode::from(8);
    }

    // Absolute before it crosses the process boundary: lex-os resolves
    // relative paths against its own cwd, and the jailer chroots before
    // opening them.
    let rootfs = match lex_iac::resolve_box_path("rootfs", std::path::Path::new(rootfs)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let kernel = match flag(args, "--box-kernel") {
        None => None,
        Some(k) => match lex_iac::resolve_box_path("kernel", std::path::Path::new(k)) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        },
    };
    if kernel.is_none() {
        eprintln!(
            "note: no --box-kernel, so lex-os boots its own default — which is a path \
             relative to the lex-os checkout, not this one. Pass --box-kernel if \
             provisioning cannot find it."
        );
    }

    // The binding, and the reason `apply` is more than `check` plus a
    // boot. An earlier acceptance named a digest; this is where the file
    // about to be applied is held to it.
    //
    // Note it compares against an approval written by a *previous* run.
    // Re-deriving the digest here and comparing it to itself would be
    // circular — the first attempt at this did exactly that and proved
    // nothing, because the threat is not a swap within one process, it
    // is a swap between the approval and the apply.
    if let Some(app_path) = flag(args, "--approval") {
        let Some(tf) = flag(args, "--tfplan") else {
            eprintln!("--approval needs --tfplan: the approval names an artifact, so apply must be given one to hold to it");
            return ExitCode::from(2);
        };
        let src = match read(app_path) {
            Ok(s) => s,
            Err(c) => return c,
        };
        let approval: lex_iac::Approval = match serde_json::from_str(&src) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("could not read the approval {app_path}: {e}");
                return ExitCode::from(2);
            }
        };
        let grant_for_check = match read(grant_path) {
            Ok(g) => g,
            Err(c) => return c,
        };
        if let Err(why) = approval.admits(std::path::Path::new(tf), &grant_for_check) {
            println!();
            println!("REFUSED — {why}");
            println!();
            println!("Nothing was applied. The box was never booted.");
            return ExitCode::from(8);
        }
        println!(
            "approval:  sha256:{} verified — this is the artifact that was accepted",
            approval.tfplan_sha256
        );
    }

    let spec = lex_iac::BoxSpec {
        rootfs,
        kernel,
        work_dir: flag(args, "--work-dir").unwrap_or("/work").to_string(),
        tfplan: flag(args, "--tfplan").unwrap_or("tfplan").to_string(),
        lex_os: flag(args, "--lex-os").unwrap_or("lex-os").to_string(),
        jail_uid: flag(args, "--jail-uid").and_then(|v| v.parse().ok()),
        jail_gid: flag(args, "--jail-gid").and_then(|v| v.parse().ok()),
    };
    let box_audit = flag(args, "--box-audit-out");
    // The link between the two records (#19).
    //
    // Read back from the chain `cmd_check` just wrote, rather than
    // recomputed here. Two reasons. It is the head of the record that
    // actually exists on disk, not of one reconstructed from the same
    // inputs — those can differ, and a link to a decision nobody kept is
    // not evidence of anything. And it makes the dependency honest: a
    // run without `--audit-out` has no persisted decision to point at,
    // so it passes no authorisation and the session correctly claims
    // none.
    let authorisation = box_audit_link(flag(args, "--audit-out"));
    // Option A of the credential design (#17): the box holds the token.
    // Read from this environment, never from argv — `ps` is readable by
    // other users on a shared host.
    let credential = match flag(args, "--credential-env") {
        None => None,
        Some(name) => match lex_iac::apply::Credential::from_env(name, &manifest.egress) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        },
    };

    // lex-os reads the guest's stdin from a *file*, so the value has to
    // be somewhere for the length of the run. `/dev/shm` is tmpfs, so on
    // a Linux host — the only kind that can boot a real box — it never
    // reaches a disk. Elsewhere it falls back to the temp dir and says
    // so, because a secret briefly on disk is a different promise.
    let cred_file = match &credential {
        None => None,
        Some(c) => {
            let dir = std::path::Path::new("/dev/shm");
            let dir = if dir.is_dir() {
                dir.to_path_buf()
            } else {
                eprintln!(
                    "note: no /dev/shm on this host, so the credential is staged in \
                     {} — on disk, not in memory, until this run ends",
                    std::env::temp_dir().display()
                );
                std::env::temp_dir()
            };
            let path = dir.join(format!("lex-iac-cred-{}", std::process::id()));
            if let Err(e) = write_secret(&path, &c.stdin_line()) {
                eprintln!("could not stage the credential: {e}");
                return ExitCode::from(2);
            }
            Some(path)
        }
    };

    let argv = {
        let mut a = lex_iac::apply::apply_argv_with_credential(
            &spec,
            grant_path,
            box_audit,
            authorisation.as_deref(),
            credential.as_ref(),
        );
        if let Some(f) = &cred_file {
            // Insert before the `--` that ends lex-os's own flags.
            let at = a.iter().position(|x| x == "--").unwrap_or(a.len());
            a.splice(
                at..at,
                ["--stdin-file".to_string(), f.display().to_string()],
            );
        }
        a
    };

    // The plan `check` just accepted, re-derived so the state wall can
    // be held to the same document rather than to a second reading of
    // it. Only needed when a candidate is coming back.
    let plan_src = if flag(args, "--state-out").is_some() {
        match (flag(args, "--tfplan"), flag(args, "--plan")) {
            (Some(tf), _) => match lex_iac::derive_plan_json(std::path::Path::new(tf)) {
                Ok((json, _)) => Some(json),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            (None, Some(p)) => match read(p) {
                Ok(src) => Some(src),
                Err(c) => return c,
            },
            (None, None) => {
                eprintln!("--state-out needs the plan too: pass --tfplan or --plan");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    // The state half of #17. Prior state goes into the image before the
    // box boots, because lex-os gives the box no host mount while it
    // runs — that is the boundary, and this works with it rather than
    // around it.
    let guest_state = format!("{}/terraform.tfstate", spec.work_dir);
    let prior_src = match flag(args, "--state") {
        None => None,
        Some(path) => match read(path) {
            Ok(src) => Some(src),
            Err(c) => return c,
        },
    };
    if let Some(src) = &prior_src {
        if let Err(e) = lex_iac::guestfs::write_file(&spec.rootfs, &guest_state, src) {
            eprintln!("could not stage prior state into the box: {e}");
            return ExitCode::from(2);
        }
        println!(
            "  staged prior state at {guest_state} ({} bytes)",
            src.len()
        );
    }

    println!();
    println!("ALLOWED — applying inside the box.");
    println!("  {}", argv.join(" "));

    if args.contains(&"--dry-run") {
        println!();
        println!("(--dry-run: the box was not booted)");
        return ExitCode::from(0);
    }

    // 3. Hand off. lex-os owns the perimeter; this gate does not
    //    reimplement it, and its exit code is passed through unchanged —
    //    a box that refused an effect must not read as an apply that
    //    succeeded.
    let status = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status();
    // Before anything branches on the outcome: a refusal is not a reason
    // to leave a token lying around.
    if let Some(f) = &cred_file {
        let _ = std::fs::remove_file(f);
    }
    match status {
        Ok(st) => {
            let code = st.code().unwrap_or(2);
            println!();
            println!("box exited {code}");

            // The record half. Only when the caller asked for the
            // candidate: without --state-out there is nothing to commit
            // and nothing to judge.
            let Some(dest) = flag(args, "--state-out") else {
                return ExitCode::from(code as u8);
            };
            // A box that failed did not produce a state worth judging,
            // and reading one would invite committing a half-apply that
            // nobody looked at.
            if code != 0 {
                eprintln!(
                    "note: the box exited {code}, so no state was extracted. \
                     Nothing was written to {dest}."
                );
                return ExitCode::from(code as u8);
            }
            let plan_src = plan_src.expect("--state-out resolved a plan above");
            match commit_state(&spec, &guest_state, prior_src.as_deref(), &plan_src, dest) {
                Ok(c) => ExitCode::from(c),
                Err(c) => ExitCode::from(c),
            }
        }
        Err(e) => {
            eprintln!("apply: could not run `{}`: {e}", spec.lex_os);
            eprintln!("       Is lex-os on PATH? Override with --lex-os <path>.");
            ExitCode::from(2)
        }
    }
}

/// Take the candidate state out of the box and decide whether it may
/// become the record.
///
/// Separate from `cmd_apply` because it is a decision, not plumbing: the
/// same comparison `lex-iac state commit` makes, run without the
/// operator having to mount an image by hand.
fn commit_state(
    spec: &lex_iac::BoxSpec,
    guest_state: &str,
    prior_src: Option<&str>,
    plan_src: &str,
    dest: &str,
) -> Result<u8, u8> {
    let candidate_src = match lex_iac::guestfs::read_file(&spec.rootfs, guest_state) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not read the candidate state out of the box: {e}");
            return Err(2);
        }
    };

    // No prior state means the box started from nothing, which is a real
    // first apply rather than a missing input — the honest prior is an
    // empty state, and terraform would have started from one too.
    const EMPTY: &str = r#"{"version":4,"resources":[]}"#;
    let parse = |what: &str, src: &str| match lex_iac::state::State::from_json(src) {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!("{what} state: {e}");
            Err(2u8)
        }
    };
    let prior = parse("prior", prior_src.unwrap_or(EMPTY))?;
    let candidate = parse("candidate", &candidate_src)?;
    let plan = match lex_iac::plan::Plan::from_json(plan_src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return Err(2);
        }
    };

    let changes = lex_iac::state::diff(&prior, &candidate);
    println!();
    match lex_iac::state::admits(&plan, &prior, &candidate) {
        Err(refusals) => {
            println!(
                "REFUSED — {} state change(s) the plan did not declare:",
                refusals.len()
            );
            for r in &refusals {
                println!("  {} — {}", r.address, r.reason);
            }
            println!(
                "\nThe box applied, but its record was not committed. Nothing was \
                 written to {dest}: a state the plan does not account for is the \
                 input to every plan after it."
            );
            Err(8)
        }
        Ok(()) => {
            if let Err(e) = std::fs::write(dest, &candidate_src) {
                eprintln!("the state was admitted, but writing `{dest}` failed: {e}");
                return Err(2);
            }
            println!(
                "COMMITTED — {} state change(s), each declared by the plan.",
                changes.len()
            );
            for (addr, c) in &changes {
                println!("  {addr} — {}", c.as_str());
            }
            println!("\nWritten to {dest}.");
            Ok(0)
        }
    }
}

/// `lex-iac state commit` — may this candidate state become the record?
///
/// The wall that sits upstream of every other one here: a plan is a
/// function of configuration *and state*, so a box that can write state
/// decides what every future plan says. The verdict is checkable because
/// the gate already read the plan as `(address, verb)` pairs.
/// Write a secret to `path`, readable only by this user.
///
/// The mode is set at creation rather than after, so there is no window
/// in which the file exists and is world-readable.
#[cfg(unix)]
fn write_secret(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body.as_bytes())
}

#[cfg(not(unix))]
fn write_secret(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    std::fs::write(path, body)
}

fn cmd_state_commit(args: &[&str]) -> ExitCode {
    let (Some(plan_path), Some(prior_path), Some(candidate_path)) = (
        flag(args, "--plan"),
        flag(args, "--prior"),
        flag(args, "--candidate"),
    ) else {
        eprintln!("state commit needs --plan, --prior and --candidate\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let json_out = args.contains(&"--json");

    // Reading failures are exit 2, never 8: "I could not tell" must not
    // be recorded as "I refused", or an operator debugging a typo would
    // read it as an attack.
    let read = |what: &str, path: &str| -> Result<String, ExitCode> {
        std::fs::read_to_string(path).map_err(|e| {
            eprintln!("cannot read {what} `{path}`: {e}");
            ExitCode::from(2)
        })
    };

    let plan_src = match read("plan", plan_path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let prior_src = match read("prior state", prior_path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let candidate_src = match read("candidate state", candidate_path) {
        Ok(s) => s,
        Err(c) => return c,
    };

    let plan = match lex_iac::plan::Plan::from_json(&plan_src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let prior = match lex_iac::state::State::from_json(&prior_src) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("prior state: {e}");
            return ExitCode::from(2);
        }
    };
    let candidate = match lex_iac::state::State::from_json(&candidate_src) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("candidate state: {e}");
            return ExitCode::from(2);
        }
    };

    let changes = lex_iac::state::diff(&prior, &candidate);
    match lex_iac::state::admits(&plan, &prior, &candidate) {
        Err(refusals) => {
            if json_out {
                println!(
                    "{}",
                    serde_json::json!({
                        "verdict": "refused",
                        "changed": changes.len(),
                        "refusals": refusals,
                    })
                );
            } else {
                println!(
                    "REFUSED — {} state change(s) the plan did not declare:",
                    refusals.len()
                );
                for r in &refusals {
                    println!("  {} — {}", r.address, r.reason);
                }
                println!(
                    "\nThe candidate was NOT committed. A state the plan does not account \
                     for is the input to every plan after it."
                );
            }
            ExitCode::from(8)
        }
        Ok(()) => {
            // Commit only after the verdict, and only when asked. For a
            // remote backend the caller owns the write and reads the
            // exit code; there is no backend integration to get wrong.
            if let Some(dest) = flag(args, "--commit-to") {
                if let Err(e) = std::fs::write(dest, &candidate_src) {
                    eprintln!("verdict was allow, but writing `{dest}` failed: {e}");
                    return ExitCode::from(2);
                }
            }
            if json_out {
                println!(
                    "{}",
                    serde_json::json!({
                        "verdict": "allowed",
                        "changed": changes.len(),
                        "committed_to": flag(args, "--commit-to"),
                    })
                );
            } else {
                println!(
                    "ALLOWED — {} state change(s), each declared by the plan.",
                    changes.len()
                );
                for (addr, c) in &changes {
                    println!("  {addr} — {}", c.as_str());
                }
                match flag(args, "--commit-to") {
                    Some(dest) => println!("\nCommitted to {dest}."),
                    None => println!(
                        "\nNot committed: no --commit-to. The verdict is the output; \
                         write the candidate where your backend keeps it."
                    ),
                }
            }
            ExitCode::from(0)
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
