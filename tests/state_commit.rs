//! The `state commit` wall, exercised through the binary an operator
//! actually runs.
//!
//! The library tests in `src/state.rs` pin the comparison. These pin the
//! things only the command can get wrong, and each of them is a way the
//! wall could be present and useless:
//!
//! - a refusal that still writes the backend,
//! - "I could not read this" reported as "I refused this",
//! - an exit code that says allow while the text says refuse.
//!
//! The last one matters because the caller acts on the exit code: for a
//! remote backend, exit 0 *is* the instruction to commit.

use std::path::{Path, PathBuf};
use std::process::Command;

fn tmp(case: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lex-iac-state-{case}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

fn write(dir: &Path, name: &str, body: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write fixture");
    p.to_string_lossy().into_owned()
}

/// A plan that declares exactly one update.
const PLAN: &str = r#"{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {"address":"local_file.greeting","type":"local_file","name":"greeting",
     "mode":"managed","provider_name":"registry.terraform.io/hashicorp/local",
     "change":{"actions":["update"]}}
  ]
}"#;

fn state(content: &str, extra: &str) -> String {
    format!(
        r#"{{"version":4,"terraform_version":"1.9.0","serial":1,"lineage":"l",
             "resources":[
               {{"mode":"managed","type":"local_file","name":"greeting",
                "instances":[{{"schema_version":0,
                  "attributes":{{"content":"{content}","filename":"./out.txt"}}}}]}}{extra}]}}"#
    )
}

/// A second resource, well-formed and internally consistent, that the
/// plan says nothing about.
const UNPLANNED: &str = r#",
  {"mode":"managed","type":"aws_iam_user","name":"backdoor",
   "instances":[{"schema_version":0,
     "attributes":{"name":"backdoor","arn":"arn:aws:iam::1:user/backdoor"}}]}"#;

struct Run {
    code: i32,
    stdout: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_lex-iac"))
        .args(args)
        .output()
        .expect("running lex-iac");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

#[test]
fn an_apply_that_did_what_the_plan_said_is_allowed() {
    let d = tmp("allow");
    let r = run(&[
        "state",
        "commit",
        "--plan",
        &write(&d, "plan.json", PLAN),
        "--prior",
        &write(&d, "prior.tfstate", &state("hello", "")),
        "--candidate",
        &write(&d, "cand.tfstate", &state("goodbye", "")),
    ]);
    assert_eq!(r.code, 0, "expected allow, got:\n{}", r.stdout);
    assert!(r.stdout.contains("ALLOWED"), "{}", r.stdout);
}

/// The decisive case. The candidate is well-formed and parses; it
/// differs only in recording one resource the plan never mentions. It
/// must be refused for that reason, and the exit code must say so.
#[test]
fn a_state_carrying_an_unplanned_resource_is_refused() {
    let d = tmp("refuse");
    let r = run(&[
        "state",
        "commit",
        "--plan",
        &write(&d, "plan.json", PLAN),
        "--prior",
        &write(&d, "prior.tfstate", &state("hello", "")),
        "--candidate",
        &write(&d, "cand.tfstate", &state("goodbye", UNPLANNED)),
    ]);
    assert_eq!(r.code, 8, "a refusal must exit 8, got:\n{}", r.stdout);
    assert!(r.stdout.contains("REFUSED"), "{}", r.stdout);
    assert!(
        r.stdout.contains("aws_iam_user.backdoor"),
        "the refusal must name what it refused: {}",
        r.stdout
    );
}

/// The property that makes the wall a wall rather than a report.
#[test]
fn a_refusal_does_not_write_the_backend() {
    let d = tmp("nowrite");
    let backend = d.join("backend.tfstate");
    let r = run(&[
        "state",
        "commit",
        "--plan",
        &write(&d, "plan.json", PLAN),
        "--prior",
        &write(&d, "prior.tfstate", &state("hello", "")),
        "--candidate",
        &write(&d, "cand.tfstate", &state("goodbye", UNPLANNED)),
        "--commit-to",
        &backend.to_string_lossy(),
    ]);
    assert_eq!(r.code, 8);
    assert!(
        !backend.exists(),
        "the backend was written despite a refusal — the wall would be decorative"
    );
}

#[test]
fn an_allowed_commit_writes_the_candidate_verbatim() {
    let d = tmp("write");
    let backend = d.join("backend.tfstate");
    let candidate = state("goodbye", "");
    let r = run(&[
        "state",
        "commit",
        "--plan",
        &write(&d, "plan.json", PLAN),
        "--prior",
        &write(&d, "prior.tfstate", &state("hello", "")),
        "--candidate",
        &write(&d, "cand.tfstate", &candidate),
        "--commit-to",
        &backend.to_string_lossy(),
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let written = std::fs::read_to_string(&backend).expect("backend written");
    assert_eq!(written, candidate, "committed bytes must be the candidate");
}

/// "I could not read this" is not "I refused this". An operator who
/// mistypes a path must not be told the box attacked them, and a
/// monitoring rule keyed on exit 8 must not fire on a typo.
#[test]
fn an_unreadable_input_is_could_not_run_not_refused() {
    let d = tmp("unreadable");
    let r = run(&[
        "state",
        "commit",
        "--plan",
        &write(&d, "plan.json", PLAN),
        "--prior",
        &d.join("absent.tfstate").to_string_lossy(),
        "--candidate",
        &write(&d, "cand.tfstate", &state("goodbye", "")),
    ]);
    assert_eq!(r.code, 2, "a missing file is exit 2, not 8");
}

/// The same distinction one level in: a document that is valid JSON but
/// is not a state must be exit 2. The decisive refusal test above is
/// only meaningful if malformed input lands somewhere else — otherwise
/// it could be passing for the wrong reason.
#[test]
fn a_document_that_is_not_a_state_is_could_not_run_not_refused() {
    let d = tmp("notastate");
    let r = run(&[
        "state",
        "commit",
        "--plan",
        &write(&d, "plan.json", PLAN),
        "--prior",
        &write(&d, "prior.tfstate", &state("hello", "")),
        "--candidate",
        &write(
            &d,
            "cand.tfstate",
            r#"{"version":4,"terraform_version":"1.9.0"}"#,
        ),
    ]);
    assert_eq!(r.code, 2, "not-a-state is exit 2, not a refusal");
}

#[test]
fn missing_flags_are_reported_rather_than_assumed() {
    let d = tmp("flags");
    let r = run(&["state", "commit", "--plan", &write(&d, "plan.json", PLAN)]);
    assert_eq!(r.code, 2);
}

/// The JSON form has to agree with the exit code, or a caller reading
/// one and acting on the other gets a different answer than the operator
/// reading the text.
#[test]
fn the_json_verdict_agrees_with_the_exit_code() {
    let d = tmp("json");
    let args = |cand: &str| -> Run {
        run(&[
            "state",
            "commit",
            "--json",
            "--plan",
            &write(&d, "plan.json", PLAN),
            "--prior",
            &write(&d, "prior.tfstate", &state("hello", "")),
            "--candidate",
            &write(&d, "cand.tfstate", cand),
        ])
    };

    let allowed = args(&state("goodbye", ""));
    assert_eq!(allowed.code, 0);
    assert!(
        allowed.stdout.contains("\"verdict\":\"allowed\""),
        "{}",
        allowed.stdout
    );

    let refused = args(&state("goodbye", UNPLANNED));
    assert_eq!(refused.code, 8);
    assert!(
        refused.stdout.contains("\"verdict\":\"refused\""),
        "{}",
        refused.stdout
    );
}
