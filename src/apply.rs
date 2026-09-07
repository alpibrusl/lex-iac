//! In-box apply: run `terraform apply` inside a lex-os microVM
//! (milestone 6 of #1).
//!
//! # Why the gate is not enough on its own
//!
//! Caution 1 in the README: *the gate is exactly as safe as the plan is
//! honest*. A provider that mutates outside its declared plan — some do,
//! on drift — is invisible to a document reader. Bounding that needs the
//! apply to happen somewhere the provider's reach is enforced rather
//! than described, which is what lex-os's perimeter is for.
//!
//! # One manifest, two enforcement points
//!
//! The grant this gate checks a plan against is a
//! `lex_os_manifest::Manifest`, which is exactly what `lex-os exec`
//! takes. So the **same file** is passed to both: the egress the gate
//! reasoned about is the egress the box is confined to, and there is no
//! second declaration that could drift from the first. That is the
//! project's invariant, and here it costs nothing to keep.
//!
//! A consequence worth stating: a grant with `exec: None` cannot apply.
//! Applying *is* executing, and a grant that never said so does not
//! authorise it. lex-os's supervisor refuses it at the perimeter
//! regardless; [`permits_apply`] refuses earlier so the operator gets a
//! sentence instead of a booted VM and a denial.
//!
//! # What this does not do
//!
//! It does not put credentials in the box, and no provider here needs
//! any. Whether cloud credentials should live inside the box or behind a
//! host-side proxy is a real decision with real blast radius, and it is
//! not one a plumbing layer should make by defaulting.

use std::path::{Path, PathBuf};

use lex_os_manifest::{Level, Manifest};

/// Where the box comes from and what it runs.
#[derive(Debug, Clone)]
pub struct BoxSpec {
    /// The guest filesystem carrying terraform and the planned working
    /// directory (see `demo/build-box.sh`).
    pub rootfs: PathBuf,
    /// Optional guest kernel. The demo's 4.14 image has no virtio-rng,
    /// and terraform blocks on `getrandom(2)` without it — see
    /// alpibrusl/lex-os#82.
    pub kernel: Option<PathBuf>,
    /// The terraform working directory *inside* the guest.
    pub work_dir: String,
    /// The planned document inside that directory. A plan file, not a
    /// config: the box applies what was already planned and gated, so
    /// it cannot re-plan into something else.
    pub tfplan: String,
    pub lex_os: String,
    pub jail_uid: Option<u32>,
    pub jail_gid: Option<u32>,
}

impl Default for BoxSpec {
    fn default() -> Self {
        Self {
            rootfs: PathBuf::from("demo/assets/box.ext4"),
            kernel: None,
            work_dir: "/work".into(),
            tfplan: "tfplan".into(),
            lex_os: "lex-os".into(),
            jail_uid: None,
            jail_gid: None,
        }
    }
}

/// Does this grant authorise running anything at all?
///
/// Applying is executing. A grant that names infrastructure verbs but
/// leaves `exec` at `None` has authorised a *decision*, not an action —
/// which is a coherent thing to want, and the reason `check` and `apply`
/// are separate verbs.
pub fn permits_apply(manifest: &Manifest) -> Result<(), String> {
    if manifest.grant.exec == Level::None {
        return Err(
            "this grant sets `exec: None`, so it does not authorise running anything — \
             including terraform. A grant may gate a plan without permitting its apply; \
             raise `exec` if applying is genuinely intended."
                .into(),
        );
    }
    Ok(())
}

/// Resolve a path the box will be booted from to an absolute one.
///
/// lex-os's default asset paths are relative to **its own** checkout, and
/// the jailer chroots before opening them — so a relative path handed
/// across the process boundary resolves against a directory this caller
/// does not control, and surfaces as `No such file or directory` from
/// deep inside provisioning, after a tap and a jail have been made and
/// unmade. Canonicalising here turns that into a sentence naming the
/// file, before anything boots.
pub fn resolve_box_path(what: &str, p: &Path) -> Result<PathBuf, String> {
    p.canonicalize()
        .map_err(|e| format!("--box-{what} {}: {e}", p.display()))
}

/// The exact `lex-os exec` invocation, as argv.
///
/// Built as data rather than a shell string so it can be asserted in a
/// test on a machine with no KVM — which is every machine this repo's CI
/// runs on. The one place this could go wrong unnoticed is the boundary
/// between the two tools, so that boundary is what the test pins.
pub fn apply_argv(spec: &BoxSpec, manifest: &str, audit_out: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = vec![
        spec.lex_os.clone(),
        "exec".into(),
        "--manifest".into(),
        // The gate's own grant, unchanged. Not a manifest derived from
        // it, not a subset — the same document, so the box cannot be
        // confined to something the gate did not reason about.
        manifest.into(),
        "--rootfs".into(),
        spec.rootfs.display().to_string(),
    ];
    if let Some(k) = &spec.kernel {
        v.push("--kernel".into());
        v.push(k.display().to_string());
    }
    if let Some(p) = audit_out {
        v.push("--audit-out".into());
        v.push(p.into());
    }
    if let Some(uid) = spec.jail_uid {
        v.push("--jail-uid".into());
        v.push(uid.to_string());
    }
    if let Some(gid) = spec.jail_gid {
        v.push("--jail-gid".into());
        v.push(gid.to_string());
    }
    // `--` then the command. `-chdir` rather than a shell, so there is
    // no quoting layer between this argv and the process that runs.
    v.push("--".into());
    v.extend([
        "/usr/bin/terraform".to_string(),
        format!("-chdir={}", spec.work_dir),
        "apply".into(),
        "-input=false".into(),
        "-auto-approve".into(),
        spec.tfplan.clone(),
    ]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Budget, Goal, Grant};

    fn manifest_with(exec: Level) -> Manifest {
        Manifest::new(
            Goal::new("apply"),
            Grant::new(Level::Full, Level::Allowlist, exec),
            Budget::research_default(),
        )
    }

    /// A path the caller gave must reach the box as an absolute one, or
    /// it resolves against lex-os's cwd rather than this one. Found the
    /// hard way: `--box-rootfs demo/assets/box.ext4` run from lex-iac's
    /// directory died as `No such file or directory (os error 2)` inside
    /// provisioning, naming nothing.
    #[test]
    fn a_relative_box_path_is_resolved_before_it_crosses_the_boundary() {
        let here = resolve_box_path("rootfs", Path::new(".")).expect("cwd resolves");
        assert!(here.is_absolute(), "{here:?}");
    }

    /// And a path that is not there is a sentence, not a boot failure.
    #[test]
    fn a_missing_box_path_names_itself() {
        let err = resolve_box_path("rootfs", Path::new("/nope/box.ext4")).unwrap_err();
        assert!(err.contains("--box-rootfs"), "{err}");
        assert!(err.contains("/nope/box.ext4"), "{err}");
    }

    /// A grant may authorise a *decision* without authorising the
    /// action. `check` and `apply` are separate verbs precisely so that
    /// is expressible.
    #[test]
    fn a_grant_that_permits_no_exec_cannot_apply() {
        let err = permits_apply(&manifest_with(Level::None)).unwrap_err();
        assert!(err.contains("exec"), "{err}");
        // ...and one that does is allowed. Without this the check could
        // be refusing everything.
        permits_apply(&manifest_with(Level::Sandboxed)).expect("sandboxed exec");
        permits_apply(&manifest_with(Level::Full)).expect("full exec");
    }

    /// The box is confined by **the gate's own manifest**, byte for
    /// byte. A derived or filtered manifest could be narrower or wider
    /// than what the gate reasoned about, and either way the two
    /// enforcement points would no longer be talking about the same
    /// grant.
    #[test]
    fn the_box_is_confined_by_the_manifest_the_gate_checked() {
        let argv = apply_argv(&BoxSpec::default(), "payments.json", None);
        let i = argv
            .iter()
            .position(|a| a == "--manifest")
            .expect("--manifest");
        assert_eq!(argv[i + 1], "payments.json");
    }

    /// A plan **file**, not a config directory. The box applies what was
    /// already planned and gated; re-planning inside would let it act on
    /// a document nobody checked.
    #[test]
    fn the_box_applies_a_planned_document_and_cannot_replan() {
        let argv = apply_argv(&BoxSpec::default(), "m.json", None);
        let cmd = &argv[argv.iter().position(|a| a == "--").expect("--") + 1..];
        assert_eq!(cmd[0], "/usr/bin/terraform");
        assert!(cmd.contains(&"apply".to_string()));
        assert!(cmd.contains(&"tfplan".to_string()));
        assert!(
            !cmd.contains(&"plan".to_string()),
            "must not re-plan in the box"
        );
        assert!(
            !cmd.contains(&"init".to_string()),
            "must not init in the box: that fetches provider code from a registry"
        );
        // Non-interactive, or the box hangs on a prompt nobody can answer.
        assert!(cmd.contains(&"-input=false".to_string()));
        assert!(cmd.contains(&"-auto-approve".to_string()));
    }

    #[test]
    fn optional_parts_are_omitted_rather_than_defaulted() {
        let argv = apply_argv(&BoxSpec::default(), "m.json", None);
        for absent in ["--kernel", "--audit-out", "--jail-uid", "--jail-gid"] {
            assert!(
                !argv.contains(&absent.to_string()),
                "{absent} should be absent"
            );
        }
        let spec = BoxSpec {
            kernel: Some(PathBuf::from("vmlinux-6.1")),
            jail_uid: Some(1000),
            jail_gid: Some(108),
            ..BoxSpec::default()
        };
        let argv = apply_argv(&spec, "m.json", Some("audit.json"));
        for present in ["--kernel", "--audit-out", "--jail-uid", "--jail-gid"] {
            assert!(
                argv.contains(&present.to_string()),
                "{present} should be present"
            );
        }
    }

    /// Everything after `--` is the guest command; nothing before it is.
    /// A flag that leaked past the separator would be read by terraform.
    #[test]
    fn the_separator_divides_the_two_tools_cleanly() {
        let spec = BoxSpec {
            kernel: Some(PathBuf::from("k")),
            ..BoxSpec::default()
        };
        let argv = apply_argv(&spec, "m.json", Some("a.json"));
        let sep = argv.iter().position(|a| a == "--").expect("--");
        assert!(argv[..sep].iter().all(|a| a != "/usr/bin/terraform"));
        assert!(argv[sep + 1..].iter().all(|a| !a.starts_with("--manifest")));
    }
}
