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
use serde::{Deserialize, Serialize};

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

/// Derive a plan's JSON from the saved binary plan, and hash the binary.
///
/// # Why this exists
///
/// `check` used to take `--plan plan.json` and `apply` used to run
/// `terraform apply tfplan`, and nothing connected the two. The gate
/// hashed the JSON it was handed — `CompiledPlan::plan_sha256`, whose
/// own comment says "an acceptance is only ever an acceptance of *these*
/// bytes" — while terraform applied a different file that no one had
/// looked at. Handing the same directory to both processes does not fix
/// it: two files can disagree, and hashing two unrelated files proves
/// nothing about either.
///
/// The fix is not to check harder. It is to stop having two artifacts.
/// Given the binary plan, this runs terraform's own `show -json` to
/// produce the document the gate reasons about, so the JSON *is* a view
/// of the bytes that will be applied rather than a claim about them, and
/// returns the artifact's digest so a later apply can prove it is still
/// holding the same file.
/// # What it needs
///
/// `terraform show -json` reads the plan through the provider plugins,
/// so this must run where `terraform init` has been done -- the plan
/// file alone is not enough, and a plan copied somewhere else fails
/// with "Failed to load plugin schemas". That is terraform's constraint,
/// not one added here, and it is the reason `--plan <json>` remains
/// supported for callers that derive the JSON in the working directory
/// and gate it elsewhere. Those callers get `artifact: unbound` and no
/// approval, which is the honest description of what they have.
pub fn derive_plan_json(tfplan: &Path) -> Result<(String, String), String> {
    let bytes = std::fs::read(tfplan)
        .map_err(|e| format!("cannot read the saved plan {}: {e}", tfplan.display()))?;
    let digest = crate::sha256_bytes(&bytes);

    let dir = tfplan.parent().filter(|p| !p.as_os_str().is_empty());
    let file = tfplan
        .file_name()
        .ok_or_else(|| format!("{} is not a file", tfplan.display()))?;

    let mut cmd = std::process::Command::new("terraform");
    if let Some(d) = dir {
        cmd.arg(format!("-chdir={}", d.display()));
    }
    cmd.arg("show").arg("-json").arg(file);

    let out = cmd.output().map_err(|e| {
        format!("could not run terraform to read {}: {e}. `--tfplan` needs terraform on PATH; pass `--plan <json>` instead if it is produced elsewhere", tfplan.display())
    })?;
    if !out.status.success() {
        return Err(format!(
            "terraform could not read {} as a saved plan: {}",
            tfplan.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok((String::from_utf8_lossy(&out.stdout).into_owned(), digest))
}

/// Refuse when the artifact on disk is not the one that was approved.
///
/// The decision names a digest; this is the check that the file still
/// hashes to it. Without it "the approved plan" is a phrase in a log
/// rather than a fact about the bytes terraform is about to read.
pub fn artifact_matches(approved: &str, tfplan: &Path) -> Result<(), String> {
    let bytes = std::fs::read(tfplan)
        .map_err(|e| format!("cannot read the saved plan {}: {e}", tfplan.display()))?;
    let found = crate::sha256_bytes(&bytes);
    if found == approved {
        return Ok(());
    }
    Err(format!(
        "the plan being applied is not the plan that was approved.\n  \
         approved: sha256:{approved}\n  \
         on disk:  sha256:{found}\n  \
         at:       {}",
        tfplan.display()
    ))
}

/// What an acceptance is an acceptance *of*.
///
/// The gap this closes: a decision made now and an apply run later were
/// connected by nothing but a filename. `check` hashed the JSON it read
/// and `apply` ran `terraform apply tfplan`, and between the two anyone
/// could have replaced the file. Verifying inside a single process run
/// proves nothing either — hashing a file and then hashing the same
/// file again is circular, which is what a first attempt at this did.
///
/// So the acceptance is written down, naming the artifact's digest, and
/// the later apply is held to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Present so a reader cannot mistake a refusal for permission.
    pub verdict: String,
    /// The saved binary plan terraform will apply. The load-bearing field.
    pub tfplan_sha256: String,
    /// The JSON derived from it, which is what the gate reasoned over.
    pub plan_sha256: String,
    /// The mandate it was judged against; a different grant is a
    /// different decision even over identical bytes.
    pub manifest_sha256: String,
    pub goal: String,
}

impl Approval {
    /// Hold an artifact and a mandate to what was accepted.
    pub fn admits(&self, tfplan: &Path, manifest_src: &str) -> Result<(), String> {
        if self.verdict != "accepted" {
            return Err(format!(
                "this approval records `{}`, not an acceptance",
                self.verdict
            ));
        }
        artifact_matches(&self.tfplan_sha256, tfplan)?;
        let found = crate::sha256_hex(manifest_src);
        if found != self.manifest_sha256 {
            return Err(format!(
                "the grant is not the one this plan was approved against.\n  \
                 approved against: sha256:{}\n  \
                 supplied:         sha256:{found}",
                self.manifest_sha256
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, bytes: &[u8]) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("lex-iac-approval-{}-{name}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    fn approval_for(tfplan: &Path, manifest_src: &str) -> Approval {
        Approval {
            verdict: "accepted".into(),
            tfplan_sha256: crate::sha256_bytes(&std::fs::read(tfplan).unwrap()),
            plan_sha256: "irrelevant-here".into(),
            manifest_sha256: crate::sha256_hex(manifest_src),
            goal: "rotate the payments API deployment".into(),
        }
    }

    #[test]
    fn the_approved_artifact_is_admitted() {
        let plan = tmp("ok.tfplan", b"\x00binary plan A");
        let grant = r#"{"goal":"x"}"#;
        approval_for(&plan, grant)
            .admits(&plan, grant)
            .expect("same bytes, same grant");
    }

    /// The case the binding exists for, and the one a re-check cannot
    /// catch: both plans are individually acceptable, so nothing about
    /// plan B's *content* is wrong. It simply is not what was approved.
    #[test]
    fn a_different_but_equally_valid_plan_is_refused() {
        let grant = r#"{"goal":"x"}"#;
        let approved = tmp("a.tfplan", b"\x00binary plan A");
        let swapped = tmp("b.tfplan", b"\x00binary plan B");
        let err = approval_for(&approved, grant)
            .admits(&swapped, grant)
            .expect_err("a substituted artifact must not inherit the acceptance");
        assert!(err.contains("not the plan that was approved"), "{err}");
        assert!(
            err.contains("approved: sha256:"),
            "the operator needs both digests: {err}"
        );
        assert!(err.contains("on disk:  sha256:"), "{err}");
    }

    /// A single flipped byte is a different plan. Terraform would apply
    /// it happily; the digest is the only thing that notices.
    #[test]
    fn one_changed_byte_is_a_different_artifact() {
        let grant = r#"{"goal":"x"}"#;
        let approved = tmp("c.tfplan", b"\x00binary plan A");
        let edited = tmp("d.tfplan", b"\x00binary plan B_");
        assert!(approval_for(&approved, grant)
            .admits(&edited, grant)
            .is_err());
    }

    /// Same bytes, different mandate. The artifact is not the whole
    /// decision: an acceptance was granted *against* a grant, and
    /// swapping the grant is as much a substitution as swapping the plan.
    #[test]
    fn the_same_plan_under_a_different_grant_is_refused() {
        let plan = tmp("e.tfplan", b"\x00binary plan A");
        let err = approval_for(&plan, r#"{"goal":"narrow"}"#)
            .admits(&plan, r#"{"goal":"wide"}"#)
            .expect_err("a different grant is a different decision");
        assert!(
            err.contains("not the one this plan was approved against"),
            "{err}"
        );
    }

    /// A refusal must never be usable as permission, however it is
    /// spelled in the file.
    #[test]
    fn a_recorded_refusal_does_not_admit_anything() {
        let plan = tmp("f.tfplan", b"\x00binary plan A");
        let grant = r#"{"goal":"x"}"#;
        let mut a = approval_for(&plan, grant);
        a.verdict = "refused".into();
        let err = a
            .admits(&plan, grant)
            .expect_err("a refusal is not an approval");
        assert!(err.contains("not an acceptance"), "{err}");
    }

    #[test]
    fn a_missing_artifact_is_an_error_not_a_pass() {
        let grant = r#"{"goal":"x"}"#;
        let plan = tmp("g.tfplan", b"\x00binary plan A");
        let approval = approval_for(&plan, grant);
        std::fs::remove_file(&plan).unwrap();
        assert!(approval.admits(&plan, grant).is_err());
    }
}
