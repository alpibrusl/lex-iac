//! Reading and writing single files in the box image, without mounting
//! it.
//!
//! `apply` has to put prior state *into* the guest before it boots, and
//! take the candidate *out* after it halts. lex-os gives the box no host
//! mount while it runs — deliberately, that is the boundary — so the
//! only moments a host can touch the guest filesystem are before and
//! after, on the image file itself.
//!
//! # Why `debugfs` rather than a loop mount
//!
//! `mount -o loop` needs root and a free `/dev/loop`, leaves a mount to
//! clean up if the process dies between the mount and the unmount, and
//! puts the guest's filesystem into the host kernel — which is the one
//! thing this project spends its effort avoiding. `debugfs` is a
//! userspace ext2/3/4 editor from e2fsprogs: no root, no loop device,
//! no kernel involvement, nothing to leak if we crash.
//!
//! e2fsprogs is already a dependency of building the box at all
//! (`demo/build-box.sh` runs `e2fsck` and `resize2fs`), so this adds no
//! new requirement.
//!
//! # The one rule
//!
//! Never touch an image while its box is running. `debugfs -w` writes
//! the block device behind the kernel's back; doing that to a live
//! filesystem corrupts it. Both callers here run strictly before boot or
//! strictly after halt.

use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum GuestFsError {
    #[error(
        "`debugfs` is not on PATH. It ships with e2fsprogs, which building the box \
         already needs — install it (`apt install e2fsprogs`) or drop --state/--state-out"
    )]
    NoDebugfs,
    #[error("could not run debugfs: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("no `{path}` in the box image — {detail}")]
    NotFound { path: String, detail: String },
    #[error("debugfs could not write `{path}` into the image: {detail}")]
    WriteFailed { path: String, detail: String },
    #[error("`{0}` is not valid UTF-8, so it is not a Terraform state file")]
    NotText(String),
    #[error("could not settle the box image before touching it: {detail}")]
    Unsettled { detail: String },
}

/// Replay the journal and settle the filesystem.
///
/// Needed on **both** sides, for reasons that look unrelated and are the
/// same reason: `debugfs` neither reads nor writes through the ext4
/// journal.
///
/// After a write, because `debugfs -w` edits behind the journal's back.
/// Before a read, because a box that halted left its last writes *in*
/// the journal — a raw read returns the filesystem as it was before the
/// box ran, which is not an error anyone would notice. The first attempt
/// at this reported "0 state changes" for an apply that had just created
/// a resource, and looked like a bug in the comparison rather than a
/// stale read.
///
/// Exit 0 is clean, 1 is "errors were fixed"; both are fine, since
/// fixing is the point. Note this means reading an image *modifies* it —
/// unavoidable, since replaying a journal is a write.
fn settle(image: &str) -> Result<(), GuestFsError> {
    match Command::new("e2fsck").args(["-fp", image]).output() {
        Ok(o) if o.status.code().unwrap_or(2) <= 1 => Ok(()),
        Ok(o) => Err(GuestFsError::Unsettled {
            detail: format!(
                "e2fsck exited {}: {}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).trim()
            ),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(GuestFsError::Unsettled {
            detail: "`e2fsck` is not on PATH; it ships with e2fsprogs alongside debugfs, \
                     and without it a staged file can be reverted and a written one \
                     never seen"
                .to_string(),
        }),
        Err(e) => Err(GuestFsError::Spawn(e)),
    }
}

fn debugfs(args: &[&str]) -> Result<std::process::Output, GuestFsError> {
    match Command::new("debugfs").args(args).output() {
        Ok(o) => Ok(o),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(GuestFsError::NoDebugfs),
        Err(e) => Err(GuestFsError::Spawn(e)),
    }
}

/// Read one file out of the image.
///
/// `debugfs` reports a missing file on **stdout** rather than failing, so
/// the absence is detected by looking for its message rather than by an
/// exit code — checking the status alone would return the error text as
/// if it were the file's contents.
pub fn read_file(image: &Path, guest_path: &str) -> Result<String, GuestFsError> {
    // The box's last writes are in the journal, not the filesystem.
    settle(&image.display().to_string())?;
    let out = debugfs(&[
        "-R",
        &format!("cat {guest_path}"),
        &image.display().to_string(),
    ])?;
    let body =
        String::from_utf8(out.stdout).map_err(|_| GuestFsError::NotText(guest_path.into()))?;
    let err = String::from_utf8_lossy(&out.stderr);

    if body.is_empty() && (err.contains("File not found") || err.contains("not found")) {
        return Err(GuestFsError::NotFound {
            path: guest_path.to_string(),
            detail: err.lines().next_back().unwrap_or("").trim().to_string(),
        });
    }
    Ok(body)
}

/// Does this path exist in the image?
pub fn exists(image: &Path, guest_path: &str) -> bool {
    matches!(
        debugfs(&["-R", &format!("stat {guest_path}"), &image.display().to_string()]),
        Ok(o) if o.status.success()
            && !String::from_utf8_lossy(&o.stderr).contains("not found")
    )
}

/// Write `body` to `guest_path` inside the image, replacing anything
/// already there.
///
/// `debugfs`'s `write` refuses to overwrite, so an existing file is
/// removed first. The removal is not checked: on the first run there is
/// nothing to remove, and a failure to remove something that *is* there
/// surfaces as the write failing, which is the error worth reporting.
pub fn write_file(image: &Path, guest_path: &str, body: &str) -> Result<(), GuestFsError> {
    let staged = std::env::temp_dir().join(format!(
        "lex-iac-stage-{}-{}",
        std::process::id(),
        guest_path.rsplit('/').next().unwrap_or("file")
    ));
    std::fs::write(&staged, body)?;

    let img = image.display().to_string();
    let _ = debugfs(&["-w", "-R", &format!("rm {guest_path}"), &img]);

    let out = debugfs(&[
        "-w",
        "-R",
        &format!("write {} {guest_path}", staged.display()),
        &img,
    ]);
    let _ = std::fs::remove_file(&staged);
    let out = out?;

    // Same shape as `read_file`: debugfs reports failure on its output
    // rather than in the exit status, so the status alone would call a
    // failed write a success.
    let err = String::from_utf8_lossy(&out.stderr);
    let msg = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || err.contains("File exists") || !msg.contains("Allocated inode") {
        return Err(GuestFsError::WriteFailed {
            path: guest_path.to_string(),
            detail: err
                .lines()
                .chain(msg.lines())
                .rfind(|l| !l.trim().is_empty() && !l.starts_with("debugfs "))
                .unwrap_or("no detail")
                .trim()
                .to_string(),
        });
    }
    settle(&img)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without debugfs every caller must get the one error that says so,
    /// rather than an io error a reader has to decode.
    #[test]
    fn a_missing_debugfs_is_named() {
        // Only meaningful where debugfs is genuinely absent, which is
        // every non-Linux dev machine.
        if Command::new("debugfs").arg("-V").output().is_ok() {
            return;
        }
        assert!(matches!(
            read_file(Path::new("/nonexistent.ext4"), "/work/x"),
            Err(GuestFsError::NoDebugfs)
        ));
    }
}
