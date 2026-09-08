//! A running ledger of decision heads (#18).
//!
//! Sealing (#14) stops a rewrite. A checkpoint (#21) stops a truncation
//! *within* a decision's chain. Neither can say a decision that happened
//! still exists, because each `check` writes its own chain to its own
//! file and nothing counts the files. `rm audit.json` is the easiest
//! thing anyone with the directory can do, and it was the one thing no
//! wall here touched.
//!
//! A ledger is one long-lived chain, appended to after every decision,
//! carrying just enough to prove the decision happened: its subject, its
//! verdict, and the head of its own chain. A deleted file becomes a
//! **visible gap** — the ledger names a head with nothing behind it.
//!
//! # It is a witness, not a copy
//!
//! No reasoning, no effect rows, no refusal detail. Those live in the
//! decision chain, which is sealed. Duplicating them would make two
//! records that can disagree, and then a question about which is true.
//! The ledger answers one question — *did this decision happen, and what
//! did it say* — and points at the record that answers the rest.
//!
//! # Why this is not lex-k8s#13 copied across
//!
//! That wall is a long-running process: one ledger, appended under a
//! mutex it had anyway, with a checkpoint printed to stdout that a log
//! collector keeps. `lex-iac check` is a one-shot CLI. There is no
//! process to hold the ledger, no lock to inherit, and no stdout anybody
//! is collecting. So:
//!
//! - the path comes from the caller (`--ledger`), which puts custody
//!   where it belongs rather than inventing a default location;
//! - concurrent runs are serialised with a lock file, because two CI
//!   jobs finishing together would otherwise read the same ledger and
//!   each write their own entry over the other's;
//! - the write is atomic (temp + rename), so a crash mid-append leaves
//!   the previous ledger rather than half of the next one.
//!
//! # What it still does not fix
//!
//! A ledger beside the decisions it witnesses is deleted by the same
//! `rm -rf`. It converts *silent* deletion into *detectable* deletion
//! for anyone holding a checkpoint over the ledger, which is what
//! `--checkpoint-out` is for. Custody of that checkpoint — a CI job log,
//! held by the forge rather than the runner, is the natural answer here
//! — is a deployment decision this crate cannot make.

use std::path::{Path, PathBuf};

use lex_os_audit::{Chain, ChainPayload, SigningKey};
use serde::{Deserialize, Serialize};

/// One decision, witnessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerEvent {
    /// The ledger was opened, and with which sealing identity.
    ///
    /// First in every ledger, so a reader can tell a fresh one from a
    /// truncated one: a ledger that does not begin here has lost its
    /// head, whatever its hashes say.
    LedgerOpened {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
    },
    /// A plan was gated, and the chain that records it.
    PlanDecided {
        /// The manifest's goal — what a reader recognises the run by.
        subject: String,
        /// `accepted` or `refused`.
        verdict: String,
        /// The head of that decision's own chain. The handle that makes
        /// a missing file detectable.
        decision_head: String,
        decision_entries: u64,
        /// The plan JSON the verdict was reached over.
        plan_sha256: String,
        /// The saved binary plan, when the decision was bound to one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tfplan_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
    },
}

impl ChainPayload for LedgerEvent {
    /// Distinct from `lex.iac.audit.v1`, so a decision entry can never
    /// be replayed as a ledger entry or the reverse. The domain is
    /// hashed into every entry, which makes that structural rather than
    /// a naming convention.
    const DOMAIN: &'static [u8] = b"lex.iac.ledger.v1";
}

/// The ledger: a chain of [`LedgerEvent`].
pub type Ledger = Chain<LedgerEvent>;

/// Append one witness to the ledger at `path`, creating it if absent.
///
/// Serialised against other runs with a lock file and written
/// atomically. Returns the ledger's new head.
pub fn witness(
    path: &Path,
    event: LedgerEvent,
    key: Option<&SigningKey>,
) -> Result<String, String> {
    let _guard = LockFile::acquire(path)?;

    let mut ledger: Ledger = match std::fs::read_to_string(path) {
        Ok(src) => Chain::from_json(&src)
            .map_err(|e| format!("the ledger at {} is not readable: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut fresh = match key {
                Some(k) => Ledger::default().sealed_with(k.clone()),
                None => Ledger::default(),
            };
            fresh.append(LedgerEvent::LedgerOpened {
                signer: key.map(|k| hex::encode(k.verifying_key().to_bytes())),
            });
            fresh
        }
        Err(e) => return Err(format!("could not read the ledger {}: {e}", path.display())),
    };

    // A ledger read back from disk has no signing key: `Chain` does not
    // serialise one, and could not safely. Put it back before appending,
    // or every entry after the first run would be unsealed and the gap
    // would be invisible until someone tried to verify.
    if let Some(k) = key {
        ledger = ledger.sealed_with(k.clone());
    }

    let head = ledger.append(event);
    let json = ledger
        .to_json()
        .map_err(|e| format!("could not serialise the ledger: {e}"))?;
    write_atomically(path, &json)?;
    Ok(head)
}

/// Write via a sibling temp file and rename.
///
/// `std::fs::write` truncates first, so a crash between truncate and
/// write leaves an empty ledger — losing every witness at once, which is
/// the failure this whole file exists to prevent.
fn write_atomically(path: &Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, contents)
        .map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("could not replace the ledger {}: {e}", path.display())
    })
}

/// An exclusive lock held for the read-modify-write.
///
/// `O_EXCL` rather than an advisory lock so it needs no dependency and
/// works the same on every filesystem this runs on. A stale lock from a
/// killed process is the known cost; it names itself in the error so an
/// operator can see what to remove.
struct LockFile(PathBuf);

impl LockFile {
    fn acquire(target: &Path) -> Result<Self, String> {
        let lock = target.with_extension("lock");
        for attempt in 0..50 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock)
            {
                Ok(_) => return Ok(LockFile(lock)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt == 49 {
                        return Err(format!(
                            "another run is holding {} — if nothing else is running, \
                             a previous one was killed and the file can be removed",
                            lock.display()
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(format!("could not take {}: {e}", lock.display())),
            }
        }
        unreachable!("the loop returns on its last attempt")
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// What a reconciliation found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Witnessed heads with no decision file behind them: deletions.
    pub missing: Vec<String>,
    /// Decision files no witness names: plants, or a ledger that lost
    /// its tail. Both are worth knowing and neither is provable from
    /// the other side alone, which is why this is checked in both
    /// directions.
    pub unwitnessed: Vec<String>,
    pub witnessed: usize,
    pub files: usize,
}

impl Reconciliation {
    pub fn agrees(&self) -> bool {
        self.missing.is_empty() && self.unwitnessed.is_empty()
    }
}

/// Compare a ledger against the decision chains it witnessed.
pub fn reconcile(ledger: &Ledger, decision_heads: &[String]) -> Reconciliation {
    let mut out = Reconciliation {
        files: decision_heads.len(),
        ..Default::default()
    };
    let mut witnessed = Vec::new();
    for entry in ledger.entries() {
        if let LedgerEvent::PlanDecided { decision_head, .. } = &entry.event {
            witnessed.push(decision_head.clone());
        }
    }
    out.witnessed = witnessed.len();
    for head in &witnessed {
        if !decision_heads.contains(head) {
            out.missing.push(head.clone());
        }
    }
    for head in decision_heads {
        if !witnessed.contains(head) {
            out.unwitnessed.push(head.clone());
        }
    }
    out
}
