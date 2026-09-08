//! The ledger (#18): proving a decision that happened still exists.
//!
//! Sealing stops a rewrite. A checkpoint stops a truncation *within* a
//! decision's chain. Neither can speak about a decision whose file is
//! gone, because each `check` writes its own chain and nothing counted
//! the chains — so `rm` was the cheapest attack on this record and the
//! one nothing here touched.

use lex_iac::ledger::{reconcile, witness, Ledger, LedgerEvent};
use lex_iac::{Chain, SigningKey};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("lex-iac-ledger-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn decided(head: &str) -> LedgerEvent {
    LedgerEvent::PlanDecided {
        subject: "rotate the payments API".into(),
        verdict: "refused".into(),
        decision_head: head.into(),
        decision_entries: 3,
        plan_sha256: "aa".into(),
        tfplan_sha256: None,
        signer: None,
    }
}

#[test]
fn a_fresh_ledger_opens_before_it_witnesses() {
    let d = dir("fresh");
    let p = d.join("ledger.json");
    witness(&p, decided("head1"), Some(&key())).unwrap();
    let l: Ledger = Chain::from_json(&std::fs::read_to_string(&p).unwrap()).unwrap();
    assert_eq!(l.len(), 2, "the opening entry, then the witness");
    assert!(matches!(
        l.entries()[0].event,
        LedgerEvent::LedgerOpened { .. }
    ));
}

/// The property. A witness outlives the file it witnessed.
#[test]
fn a_deleted_decision_becomes_a_visible_gap() {
    let d = dir("gap");
    let p = d.join("ledger.json");
    witness(&p, decided("head-kept"), None).unwrap();
    witness(&p, decided("head-deleted"), None).unwrap();
    let l: Ledger = Chain::from_json(&std::fs::read_to_string(&p).unwrap()).unwrap();

    // Only one decision file survives.
    let r = reconcile(&l, &["head-kept".to_string()]);
    assert!(!r.agrees());
    assert_eq!(r.missing, vec!["head-deleted".to_string()]);
    assert!(r.unwitnessed.is_empty());
}

/// The other direction, which the first cannot prove: a file no witness
/// names is either planted or evidence the ledger itself lost its tail.
#[test]
fn a_decision_nobody_witnessed_is_reported_too() {
    let d = dir("plant");
    let p = d.join("ledger.json");
    witness(&p, decided("head-known"), None).unwrap();
    let l: Ledger = Chain::from_json(&std::fs::read_to_string(&p).unwrap()).unwrap();

    let r = reconcile(&l, &["head-known".into(), "head-planted".into()]);
    assert!(!r.agrees());
    assert_eq!(r.unwitnessed, vec!["head-planted".to_string()]);
    assert!(r.missing.is_empty());
}

#[test]
fn an_intact_pair_agrees() {
    let d = dir("agree");
    let p = d.join("ledger.json");
    witness(&p, decided("h1"), None).unwrap();
    witness(&p, decided("h2"), None).unwrap();
    let l: Ledger = Chain::from_json(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let r = reconcile(&l, &["h1".into(), "h2".into()]);
    assert!(r.agrees(), "{r:?}");
    assert_eq!(r.witnessed, 2);
}

/// Every entry is sealed, including ones appended by later runs. A
/// `Chain` read back from disk carries no key — it cannot — so a naive
/// implementation seals the first run's entries and silently leaves
/// every subsequent one unsealed.
#[test]
fn entries_appended_by_a_later_run_are_sealed_too() {
    let d = dir("seals");
    let p = d.join("ledger.json");
    witness(&p, decided("h1"), Some(&key())).unwrap();
    witness(&p, decided("h2"), Some(&key())).unwrap();
    let l: Ledger = Chain::from_json(&std::fs::read_to_string(&p).unwrap()).unwrap();
    l.verify_seals(&[key().verifying_key()])
        .expect("every entry, not just the first run's");
}

/// `check` is a one-shot CLI, so two CI jobs finishing together really
/// do race. Without serialisation each reads the same ledger and writes
/// its own entry over the other's, and the loss is silent.
#[test]
fn concurrent_runs_do_not_lose_witnesses() {
    let d = dir("race");
    let p = d.join("ledger.json");
    let mut handles = Vec::new();
    for i in 0..8 {
        let p = p.clone();
        handles.push(std::thread::spawn(move || {
            witness(&p, decided(&format!("head{i}")), None)
        }));
    }
    for h in handles {
        h.join().unwrap().expect("every append succeeds");
    }
    let l: Ledger = Chain::from_json(&std::fs::read_to_string(&p).unwrap()).unwrap();
    assert_eq!(l.len(), 9, "one opening entry and eight witnesses");
    l.verify().expect("the chain is intact after the race");
}

/// The lock must not survive the run that took it, or the next one
/// blocks forever on a file nobody holds.
#[test]
fn the_lock_is_released() {
    let d = dir("lock");
    let p = d.join("ledger.json");
    witness(&p, decided("h1"), None).unwrap();
    assert!(
        !p.with_extension("lock").exists(),
        "a lock left behind blocks every later run"
    );
}
