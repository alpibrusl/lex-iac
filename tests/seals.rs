//! Sealed decision logs (alpibrusl/lex-os#54, this repo's half).
//!
//! The chain is tamper-*evident* only against someone who cannot
//! recompute it. Its hashes are derived from the contents, so whoever
//! can reach `--audit-out`'s file can rewrite a refusal into an
//! acceptance, rebuild every hash, and hand you a log that verifies
//! perfectly. The seal is the part they cannot rebuild.
//!
//! The property under test:
//!
//! > A rewritten verdict passes the chain and fails the seal.
//!
//! # What a seal does not do here
//!
//! It does not make `--signer` true. That flag is a claim typed on a
//! command line; nothing upstream of this gate authenticates who ran
//! `terraform plan`, which is exactly why lex-k8s takes no such flag and
//! reads the API server's `userInfo.username` instead (lex-os#70).
//! Sealing raises the record from *unattributable and editable* to
//! *attributable to this gate and tamper-evident* — a real improvement,
//! and a different claim.

use lex_iac::{check, check_sealed, Chain, Manifest, PlanEvent, SigningKey, Verdict};

fn fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn manifest(name: &str) -> Manifest {
    Manifest::from_json(&fixture(name)).unwrap_or_else(|e| panic!("parsing manifest {name}: {e}"))
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The demo refusal — a plan that reads as three tag edits, hiding a
/// database replacement — decided with every entry sealed.
fn sealed_refusal(k: &SigningKey) -> Chain<PlanEvent> {
    let d = check_sealed(
        &fixture("harmless_tag_change.json"),
        &manifest("grant_with_rds_wildcard.json"),
        None,
        None,
        k,
    )
    .expect("the gate runs");
    assert!(matches!(d.verdict, Verdict::Deny { .. }), "a refusal");
    d.audit
}

#[test]
fn a_sealed_decision_seals_every_entry() {
    let k = key(1);
    let audit = sealed_refusal(&k);
    assert!(audit.len() >= 2, "request plus verdict at least");
    assert_eq!(
        audit.sealed_count(),
        audit.len(),
        "every entry, not most of them — an unsealed entry is where a forged one goes"
    );
    audit.verify().expect("the chain");
    audit.verify_seals(&[k.verifying_key()]).expect("the seals");

    // Negative control: another key must not do, or this would pass on a
    // `verify_seals` that returned Ok unconditionally.
    assert!(audit.verify_seals(&[key(2).verifying_key()]).is_err());
}

/// **The attack.** Someone with the log file turns the refusal into an
/// acceptance and rebuilds the chain — which costs nothing, because the
/// hashes are derived. Here the rebuild is done by calling the library
/// itself, which is exactly the tool a forger has.
///
/// The result verifies as a chain. The seals are what refuse it.
#[test]
fn a_rewritten_verdict_passes_the_chain_and_fails_the_seal() {
    let k = key(1);
    let audit = sealed_refusal(&k);

    let raw: Vec<serde_json::Value> =
        serde_json::from_str(&audit.to_json().unwrap()).expect("entries");

    let mut forged: Chain<PlanEvent> = Chain::new();
    for (i, entry) in raw.iter().enumerate() {
        let last = i == raw.len() - 1;
        let event: PlanEvent = if last {
            assert_eq!(entry["event"]["kind"], "plan_refused");
            serde_json::from_value(serde_json::json!({
                "kind": "plan_accepted",
                "artifact_sha256": entry["event"]["artifact_sha256"].clone(),
                "manifest": entry["event"]["manifest"].clone(),
                "subject": entry["event"]["subject"].clone(),
            }))
            .expect("a plan_accepted event")
        } else {
            serde_json::from_value(entry["event"].clone()).expect("the original event")
        };
        forged.append(event);
    }

    // The seals come along unchanged — the forger has them, they were in
    // the file.
    let mut with_seals: Vec<serde_json::Value> =
        serde_json::from_str(&forged.to_json().unwrap()).expect("entries");
    for (i, entry) in with_seals.iter_mut().enumerate() {
        entry["seal"] = raw[i]["seal"].clone();
    }
    let forged: Chain<PlanEvent> =
        Chain::from_json(&serde_json::to_string(&with_seals).unwrap()).expect("parses");

    // The load-bearing assertion: the chain is *fine*. Nothing inside it
    // says the refusal ever happened.
    forged
        .verify()
        .expect("a recomputed chain verifies — the hashes are derived, not signed");
    assert!(
        matches!(
            forged.entries().last().unwrap().event,
            PlanEvent::PlanAccepted { .. }
        ),
        "the refusal is gone from the record"
    );
    assert_ne!(forged.head(), audit.head(), "and it is a different history");

    let err = forged
        .verify_seals(&[k.verifying_key()])
        .expect_err("the seals must refuse a rewritten decision");
    assert!(format!("{err}").contains("contents"), "{err}");
}

/// Sealing is opt-in, and an unsealed log is reported as unsealed rather
/// than as failing. `check` writes exactly what it always wrote.
#[test]
fn an_unsealed_decision_is_byte_for_byte_what_it_was() {
    let d = check(
        &fixture("harmless_tag_change.json"),
        &manifest("grant_with_rds_wildcard.json"),
        None,
        None,
    )
    .expect("the gate runs");
    assert_eq!(d.audit.sealed_count(), 0);
    d.audit.verify().expect("still a valid chain");
    assert!(!d.audit.to_json().unwrap().contains("seal"));
}

/// Sealing must not change the decision, the verdict, or the hashes — or
/// `lex attest import-apply` would see a different artifact for the same
/// plan, and a submitter's record would fork.
#[test]
fn sealing_changes_nothing_but_the_seal() {
    let plan = fixture("harmless_tag_change.json");
    let m = manifest("grant_with_rds_wildcard.json");
    let plain = check(&plan, &m, None, None).unwrap();
    let sealed = check_sealed(&plan, &m, None, None, &key(1)).unwrap();

    assert_eq!(plain.audit.head(), sealed.audit.head(), "same head");
    assert_eq!(plain.audit.len(), sealed.audit.len());
    assert_eq!(
        format!("{:?}", plain.verdict),
        format!("{:?}", sealed.verdict)
    );
}

/// A seal is bound to the entry it covers, not merely to the key — so
/// one lifted from another decision does not transfer.
#[test]
fn a_seal_does_not_transfer_between_decisions() {
    let k = key(1);
    let a = sealed_refusal(&k);
    let b = check_sealed(
        &fixture("harmless_tag_change.json"),
        // A different grant, so a different decision for the same plan.
        &manifest("grant_names_the_replace.json"),
        None,
        None,
        &k,
    )
    .expect("the gate runs")
    .audit;
    assert_ne!(a.head(), b.head(), "different decisions");

    let mut raw_a: Vec<serde_json::Value> =
        serde_json::from_str(&a.to_json().unwrap()).expect("entries");
    let raw_b: Vec<serde_json::Value> =
        serde_json::from_str(&b.to_json().unwrap()).expect("entries");
    raw_a[0]["seal"] = raw_b[0]["seal"].clone();

    let grafted: Chain<PlanEvent> =
        Chain::from_json(&serde_json::to_string(&raw_a).unwrap()).expect("parses");
    assert!(
        grafted.verify_seals(&[k.verifying_key()]).is_err(),
        "a seal covers its entry, not merely the key that made it"
    );
}

/// The two gates' chains carry different domains, so a Kubernetes
/// admission entry can never be replayed into a Terraform gate's log —
/// even though both are `Chain<E>` and both promote through the same
/// `PlanApply` attestation kind (lex-os#70).
#[test]
fn this_gates_domain_is_its_own() {
    use lex_iac::Chain as _Chain;
    use lex_os_audit::ChainPayload;
    let _ = std::marker::PhantomData::<_Chain<PlanEvent>>;
    assert_eq!(PlanEvent::DOMAIN, b"lex.iac.audit.v1");
}

// ── Truncation (#21) ────────────────────────────────────────────────────
//
// The seal and the chain share a blind spot, and it is not a flaw in
// either: a hash chain proves the entries it *contains* are unaltered,
// and a seal proves each entry is genuine. Every entry left after a
// deletion is genuine, and the chain that remains is intact — so a log
// somebody shortened verifies perfectly by both.
//
// The refusal is the last entry written. An operator who would rather
// the record did not show a refused production-database destroy does not
// need to forge anything, or hold any key: they drop one entry off the
// end. Only a statement made while that entry still existed can
// contradict them.

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// Drop the last entry the way an attacker would: by editing the file.
/// Going through JSON rather than an in-memory constructor keeps the
/// test on the path the log actually travels.
fn truncate_tail(chain: &Chain<PlanEvent>) -> Chain<PlanEvent> {
    let json = chain.to_json().expect("serialise");
    let mut entries: Vec<serde_json::Value> =
        serde_json::from_str(&json).expect("array of entries");
    entries.pop().expect("a tail to remove");
    Chain::from_json(&serde_json::to_string(&entries).unwrap()).expect("still well-formed JSON")
}

/// The property the checkpoint exists for.
#[test]
fn a_truncated_log_still_passes_the_chain_and_the_seals() {
    let key = signing_key();
    let d = check_sealed(
        &fixture("rotate_deployment.json"),
        &Manifest::from_json(&fixture("grant_ecs_only.json")).unwrap(),
        None,
        None,
        &key,
    )
    .unwrap();
    assert!(d.audit.len() >= 2, "need a tail to remove");

    let short = truncate_tail(&d.audit);

    // Both of the walls that already existed report clean. This is the
    // finding, not a bug being introduced by the test.
    short
        .verify()
        .expect("a truncated chain is still internally consistent");
    short
        .verify_seals(&[key.verifying_key()])
        .expect("every surviving entry is genuinely sealed");
}

/// ...and the checkpoint is what notices.
#[test]
fn a_checkpoint_refuses_the_truncated_log() {
    let key = signing_key();
    let d = check_sealed(
        &fixture("rotate_deployment.json"),
        &Manifest::from_json(&fixture("grant_ecs_only.json")).unwrap(),
        None,
        None,
        &key,
    )
    .unwrap();
    let cp = d.audit.checkpoint(&key, 1_757_000_000);
    let verified = cp.verify(&key.verifying_key()).expect("we just signed it");

    d.audit
        .verify_against(&verified)
        .expect("the intact chain matches its own checkpoint");

    let short = truncate_tail(&d.audit);
    let err = short
        .verify_against(&verified)
        .expect_err("a shorter chain must not satisfy a longer commitment");
    let msg = format!("{err}");
    assert!(msg.contains("truncated"), "{msg}");
}

/// A commitment nobody trusts is not evidence. Whoever can shorten the
/// log can also write a checkpoint agreeing with the shortened length,
/// so the signature has to be checked against a key chosen in advance —
/// which is why `verify_against` takes a `VerifiedCheckpoint` and there
/// is no way to reach it with an unchecked one.
#[test]
fn a_checkpoint_signed_by_a_stranger_does_not_verify() {
    let key = signing_key();
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let d = check_sealed(
        &fixture("rotate_deployment.json"),
        &Manifest::from_json(&fixture("grant_ecs_only.json")).unwrap(),
        None,
        None,
        &key,
    )
    .unwrap();
    let forged = d.audit.checkpoint(&attacker, 1_757_000_000);
    assert!(
        forged.verify(&key.verifying_key()).is_err(),
        "a checkpoint must not verify under a key that did not sign it"
    );
}
