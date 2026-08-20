//! Conformance tests over a real MST transparent statement.
//!
//! The pinned constants come from two independent implementations that agree:
//! the .NET prototype and pyscitt. A change to any of them is a change to what
//! this tool considers the same statement, so it should never be quietly
//! updated to match new output.

use scitt_receipt::{verify_statement, KeyLookup, LedgerKeySet, Sign1};
use std::path::PathBuf;

/// SHA-256 of the signed statement, cross-checked against .NET and pyscitt.
const EXPECTED_CLAIM_DIGEST: &str =
    "5207494c12c986e33324c602e535717f67f0a6b56235f413e4a07d4d66d59565";
/// Length of the statement re-encoded with an empty unprotected bucket.
const EXPECTED_SIGNED_LEN: usize = 8462;
/// COSE algorithm of the Issuer's signature over the statement: PS256.
const EXPECTED_STATEMENT_ALG: i64 = -37;
/// COSE algorithm of the transparency service's signature over the Merkle
/// root: ES384. Pinned because it selects the curve used to verify the root
/// signature, so a change here is a change to which key material can satisfy
/// this receipt — not a cosmetic detail.
const EXPECTED_RECEIPT_ALG: i64 = -35;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "corpus",
        "fixtures",
        name,
    ]
    .iter()
    .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()))
}

fn key_set() -> LedgerKeySet {
    LedgerKeySet::from_cose_key_set(&fixture("musa-mst-july-scitt-keys.cbor"), None)
        .expect("fixture key set must parse")
}

#[test]
fn claim_digest_matches_independent_implementations() {
    let statement = Sign1::parse(&fixture("transparent-statement.cose")).unwrap();
    assert_eq!(
        statement.signed_statement_bytes().unwrap().len(),
        EXPECTED_SIGNED_LEN
    );
    assert_eq!(
        scitt_receipt::cbor::hex(&statement.claim_digest().unwrap()),
        EXPECTED_CLAIM_DIGEST
    );
}

#[test]
fn stripping_receipts_is_stable_across_reparse() {
    // Re-encoding must be idempotent, or the claim digest would depend on how
    // many times the statement had been through a tool.
    let statement = Sign1::parse(&fixture("transparent-statement.cose")).unwrap();
    let stripped = statement.signed_statement_bytes().unwrap();
    let reparsed = Sign1::parse(&stripped).unwrap();
    assert_eq!(reparsed.signed_statement_bytes().unwrap(), stripped);
    assert_eq!(
        reparsed.claim_digest().unwrap(),
        statement.claim_digest().unwrap()
    );
}

#[test]
fn key_set_parses_and_binds_kids_to_key_material() {
    let keys = key_set();
    assert!(!keys.keys.is_empty(), "fixture must contain usable keys");
    assert!(
        keys.skipped.is_empty(),
        "unexpected unparseable keys: {:?}",
        keys.skipped
    );
    for key in &keys.keys {
        assert!(
            key.kid_bound_to_key,
            "CCF derives kid from the key; {} did not match {}",
            key.kid, key.spki_sha256
        );
    }
}

#[test]
fn genuine_statement_verifies_end_to_end() {
    let facts = verify_statement(&fixture("transparent-statement.cose"), &key_set()).unwrap();

    assert_eq!(facts.claim_digest, EXPECTED_CLAIM_DIGEST);
    assert_eq!(facts.signature_valid, Some(true), "{:?}", facts.problems);
    assert!(facts.certificate_chain_len >= 1);
    assert_eq!(facts.receipts.len(), 1, "{:?}", facts.problems);

    let receipt = &facts.receipts[0];
    assert_eq!(
        receipt.key_lookup,
        Some(KeyLookup::Found),
        "{:?}",
        receipt.problems
    );
    assert_eq!(
        receipt.root_signature_valid,
        Some(true),
        "{:?}",
        receipt.problems
    );
    assert_eq!(
        receipt.bound_to_statement,
        Some(true),
        "{:?}",
        receipt.problems
    );
    assert!(receipt.fully_verified());
    assert_eq!(
        receipt.claims_digest.as_deref(),
        Some(EXPECTED_CLAIM_DIGEST)
    );

    // Both algorithms are pinned. They are not decoration: the receipt's `alg`
    // selects the curve the root signature is verified against, so an
    // unnoticed change here changes which key material can satisfy this
    // receipt. `corpus/README.md` documented ES256 for four releases while the
    // fixture was ES384, because nothing asserted it.
    assert_eq!(facts.alg, Some(EXPECTED_STATEMENT_ALG));
    assert_eq!(receipt.algorithm, Some(EXPECTED_RECEIPT_ALG));
}

#[test]
fn tampered_payload_breaks_both_the_signature_and_the_binding() {
    // The important half of this assertion is the binding. A tampered payload
    // changes the claim digest, so even an attacker who could forge the issuer
    // signature would still be holding a receipt for a different statement.
    let facts = verify_statement(&fixture("payload-tampered.cose"), &key_set()).unwrap();

    assert_ne!(facts.claim_digest, EXPECTED_CLAIM_DIGEST);
    assert_eq!(facts.signature_valid, Some(false));
    assert_eq!(facts.receipts[0].bound_to_statement, Some(false));
    assert!(!facts.receipts[0].fully_verified());
}

#[test]
fn tampered_statement_is_rejected() {
    let facts = verify_statement(&fixture("tampered-statement.cose"), &key_set()).unwrap();
    let ok =
        facts.signature_valid == Some(true) && facts.receipts.iter().any(|r| r.fully_verified());
    assert!(!ok, "a tampered statement must not verify: {facts:?}");
}

#[test]
fn wrong_key_set_reports_an_unknown_kid_rather_than_a_bad_signature() {
    // Distinguishing these is the difference between "rotate your trust
    // material" and "this artifact was tampered with".
    let stale = LedgerKeySet::from_cose_key_set(&fixture("stale-scitt-keys.cbor"), None)
        .expect("stale key set must still parse");
    let facts = verify_statement(&fixture("transparent-statement.cose"), &stale).unwrap();

    let receipt = &facts.receipts[0];
    assert_eq!(receipt.key_lookup, Some(KeyLookup::UnknownKid));
    assert_eq!(receipt.root_signature_valid, None);
    assert_eq!(
        receipt.bound_to_statement,
        Some(true),
        "binding does not depend on trust material"
    );
    assert!(!receipt.fully_verified());
}

#[test]
fn a_key_set_scoped_to_another_issuer_never_matches() {
    let scoped = LedgerKeySet {
        issuer: Some("https://not-the-issuer.example".into()),
        ..key_set()
    };
    let facts = verify_statement(&fixture("transparent-statement.cose"), &scoped).unwrap();
    assert_eq!(
        facts.receipts[0].key_lookup,
        Some(KeyLookup::IssuerMismatch)
    );
    assert!(!facts.receipts[0].fully_verified());
}

#[test]
fn truncated_input_is_rejected_without_panicking() {
    let full = fixture("transparent-statement.cose");
    for cut in [0usize, 1, 16, 512, full.len() / 2] {
        let result = Sign1::parse(&full[..cut]);
        assert!(result.is_err(), "{cut}-byte prefix must not parse");
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    // Accepting trailing data would let an attacker append content that some
    // other parser in the pipeline treats as significant.
    let mut bytes = fixture("transparent-statement.cose");
    bytes.push(0x00);
    assert!(Sign1::parse(&bytes).is_err());
}
