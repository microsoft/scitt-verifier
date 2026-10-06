//! Binding a key set to the service certificate the identity service published.
//!
//! The certificate and key set are real bytes from the same ledger, so the
//! positive case proves the check accepts what a working service serves, not
//! merely what a hand-built fixture happens to contain.

use scitt_receipt::{
    chain::parse_pem_certificates, sha256_hex, spki_from_certificate_der, verify_statement,
    KeyLookup, LedgerKeySet, ServiceKeyMismatch,
};
use std::path::PathBuf;

/// SHA-256 of the service certificate DER, as recorded in docs/trust-material.md.
const SERVICE_CERT_SHA256: &str =
    "b021d80900d21bead1fb8b98f9442d7ed94ab5aa5bf26216202eb615e86dc768";

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

fn keys(name: &str) -> LedgerKeySet {
    LedgerKeySet::from_cose_key_set(&fixture(name)).expect("fixture key set must parse")
}

fn service_key_kid() -> String {
    let pem = String::from_utf8(fixture("mst-test-service-cert.pem")).unwrap();
    let certs = parse_pem_certificates(&pem).unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(sha256_hex(&certs[0]), SERVICE_CERT_SHA256);
    sha256_hex(&spki_from_certificate_der(&certs[0]).unwrap())
}

#[test]
fn the_ledgers_own_key_set_contains_its_service_key() {
    let kid = service_key_kid();
    let set = keys("mst-test-scitt-keys.cbor");
    let key = set.service_key(&kid).expect("service key must be present");
    assert_eq!(key.kid, kid);
    assert!(key.kid_bound_to_key);
}

#[test]
fn another_services_key_set_does_not() {
    let set = keys("other-service-scitt-keys.cbor");
    assert_eq!(
        set.service_key(&service_key_kid()).unwrap_err(),
        ServiceKeyMismatch::Absent
    );
}

#[test]
fn a_duplicated_service_key_is_ambiguous() {
    let kid = service_key_kid();
    let mut set = keys("mst-test-scitt-keys.cbor");
    let copy = set.service_key(&kid).unwrap().clone();
    set.keys.push(copy);
    assert_eq!(
        set.service_key(&kid).unwrap_err(),
        ServiceKeyMismatch::Ambiguous
    );
}

/// The attack the check exists for: an entry that claims the service's `kid`
/// while carrying some other key.
#[test]
fn a_relabelled_foreign_key_is_unbound() {
    let kid = service_key_kid();
    let mut set = keys("other-service-scitt-keys.cbor");
    let mut forged = set.keys[0].clone();
    forged.kid = kid.clone();
    forged.kid_bound_to_key = forged.spki_sha256 == forged.kid;
    set.keys = vec![forged];
    assert_eq!(
        set.service_key(&kid).unwrap_err(),
        ServiceKeyMismatch::Unbound
    );
}

#[test]
fn restricting_to_the_service_key_still_verifies_its_receipt() {
    let set = keys("mst-test-scitt-keys.cbor");
    let only = set.restricted_to(set.service_key(&service_key_kid()).unwrap());
    assert_eq!(only.keys.len(), 1);
    let facts = verify_statement(&fixture("transparent-statement.cose"), &only).unwrap();
    assert!(facts.any_receipt_verified());
}

/// A key the caller cannot vouch for must leave a receipt unevaluated, not
/// verified, even though the full set would have verified it.
#[test]
fn restricting_away_the_signing_key_leaves_the_receipt_unevaluated() {
    let set = keys("mst-test-scitt-keys.cbor");
    let other = keys("other-service-scitt-keys.cbor");
    let only = set.restricted_to(&other.keys[0]);
    let facts = verify_statement(&fixture("transparent-statement.cose"), &only).unwrap();
    assert!(!facts.any_receipt_verified());
    assert_eq!(facts.receipts[0].key_lookup, Some(KeyLookup::UnknownKid));
    assert_eq!(facts.receipts[0].root_signature_valid, None);
}
