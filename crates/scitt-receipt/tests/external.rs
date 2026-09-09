//! Detached signatures, checked against a statement a real ledger registered.
//!
//! In `tests/` rather than beside the code because the core forbids file I/O
//! in `src/`, and the outcomes that matter here — a signature that verifies
//! and one that does not — cannot be reached without real key material. The
//! unit tests next to the module cover the shapes that need no crypto.

use scitt_receipt::external::{verify_cose_sign1, verify_detached, Detached};
use scitt_receipt::statement::Sign1;
use scitt_receipt::{labels, CborValue};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The descriptor at `external-signature[0]`, and the payload it covers.
fn descriptor_and_payload() -> (CborValue, Vec<u8>) {
    let statement = Sign1::parse(&fixture("cbor-header.cose")).expect("fixture must parse");
    let payload = statement.payload.clone().expect("fixture has a payload");

    let CborValue::Map(entries) = &statement.protected else {
        panic!("protected bucket is not a map");
    };
    let value = entries
        .iter()
        .find(|(k, _)| matches!(k, CborValue::TextString(s) if s == "external-signature"))
        .map(|(_, v)| v)
        .expect("fixture carries an external-signature header");
    let CborValue::Array(items) = value else {
        panic!("external-signature is not an array");
    };
    (items[0].clone(), payload)
}

fn replace(descriptor: &CborValue, label: i64, value: CborValue) -> CborValue {
    let CborValue::Map(entries) = descriptor else {
        panic!("descriptor is not a map");
    };
    CborValue::Map(
        entries
            .iter()
            .map(|(k, v)| match k {
                CborValue::Int(i) if *i == label => (k.clone(), value.clone()),
                _ => (k.clone(), v.clone()),
            })
            .collect(),
    )
}

#[test]
fn a_real_detached_signature_verifies_over_the_payload() {
    let (descriptor, payload) = descriptor_and_payload();
    match verify_detached(&descriptor, Some(&payload)) {
        Detached::Valid(signer) => {
            assert_eq!(signer.chain_len, 1);
            let subject = signer.subject.expect("the certificate names a subject");
            assert!(subject.contains("Example External Signer"), "{subject}");
        }
        other => panic!("expected a valid signature, got {other:?}"),
    }
}

/// The property that makes this assertion worth more than matching on the
/// descriptor's shape: flipping one bit of the signature is caught. A policy
/// that only read the algorithm and the certificate subject would still pass
/// on these bytes.
#[test]
fn one_flipped_bit_fails() {
    let (descriptor, payload) = descriptor_and_payload();
    let CborValue::Map(entries) = &descriptor else {
        unreachable!()
    };
    let mut signature = entries
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (CborValue::Int(i), CborValue::ByteString(b)) if *i == labels::DETACHED_SIGNATURE => {
                Some(b.clone())
            }
            _ => None,
        })
        .expect("the descriptor carries a signature");
    signature[0] ^= 0x01;

    let tampered = replace(
        &descriptor,
        labels::DETACHED_SIGNATURE,
        CborValue::ByteString(signature),
    );
    assert!(matches!(
        verify_detached(&tampered, Some(&payload)),
        Detached::Invalid { .. }
    ));
}

/// The signature covers the payload, so a different payload must not satisfy
/// it. This is what stops a producer moving a real supplier signature onto a
/// statement about something else.
#[test]
fn the_signature_does_not_cover_a_different_payload() {
    let (descriptor, payload) = descriptor_and_payload();
    let mut other = payload.clone();
    other.push(b' ');
    assert!(matches!(
        verify_detached(&descriptor, Some(&other)),
        Detached::Invalid { .. }
    ));
}

/// A signature of the wrong length for the declared algorithm is a failed
/// check, not an unanswerable one: the producer said what these bytes are,
/// and they are not that.
#[test]
fn a_signature_of_the_wrong_length_fails() {
    let (descriptor, payload) = descriptor_and_payload();
    let truncated = replace(
        &descriptor,
        labels::DETACHED_SIGNATURE,
        CborValue::ByteString(vec![0u8; 16]),
    );
    assert!(matches!(
        verify_detached(&truncated, Some(&payload)),
        Detached::Invalid { .. }
    ));
}

// ---------------------------------------------------------------------------
// A nested COSE_Sign1, the standard shape for the same job.
// ---------------------------------------------------------------------------

/// The nested COSE_Sign1 at `external-statement`, and the payload it covers.
fn nested_and_payload() -> (CborValue, Vec<u8>) {
    let statement = Sign1::parse(&fixture("nested-sign1.cose")).expect("fixture must parse");
    let payload = statement.payload.clone().expect("fixture has a payload");

    let CborValue::Map(entries) = &statement.protected else {
        panic!("protected bucket is not a map");
    };
    let value = entries
        .iter()
        .find(|(k, _)| matches!(k, CborValue::TextString(s) if s == "external-statement"))
        .map(|(_, v)| v)
        .expect("fixture carries a nested COSE_Sign1");
    (value.clone(), payload)
}

/// Rebuild the nested COSE_Sign1 with one array element replaced.
fn with_element(nested: &CborValue, index: usize, value: CborValue) -> CborValue {
    let CborValue::Tagged { tag, payload } = nested else {
        panic!("nested value is not tagged");
    };
    let CborValue::Array(items) = payload.as_ref() else {
        panic!("nested value is not an array");
    };
    let mut items = items.clone();
    items[index] = value;
    CborValue::Tagged {
        tag: *tag,
        payload: Box::new(CborValue::Array(items)),
    }
}

fn signature_of(nested: &CborValue) -> Vec<u8> {
    let CborValue::Tagged { payload, .. } = nested else {
        panic!("not tagged")
    };
    let CborValue::Array(items) = payload.as_ref() else {
        panic!("not an array")
    };
    match &items[3] {
        CborValue::ByteString(b) => b.clone(),
        other => panic!("signature is {other:?}"),
    }
}

#[test]
fn a_nested_cose_sign1_verifies_over_the_statement_payload() {
    let (nested, payload) = nested_and_payload();
    match verify_cose_sign1(&nested, Some(&payload)) {
        Detached::Valid(signer) => {
            let subject = signer.subject.expect("the certificate names a subject");
            assert!(subject.contains("Example External Signer"), "{subject}");
        }
        other => panic!("expected a valid signature, got {other:?}"),
    }
}

#[test]
fn a_nested_cose_sign1_with_a_flipped_bit_fails() {
    let (nested, payload) = nested_and_payload();
    let mut sig = signature_of(&nested);
    sig[0] ^= 0x01;
    let tampered = with_element(&nested, 3, CborValue::ByteString(sig));
    assert!(matches!(
        verify_cose_sign1(&tampered, Some(&payload)),
        Detached::Invalid { .. }
    ));
}

/// Duplicating the payload inside the nested envelope is wasteful but not
/// wrong, so long as the two copies agree.
#[test]
fn an_embedded_payload_that_matches_is_accepted() {
    let (nested, payload) = nested_and_payload();
    let embedded = with_element(&nested, 2, CborValue::ByteString(payload.clone()));
    assert!(matches!(
        verify_cose_sign1(&embedded, Some(&payload)),
        Detached::Valid(_)
    ));
}

/// The case the strictness exists for. Two disagreeing copies of the payload
/// inside one signed statement would let a producer have a supplier endorse
/// one thing while registering another, with both signatures verifying. The
/// signature here is genuinely valid over the bytes it covers; those bytes are
/// simply not the ones being deployed.
#[test]
fn an_embedded_payload_that_differs_fails() {
    let (nested, payload) = nested_and_payload();
    let embedded = with_element(
        &nested,
        2,
        CborValue::ByteString(b"something else".to_vec()),
    );
    match verify_cose_sign1(&embedded, Some(&payload)) {
        Detached::Invalid { why, .. } => {
            assert!(why.contains("embeds its own payload"), "{why}");
            assert!(
                why.contains("not the bytes this statement registered"),
                "{why}"
            );
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

/// The two conventions read different structures. Pointing one at the other's
/// shape must say so, not report a forgery.
#[test]
fn the_two_conventions_do_not_silently_read_each_other() {
    let (descriptor, payload) = descriptor_and_payload();
    let as_sign1 = verify_cose_sign1(&descriptor, Some(&payload));
    match as_sign1 {
        Detached::Unusable(why) => assert!(why.contains("not a COSE_Sign1"), "{why}"),
        other => panic!("expected unusable, got {other:?}"),
    }

    let (nested, payload) = nested_and_payload();
    match verify_detached(&nested, Some(&payload)) {
        Detached::Unusable(_) => {}
        other => panic!("expected unusable, got {other:?}"),
    }
}
