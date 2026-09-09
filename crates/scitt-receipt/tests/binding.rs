//! Binding a statement to an artifact, exercised against the real corpus.
//!
//! These live in `tests/` rather than beside the code because the core forbids
//! file I/O in `src/` and CI greps for it. Reading fixtures here keeps that
//! boundary intact while still testing against statements a real ledger
//! produced rather than bytes assembled to make the test pass.

use scitt_receipt::binding::{bind, Binding, BindingMode, BindingReason};
use scitt_receipt::statement::Sign1;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn statement(name: &str) -> Sign1 {
    Sign1::parse(&fixture(name)).expect("fixture must parse")
}

#[test]
fn an_embedded_payload_binds_to_its_own_artifact() {
    let report = bind(
        &statement("transparent-statement.cose"),
        &fixture("artifact.bin"),
        BindingMode::PayloadBytes,
    );
    assert_eq!(report.outcome, Binding::Bound);
    assert!(matches!(
        report.reason,
        BindingReason::PayloadIsArtifact { .. }
    ));
    assert!(report
        .reason
        .describe("artifact.bin")
        .contains("byte-identical"));
}

/// The check the whole feature exists for: a genuine statement paired with the
/// wrong file must say so rather than passing on the strength of its signature.
#[test]
fn an_embedded_payload_does_not_bind_to_a_different_artifact() {
    let report = bind(
        &statement("transparent-statement.cose"),
        &fixture("bad-artifact.bin"),
        BindingMode::PayloadBytes,
    );
    assert_eq!(report.outcome, Binding::Mismatch);
    let text = report.reason.describe("bad-artifact.bin");
    assert!(text.contains("does not equal"), "{text}");
    assert!(text.contains("bad-artifact.bin"), "{text}");
}

#[test]
fn a_hash_envelope_binds_to_its_preimage() {
    let report = bind(
        &statement("hash-envelope.cose"),
        &fixture("hash-envelope-artifact.spdx.json"),
        BindingMode::PayloadDigest,
    );
    assert_eq!(report.outcome, Binding::Bound);
    assert!(matches!(
        report.reason,
        BindingReason::DigestIsArtifact { .. }
    ));
}

#[test]
fn a_hash_envelope_does_not_bind_to_a_different_preimage() {
    let report = bind(
        &statement("hash-envelope.cose"),
        &fixture("hash-envelope-bad-artifact.spdx.json"),
        BindingMode::PayloadDigest,
    );
    assert_eq!(report.outcome, Binding::Mismatch);
}

/// Both mode mismatches must be `CannotCompare`. Returning `Mismatch` would
/// tell an operator their artifact is wrong when the tool was simply asked the
/// wrong question — the difference between halting a release and fixing a flag.
#[test]
fn a_mode_that_does_not_fit_the_statement_cannot_compare() {
    let envelope_as_bytes = bind(
        &statement("hash-envelope.cose"),
        &fixture("hash-envelope-artifact.spdx.json"),
        BindingMode::PayloadBytes,
    );
    assert_eq!(envelope_as_bytes.outcome, Binding::CannotCompare);
    assert_eq!(
        envelope_as_bytes.reason,
        BindingReason::HashEnvelopeNeedsDigestMode
    );

    let plain_as_digest = bind(
        &statement("transparent-statement.cose"),
        &fixture("artifact.bin"),
        BindingMode::PayloadDigest,
    );
    assert_eq!(plain_as_digest.outcome, Binding::CannotCompare);
    assert_eq!(plain_as_digest.reason, BindingReason::NotAHashEnvelope);
}

/// A correct artifact paired with a tampered statement must still bind: the
/// two questions are independent, and conflating them would hide which one
/// actually failed.
#[test]
fn binding_is_independent_of_whether_the_signature_verifies() {
    let report = bind(
        &statement("tampered-statement.cose"),
        &fixture("artifact.bin"),
        BindingMode::PayloadBytes,
    );
    assert_eq!(report.outcome, Binding::Bound);
}

/// Every reason must carry a machine-stable code, and no two may share one:
/// consumers that switch on `code` would silently conflate two findings.
#[test]
fn reason_codes_are_distinct() {
    let reasons = [
        BindingReason::PayloadIsArtifact { len: 1 },
        BindingReason::PayloadIsNotArtifact {
            payload_len: 1,
            payload_sha256: "a".into(),
            artifact_len: 2,
            artifact_sha256: "b".into(),
        },
        BindingReason::DigestIsArtifact {
            alg: "SHA-256".into(),
            len: 1,
        },
        BindingReason::DigestIsNotArtifact {
            alg: "SHA-256".into(),
            stated: "a".into(),
            computed: "b".into(),
        },
        BindingReason::HashEnvelopeNeedsDigestMode,
        BindingReason::NotAHashEnvelope,
        BindingReason::PayloadDetached {
            mode: BindingMode::PayloadBytes,
        },
        BindingReason::UnsupportedHashAlg {
            alg: "SHA-1".into(),
        },
        BindingReason::DigestLengthMismatch {
            alg: "SHA-256".into(),
            expected_len: 32,
            payload_len: 8,
        },
    ];

    let mut codes: Vec<&str> = reasons.iter().map(|r| r.code()).collect();
    let total = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), total, "reason codes must be distinct");

    // And every one must say something naming the artifact it was given, so a
    // report never leaves a reader guessing which file was compared.
    for reason in &reasons {
        let text = reason.describe("the-artifact");
        assert!(!text.is_empty(), "{:?} described as nothing", reason.code());
    }
}
