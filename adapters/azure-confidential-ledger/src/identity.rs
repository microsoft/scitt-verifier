//! Binding a node's attestation report to the ledger it claims to belong to.
//!
//! Attestation alone establishes that *some* genuine SEV-SNP machine produced
//! a report and that it is enforcing a particular execution policy. It says
//! nothing about *whose* machine it is. Without the binding in this module, an
//! adapter would accept a real, correctly endorsed node belonging to an
//! entirely different service — including one an attacker stood up themselves
//! with the same policy — and report that the ledger the operator named is
//! enforcing it.
//!
//! The binding is a two-link chain, and both links are needed:
//!
//! 1. **Report to key.** CCF places `sha256(SubjectPublicKeyInfo DER)` of the
//!    node's own key in the first 32 bytes of `REPORT_DATA`. Because the
//!    report is signed by the AMD-rooted VCEK, this ties the hardware
//!    attestation to one specific public key.
//! 2. **Key to service.** The node certificate carrying that key is signed by
//!    the ledger's service identity certificate, which the consumer obtained
//!    from a source it independently trusts — for Azure Confidential Ledger,
//!    the publicly-trusted identity service, never the ledger under
//!    assessment.
//!
//! Either link alone is worthless. The first proves a key was attested but not
//! by whom it is vouched for; the second proves a service vouched for a key
//! but not that the key is in a confidential VM.
//!
//! Both facts were confirmed against a live Azure Confidential Ledger on
//! 2026-09-22: every node certificate served by `/gov/service/nodes` hashed to
//! the node identifier the ledger reported, was issued by `CN=CCF Service`,
//! and matched the first 32 bytes of `REPORT_DATA` in that node's report.
//!
//! ## What this deliberately does not check
//!
//! Certificate *validity periods* are not enforced. Saved evidence is a
//! recording, and CCF node certificates are short-lived: refusing an expired
//! one would make every bundle fail once its nodes rotated, which is a fact
//! about elapsed time and not about the ledger. Whether the assessed nodes are
//! still serving is the freshness question, which this crate reports as
//! permanently unevaluable rather than quietly folding in here. The validity
//! window that *was* observed is returned so the caller can report it.

use scitt_receipt::{chain, der};
use tav_crypto::{
    CertificateBackend, CryptoBackend, EcSignatureKeyAlgorithm, KeyBackend, SignatureBackend,
    SignatureKeyAlgorithm,
};

/// What the binding established, for reporting.
#[derive(Debug)]
pub(crate) struct BindingDetails {
    /// Latest `notBefore` across the validated path.
    pub not_before: i64,
    /// Earliest `notAfter` across the validated path.
    pub not_after: i64,
}

/// Verify that this node's report, key, and certificate all belong to the
/// ledger whose service certificate was supplied.
///
/// `report_data` is the authenticated 64-byte field from a report whose
/// signature and AMD chain have *already* verified. Passing an unauthenticated
/// report here would compare a number an attacker chose against a certificate
/// they also chose, and find them equal.
pub(crate) fn verify_binding(
    node_certificate_pem: &[u8],
    service_certificate_der: &[u8],
    report_data: &[u8; 64],
) -> Result<BindingDetails, String> {
    let pem = core::str::from_utf8(node_certificate_pem)
        .map_err(|_| "the node certificate is not valid UTF-8 PEM".to_string())?;
    let mut certs = chain::parse_pem_certificates(pem)
        .map_err(|e| format!("the node certificate could not be parsed: {e}"))?;
    if certs.len() != 1 {
        // More than one would make "which certificate was bound" ambiguous,
        // and the answer decides what the whole check means.
        return Err(format!(
            "expected exactly one node certificate, found {}",
            certs.len()
        ));
    }
    let node_der = certs.remove(0);

    // Link 1: the attested key.
    let spki = scitt_receipt::spki_from_certificate_der(&node_der)
        .map_err(|e| format!("the node certificate's public key could not be read: {e}"))?;
    let expected = scitt_receipt::sha256(&spki);
    // Only the first 32 bytes carry the digest; CCF leaves the rest zero. A
    // comparison over all 64 would depend on padding this code does not own.
    if report_data[..32] != expected {
        return Err(format!(
            "the report attests key {}, but the node certificate carries {}. This report \
             was not produced by the holder of this certificate.",
            hex(&report_data[..32]),
            hex(&expected)
        ));
    }

    // Link 2: who vouches for that key.
    verify_issued_by(&node_der, service_certificate_der)?;

    // Recorded, not enforced. See the module comment.
    let validity = der::parse_validity(&node_der)
        .map_err(|e| format!("the node certificate's validity could not be read: {e}"))?;

    Ok(BindingDetails {
        not_before: validity.not_before,
        not_after: validity.not_after,
    })
}

/// Verify that `issuer_der` signed `subject_der`.
///
/// Not `scitt_receipt::chain::validate`, which cannot answer this question:
/// the pinned X.509 backend parses only RSA signature algorithms, so it
/// reports every ECDSA-signed certificate as one this build cannot check — and
/// CCF signs both its service and node certificates with ECDSA P-384. What the
/// backend *can* do is verify a raw ECDSA signature, so the certificate is
/// taken apart here and that primitive is used directly.
///
/// Only the issuer relationship is established. This is not path validation:
/// there is exactly one link, the anchor is supplied by the consumer rather
/// than discovered, and no name chaining, basic constraints, or validity
/// window is consulted. That is the whole question CCF poses — a node
/// certificate is signed directly by the service identity — and claiming more
/// would overstate it.
fn verify_issued_by(subject_der: &[u8], issuer_der: &[u8]) -> Result<(), String> {
    let (tbs, signature) = der::tbs_and_signature(subject_der)
        .map_err(|e| format!("the node certificate could not be taken apart: {e}"))?;

    let oid = der::parse_signature_algorithm_oid(subject_der)
        .map_err(|e| format!("the node certificate's signature algorithm is unreadable: {e}"))?;
    let digest = ec_algorithm_for(&oid).ok_or_else(|| {
        format!(
            "the node certificate is signed with algorithm {oid}, which this build cannot \
             verify; the certificate was not checked either way"
        )
    })?;

    let issuer_spki = scitt_receipt::spki_from_certificate_der(issuer_der).map_err(|e| {
        format!("the service identity certificate's public key could not be read: {e}")
    })?;

    // The signature algorithm OID names the *digest*, not the curve, and the
    // backend's algorithm enum fuses the two. The key is therefore imported
    // under the same fused algorithm the signature is parsed with, so a
    // certificate whose digest and curve disagree fails to import rather than
    // being verified against a curve nobody named.
    let algorithm = SignatureKeyAlgorithm::Ec(digest);
    let key =
        <tav_crypto::Key as KeyBackend>::from_spki_der(&issuer_spki, algorithm).map_err(|e| {
            format!(
                "the service identity's key could not be used to check a {} signature: {e}",
                digest.name()
            )
        })?;
    let signature = <tav_crypto::Signature as SignatureBackend>::from_bytes(signature, algorithm)
        .map_err(|e| format!("the node certificate's signature is malformed: {e}"))?;

    <tav_crypto::Crypto as CryptoBackend>::verify_signature(&key, &signature, tbs).map_err(|e| {
        format!("the node certificate is not signed by the ledger's service identity: {e}")
    })
}

/// Map an ECDSA signature-algorithm OID onto the backend's fused curve/digest.
///
/// RSA is deliberately absent. CCF uses ECDSA throughout, and an RSA-signed
/// certificate here would mean the evidence did not come from the service this
/// check was written for — better reported as unverifiable than quietly
/// admitted through a path nothing exercises.
fn ec_algorithm_for(oid: &str) -> Option<EcSignatureKeyAlgorithm> {
    match oid {
        "1.2.840.10045.4.3.2" => Some(EcSignatureKeyAlgorithm::P256), // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Some(EcSignatureKeyAlgorithm::P384), // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4" => Some(EcSignatureKeyAlgorithm::P521), // ecdsa-with-SHA512
        _ => None,
    }
}

/// Silence the unused-import warning when `CertificateBackend` is only needed
/// for its trait bound on `CryptoBackend`.
const _: fn() = || {
    fn assert_backend<T: CertificateBackend>() {}
    assert_backend::<tav_crypto::Crypto>();
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real CCF node certificate and the service identity that signed it,
    /// from `mst-test-scitt-verifier`, the throwaway ledger that also backs the
    /// conformance corpus, fetched via `/gov/service/nodes` and the publicly
    /// trusted identity service.
    ///
    /// Both are public TLS material and contain no secret, and the ledger is
    /// ours: evidence from a production service belonging to another team must
    /// not be committed here, however public its certificate is.
    ///
    /// They are committed rather than synthesised because the DER this parses
    /// and the ECDSA P-384 issuer signature it verifies are what CCF actually
    /// emits, and a hand-built pair would only test that this file agrees with
    /// itself.
    const SERVICE_PEM: &str = include_str!("../tests/fixtures/service-identity.pem");
    const NODE_PEM: &str = include_str!("../tests/fixtures/node.pem");

    fn service_der() -> Vec<u8> {
        chain::parse_pem_certificates(SERVICE_PEM)
            .expect("fixture parses")
            .remove(0)
    }

    /// `REPORT_DATA` as CCF would have built it for this node: the SPKI digest
    /// in the low 32 bytes, zero in the rest.
    fn report_data_for(node_pem: &str) -> [u8; 64] {
        let der = chain::parse_pem_certificates(node_pem)
            .expect("fixture parses")
            .remove(0);
        let spki = scitt_receipt::spki_from_certificate_der(&der).expect("spki");
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&scitt_receipt::sha256(&spki));
        rd
    }

    #[test]
    fn a_node_certified_by_the_service_binds() {
        let details = verify_binding(
            NODE_PEM.as_bytes(),
            &service_der(),
            &report_data_for(NODE_PEM),
        )
        .expect("the live pair must bind");
        assert!(details.not_before < details.not_after);
    }

    /// The case the whole check exists for: a genuine, correctly endorsed
    /// report from a machine that is not this ledger's node. Simulated by
    /// leaving `REPORT_DATA` committing to some other key.
    #[test]
    fn a_report_attesting_another_key_is_refused() {
        let mut rd = report_data_for(NODE_PEM);
        rd[0] ^= 0xff;
        let err = verify_binding(NODE_PEM.as_bytes(), &service_der(), &rd).unwrap_err();
        assert!(err.contains("not produced by the holder"), "{err}");
    }

    /// Only the first 32 bytes carry the digest. Trailing bytes must not be
    /// compared, or a padding convention this code does not own would decide
    /// the verdict.
    #[test]
    fn the_high_half_of_report_data_is_not_compared() {
        let mut rd = report_data_for(NODE_PEM);
        rd[63] = 0x01;
        verify_binding(NODE_PEM.as_bytes(), &service_der(), &rd)
            .expect("the low 32 bytes still match");
    }

    /// Anchoring to a different service must fail even though the node
    /// certificate and its report agree with each other. Without this link, a
    /// node attesting its own self-consistent key would pass.
    #[test]
    fn a_node_from_another_ledger_is_refused() {
        // The node certificate as its own anchor: internally consistent, and
        // signed by nothing the consumer trusts.
        let node_der = chain::parse_pem_certificates(NODE_PEM)
            .expect("fixture parses")
            .remove(0);
        let err =
            verify_binding(NODE_PEM.as_bytes(), &node_der, &report_data_for(NODE_PEM)).unwrap_err();
        assert!(
            err.contains("service identity"),
            "must name the anchor as the problem: {err}"
        );
    }

    /// A tampered certificate must fail, and must not be reported as a key
    /// mismatch: the signature is what broke.
    #[test]
    fn a_tampered_node_certificate_is_refused() {
        let mut lines: Vec<String> = NODE_PEM.lines().map(str::to_string).collect();
        // The second-to-last body line lands inside the signature for a
        // certificate this size, so flipping a character there leaves the
        // structure and the public key intact and breaks only the signature.
        let target = lines.len() - 3;
        let line = &mut lines[target];
        let first = if line.starts_with('A') { 'B' } else { 'A' };
        line.replace_range(0..1, &first.to_string());
        let tampered = lines.join("\n");
        let err = verify_binding(
            tampered.as_bytes(),
            &service_der(),
            &report_data_for(&tampered),
        )
        .unwrap_err();
        assert!(err.contains("not signed by"), "{err}");
    }

    /// The error must say the certificate is unparseable, not that the key
    /// did not match. Sending an operator to compare keys when the real
    /// problem is a malformed file wastes the one clue they were given.
    #[test]
    fn an_unparseable_certificate_says_so() {
        let err =
            verify_binding(b"-----BEGIN CERTIFICATE-----\nnope\n", b"", &[0u8; 64]).unwrap_err();
        assert!(
            err.contains("could not be parsed") || err.contains("not valid UTF-8"),
            "{err}"
        );
    }

    /// Two certificates leave "which one was bound" undecided, so the file is
    /// refused rather than the first one silently chosen.
    #[test]
    fn more_than_one_node_certificate_is_refused() {
        let doubled = format!("{NODE_PEM}\n{NODE_PEM}");
        let err = verify_binding(doubled.as_bytes(), &service_der(), &[0u8; 64]).unwrap_err();
        assert!(err.contains("exactly one"), "{err}");
    }
}
