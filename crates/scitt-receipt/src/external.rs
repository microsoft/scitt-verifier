//! Detached signatures carried inside a protected header.
//!
//! A producer may place a signature made by a *different* party in the
//! statement's protected header — a component supplier signing the manifest a
//! service later registers. The descriptor borrows COSE's header labels:
//! `1` the algorithm, `33` the certificate chain, `-1` the signature.
//!
//! What this buys a relying party is evidence from a second organisation. The
//! envelope signature says who registered the statement; this says who stood
//! behind its contents. When the two are the same party it adds nothing.
//!
//! The signature is over the payload bytes as they appear in the statement.
//! That convention is the producer's, not COSE's, so it is stated here rather
//! than discovered: a detached signature says nothing about *what* was signed,
//! and a verifier that guesses would report a failure on a sound signature —
//! the worst outcome for a gate, because it teaches operators to ignore it.

use crate::error::{Error, Result};
use crate::labels;
use crate::statement::Sign1;
use tav_cose::CborValue;
use tav_crypto::{
    CertificateBackend, CryptoBackend, KeyBackend, RsaPkcs1v15SignatureKeyAlgorithm,
    SignatureBackend, SignatureKeyAlgorithm,
};

/// Who made a detached signature, as far as the certificate says.
///
/// Names only. A subject is what a certificate claims, and this build does not
/// validate the chain to a trusted root, so two statements naming the same
/// subject are not thereby from the same signer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetachedSigner {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub chain_len: usize,
}

/// The result of examining one detached signature.
#[derive(Debug, Clone)]
pub enum Detached {
    /// The signature verifies against the key in its own certificate.
    ///
    /// This is a statement about bytes, not about trust. The certificate is
    /// whatever the producer put there, up to and including one it minted for
    /// the purpose, so a caller that stops here has verified a self-assertion.
    Valid(DetachedSigner),
    /// The signature is present and well formed, and it does not establish
    /// what the policy asked about this statement.
    ///
    /// Carries a reason because there is more than one way to arrive here and
    /// they call for different responses: bytes that are not a signature by
    /// that key at all, and a perfectly good signature that covers something
    /// other than this statement's payload.
    Invalid { signer: DetachedSigner, why: String },
    /// The question could not be put: something is missing, malformed, or uses
    /// an algorithm this build cannot compute. Never a pass, and never a
    /// failure either — the difference matters to whoever reads the report.
    Unusable(String),
}

/// COSE_Sign1's `Sig_structure` context string (RFC 9052 §4.4).
const SIG_STRUCTURE_CONTEXT: &str = "Signature1";

/// Map a COSE algorithm to a key algorithm, including the RSA PKCS#1 v1.5
/// identifiers.
///
/// `tav_cose::signature_key_algorithm_for_cose_alg` covers ECDSA and RSA-PSS
/// and stops there, so `-257` — overwhelmingly the algorithm on a detached
/// supplier signature — arrives as an error. The backend implements PKCS#1
/// v1.5 in full; only the mapping was missing, so it is supplied here rather
/// than the capability being declared absent.
fn key_algorithm(alg: i64) -> Option<SignatureKeyAlgorithm> {
    match alg {
        labels::alg::RS256 => Some(SignatureKeyAlgorithm::RsaPkcs1v15(
            RsaPkcs1v15SignatureKeyAlgorithm::Rs256,
        )),
        -258 => Some(SignatureKeyAlgorithm::RsaPkcs1v15(
            RsaPkcs1v15SignatureKeyAlgorithm::Rs384,
        )),
        -259 => Some(SignatureKeyAlgorithm::RsaPkcs1v15(
            RsaPkcs1v15SignatureKeyAlgorithm::Rs512,
        )),
        other => tav_cose::signature_key_algorithm_for_cose_alg(other).ok(),
    }
}

fn member(map: &CborValue, label: i64) -> Option<&CborValue> {
    let CborValue::Map(entries) = map else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Int(i) if *i == label))
        .map(|(_, v)| v)
}

fn bytes(value: Option<&CborValue>) -> Option<&[u8]> {
    match value {
        Some(CborValue::ByteString(b)) => Some(b),
        _ => None,
    }
}

/// The leaf certificate of the descriptor's `x5chain`, and the chain's length.
///
/// A single byte string is accepted as a one-element chain, matching how
/// `x5chain` is read elsewhere: RFC 9360 permits both encodings, and rejecting
/// the shorthand would fail statements that are perfectly well formed.
fn leaf_der(descriptor: &CborValue) -> Option<(Vec<u8>, usize)> {
    match member(descriptor, labels::X5CHAIN)? {
        CborValue::ByteString(b) => Some((b.clone(), 1)),
        CborValue::Array(items) => match items.first() {
            Some(CborValue::ByteString(b)) => Some((b.clone(), items.len())),
            _ => None,
        },
        _ => None,
    }
}

/// Check one detached signature descriptor against the bytes it should cover.
///
/// `payload` is the statement's payload. A detached payload leaves nothing to
/// check against and is reported as unusable rather than assumed empty.
pub fn verify_detached(descriptor: &CborValue, payload: Option<&[u8]>) -> Detached {
    let Some(payload) = payload else {
        return Detached::Unusable(
            "the statement's payload is detached, so there are no bytes to check the signature \
             against"
                .into(),
        );
    };

    let Some(CborValue::Int(alg)) = member(descriptor, labels::ALG) else {
        return Detached::Unusable(
            "the descriptor declares no algorithm at label 1, so which signature scheme to apply \
             is unknown"
                .into(),
        );
    };
    let Some(algorithm) = key_algorithm(*alg) else {
        return Detached::Unusable(format!(
            "{} ({alg}) is not an algorithm this build can verify",
            labels::alg::name(*alg)
        ));
    };

    let Some(signature_bytes) = bytes(member(descriptor, labels::DETACHED_SIGNATURE)) else {
        return Detached::Unusable("the descriptor carries no signature at label -1".into());
    };

    let Some((der, chain_len)) = leaf_der(descriptor) else {
        return Detached::Unusable(
            "the descriptor carries no certificate at label 33, so there is no key to check the \
             signature with. A signature nobody can check is not evidence."
                .into(),
        );
    };

    let signer = match describe(&der, chain_len) {
        Ok(signer) => signer,
        Err(e) => return Detached::Unusable(e.to_string()),
    };

    match verify(&der, algorithm, signature_bytes, payload) {
        Ok(true) => Detached::Valid(signer),
        Ok(false) => Detached::Invalid {
            signer,
            why: "the bytes at label -1 are not a signature over the payload by the key in the \
                  certificate at label 33"
                .into(),
        },
        Err(e) => Detached::Unusable(e.to_string()),
    }
}

/// Check a nested COSE_Sign1 carried in a protected header.
///
/// The standard shape for the same job the hand-rolled descriptor does, and a
/// better one: COSE already defines how to carry an algorithm, a certificate
/// chain and a signature together, and — through `Sig_structure` — exactly
/// which bytes the signature covers. Nothing has to be inferred, and any COSE
/// library can check it.
///
/// A detached payload (`nil`) is the expected form: the signature is computed
/// over the outer statement's payload without duplicating it. At the size of a
/// certificate chain the wrapper costs a handful of bytes over the descriptor.
///
/// An *embedded* payload is accepted only when it is byte-for-byte the outer
/// statement's payload. This is the case worth being strict about: two copies
/// of the payload inside one signed statement, with nothing forcing them to
/// agree, means a producer could embed what the supplier endorsed and register
/// something else. Both signatures verify. Treating that as a pass would
/// report an endorsement of bytes nobody is deploying.
pub fn verify_cose_sign1(descriptor: &CborValue, payload: Option<&[u8]>) -> Detached {
    // Re-encoding to reach `Sign1::parse` is safe in a way re-encoding the
    // outer statement would not be. Nothing here is compared against the wire:
    // the protected bucket is a byte string, which round-trips exactly, and it
    // is those bytes — not this array — that the signature covers.
    let bytes = match descriptor.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            return Detached::Unusable(format!(
                "the value at this path could not be read as a COSE_Sign1: {e:?}"
            ))
        }
    };
    let inner = match Sign1::parse(&bytes) {
        Ok(inner) => inner,
        Err(e) => {
            return Detached::Unusable(format!(
                "the value at this path is not a COSE_Sign1: {e}. A hand-rolled descriptor map \
                 is read with signedOver 'payload' instead."
            ))
        }
    };

    let Some(leaf) = inner.x5chain().first().cloned() else {
        return Detached::Unusable(
            "the nested COSE_Sign1 carries no x5chain, so there is no key to check its signature \
             with. A signature nobody can check is not evidence."
                .into(),
        );
    };
    let signer = match describe(&leaf, inner.x5chain().len()) {
        Ok(signer) => signer,
        Err(e) => return Detached::Unusable(e.to_string()),
    };

    let Some(statement_payload) = payload else {
        return Detached::Unusable(
            "the statement's payload is detached, so there is nothing for the nested COSE_Sign1 \
             to be about"
                .into(),
        );
    };

    if let Some(embedded) = &inner.payload {
        if embedded != statement_payload {
            return Detached::Invalid {
                signer,
                why: format!(
                    "the nested COSE_Sign1 embeds its own payload of {} bytes, which is not the \
                     statement's {} byte payload. Its signature may well be valid over those \
                     bytes; they are not the bytes this statement registered.",
                    embedded.len(),
                    statement_payload.len()
                ),
            };
        }
    }

    match verify_sign1(&inner, statement_payload, &leaf) {
        Ok(true) => Detached::Valid(signer),
        Ok(false) => Detached::Invalid {
            signer,
            why: "the nested COSE_Sign1's signature does not verify over the statement's payload"
                .into(),
        },
        Err(e) => Detached::Unusable(e.to_string()),
    }
}

fn verify_sign1(inner: &Sign1, payload: &[u8], der: &[u8]) -> Result<bool> {
    let alg = inner.alg()?;
    let algorithm = key_algorithm(alg).ok_or(Error::UnsupportedAlgorithm(alg))?;

    // Deliberately not `tav_cose::cose_verify1`, which the envelope check uses.
    // It returns one error for two different questions — "this signature is
    // wrong" and "I cannot map this algorithm" — and its algorithm table has
    // no RSA PKCS#1 entry, so every RS256 signature came back as an error that
    // reads exactly like a forgery. Building the structure here keeps the two
    // apart: an algorithm this build cannot compute is refused above, by name.
    let tbs = CborValue::Array(vec![
        CborValue::TextString(SIG_STRUCTURE_CONTEXT.into()),
        CborValue::ByteString(inner.protected_raw.clone()),
        // external_aad, empty. Nothing in this profile supplies one, and a
        // value here would have to come from outside the statement.
        CborValue::ByteString(Vec::new()),
        CborValue::ByteString(payload.to_vec()),
    ])
    .to_bytes()
    .map_err(|e| Error::Structure(format!("could not build the Sig_structure: {e:?}")))?;

    verify(der, algorithm, &inner.signature, &tbs)
}

fn describe(der: &[u8], chain_len: usize) -> Result<DetachedSigner> {
    let cert = <tav_crypto::Crypto as CertificateBackend>::from_der(der)
        .map_err(|e| Error::Crypto(format!("the signer's certificate is not valid DER: {e}")))?;
    Ok(DetachedSigner {
        subject: Some(<tav_crypto::Crypto as CertificateBackend>::subject_name(
            &cert,
        )),
        issuer: Some(<tav_crypto::Crypto as CertificateBackend>::issuer_name(
            &cert,
        )),
        chain_len,
    })
}

fn verify(
    der: &[u8],
    algorithm: SignatureKeyAlgorithm,
    signature: &[u8],
    payload: &[u8],
) -> Result<bool> {
    let cert = <tav_crypto::Crypto as CertificateBackend>::from_der(der)
        .map_err(|e| Error::Crypto(format!("the signer's certificate is not valid DER: {e}")))?;
    let spki = <tav_crypto::Crypto as CertificateBackend>::get_public_key(&cert)
        .map_err(|e| Error::Crypto(format!("could not read the signer's public key: {e}")))?;
    let key = <tav_crypto::Key as KeyBackend>::from_spki_der(&spki, algorithm)
        .map_err(|e| Error::Crypto(format!("could not import the signer's public key: {e}")))?;

    // A signature of the wrong length or shape for the declared algorithm is a
    // failed check, not an unanswerable one: the producer said what this is,
    // and it is not that.
    let Ok(signature) =
        <tav_crypto::Signature as SignatureBackend>::from_bytes(signature, algorithm)
    else {
        return Ok(false);
    };

    Ok(<tav_crypto::Crypto as CryptoBackend>::verify_signature(&key, &signature, payload).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: Vec<(i64, CborValue)>) -> CborValue {
        CborValue::Map(
            entries
                .into_iter()
                .map(|(k, v)| (CborValue::Int(k), v))
                .collect(),
        )
    }

    fn unusable(d: Detached) -> String {
        match d {
            Detached::Unusable(why) => why,
            other => panic!("expected unusable, got {other:?}"),
        }
    }

    /// A descriptor missing any of its three parts is unanswerable, not a
    /// failure. Reporting these as failures would put a forgery in the report
    /// every time a producer omitted a field.
    #[test]
    fn an_incomplete_descriptor_cannot_be_evaluated() {
        let cert = CborValue::Array(vec![CborValue::ByteString(vec![0x30, 0x82])]);
        let sig = CborValue::ByteString(vec![0u8; 384]);

        let no_alg = map(vec![
            (labels::X5CHAIN, cert.clone()),
            (labels::DETACHED_SIGNATURE, sig.clone()),
        ]);
        assert!(unusable(verify_detached(&no_alg, Some(b"x"))).contains("no algorithm"));

        let no_sig = map(vec![
            (labels::ALG, CborValue::Int(labels::alg::RS256)),
            (labels::X5CHAIN, cert),
        ]);
        assert!(unusable(verify_detached(&no_sig, Some(b"x"))).contains("no signature"));

        let no_cert = map(vec![
            (labels::ALG, CborValue::Int(labels::alg::RS256)),
            (labels::DETACHED_SIGNATURE, sig),
        ]);
        assert!(unusable(verify_detached(&no_cert, Some(b"x"))).contains("no certificate"));
    }

    /// An algorithm this build cannot compute is a gap in the tool, not a
    /// verdict about the statement.
    #[test]
    fn an_unsupported_algorithm_cannot_be_evaluated() {
        let descriptor = map(vec![
            (labels::ALG, CborValue::Int(-8)),
            (
                labels::X5CHAIN,
                CborValue::Array(vec![CborValue::ByteString(vec![0x30])]),
            ),
            (
                labels::DETACHED_SIGNATURE,
                CborValue::ByteString(vec![0; 64]),
            ),
        ]);
        let why = unusable(verify_detached(&descriptor, Some(b"x")));
        assert!(why.contains("EdDSA"), "{why}");
        assert!(
            why.contains("not an algorithm this build can verify"),
            "{why}"
        );
    }

    /// With no payload there is nothing to check against, and assuming empty
    /// bytes would ask a different question than the policy asked.
    #[test]
    fn a_detached_payload_cannot_be_evaluated() {
        let descriptor = map(vec![(labels::ALG, CborValue::Int(labels::alg::RS256))]);
        assert!(unusable(verify_detached(&descriptor, None)).contains("detached"));
    }

    /// Certificate bytes that are not a certificate are unanswerable rather
    /// than a failed signature: no key was ever obtained to check against.
    #[test]
    fn a_malformed_certificate_cannot_be_evaluated() {
        let descriptor = map(vec![
            (labels::ALG, CborValue::Int(labels::alg::RS256)),
            (
                labels::X5CHAIN,
                CborValue::Array(vec![CborValue::ByteString(b"not a certificate".to_vec())]),
            ),
            (
                labels::DETACHED_SIGNATURE,
                CborValue::ByteString(vec![0; 384]),
            ),
        ]);
        assert!(unusable(verify_detached(&descriptor, Some(b"x"))).contains("valid DER"));
    }

    /// RS256 is the algorithm on essentially every detached supplier
    /// signature, and the upstream COSE mapping omits it. A guard, because
    /// losing it would turn every such check into `cannotEvaluate` — which
    /// reads as "nothing is wrong" rather than as a regression.
    #[test]
    fn rsa_pkcs1_algorithms_are_mapped() {
        for alg in [labels::alg::RS256, -258, -259] {
            assert!(
                key_algorithm(alg).is_some(),
                "{} ({alg}) must be verifiable",
                labels::alg::name(alg)
            );
        }
    }
}
