//! `did:x509` issuer resolution.
//!
//! A `did:x509` identifier pins a certificate authority by hash and then
//! states predicates the leaf certificate must satisfy. Both halves matter:
//! the fingerprint says *which* CA, the predicates say *which signer under
//! it*. Checking one without the other is not a weaker version of the check,
//! it is a different and much emptier one.
//!
//! ## Why this is not simply a string comparison
//!
//! `signerSubjectContains` reads a name out of the certificate the statement
//! carries — the same certificate a forger chooses. A `did:x509` is different
//! in kind: the fingerprint commits to a CA certificate's bytes, so it cannot
//! be satisfied by minting a new leaf. That is only true once the chain has
//! been validated, because otherwise the CA certificate named by the
//! fingerprint need not have issued anything. See [`crate::chain`].
//!
//! ## The index that is easy to get wrong
//!
//! The fingerprint identifies **any non-leaf certificate in the chain**, not a
//! fixed position. Real chains differ:
//!
//! | Chain | Fingerprint matches |
//! | --- | --- |
//! | 2-cert, self-signed CA | index 1 |
//! | Microsoft ESRP / Code Transparency Service, 3-cert | index **2** |
//!
//! Hard-coding index 1 passes the two-certificate case and silently rejects
//! every production Microsoft statement. The reference implementation
//! (`didx509cpp.h`, vendored in CCF) scans `for (size_t i = 1; i < chain.size();
//! i++)`, and this module does the same.

use crate::der;
use crate::error::{Error, Result};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tav_crypto::base64::base64_encode_no_padding;
use tav_crypto::CertificateBackend;

/// OID of the `extKeyUsage` extension (RFC 5280 §4.2.1.12).
const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";

/// A parsed `did:x509` identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidX509 {
    /// `sha256`, `sha384`, or `sha512`.
    pub fingerprint_alg: String,
    /// Base64url, unpadded, of the CA certificate digest.
    pub fingerprint: String,
    /// Predicates in the order they appeared, as `(name, value)`.
    pub predicates: Vec<(String, String)>,
}

/// Whether a string looks like a `did:x509`, without committing to it parsing.
pub fn is_did_x509(did: &str) -> bool {
    did.starts_with("did:x509:")
}

/// Parse a `did:x509` identifier.
///
/// Version `0` is the only one defined, and an unrecognised version is
/// rejected rather than parsed optimistically: a future version could change
/// what the fingerprint covers, and treating it as version 0 would check the
/// wrong thing while reporting success.
pub fn parse(did: &str) -> Result<DidX509> {
    const PREFIX: &str = "did:x509:0:";
    let Some(rest) = did.strip_prefix(PREFIX) else {
        return Err(Error::TrustMaterial(format!(
            "issuer '{did}' is not a did:x509 version 0 identifier"
        )));
    };

    let mut sections = rest.split("::");
    let anchor = sections.next().unwrap_or_default();

    let Some((fingerprint_alg, fingerprint)) = anchor.split_once(':') else {
        return Err(Error::TrustMaterial(
            "did:x509 is missing its CA fingerprint algorithm or value".into(),
        ));
    };
    if !matches!(fingerprint_alg, "sha256" | "sha384" | "sha512") {
        return Err(Error::TrustMaterial(format!(
            "did:x509 CA fingerprint algorithm '{fingerprint_alg}' is not one of sha256, sha384, sha512"
        )));
    }
    if fingerprint.is_empty() {
        return Err(Error::TrustMaterial(
            "did:x509 CA fingerprint is empty".into(),
        ));
    }

    let mut predicates = Vec::new();
    for section in sections {
        // The value may itself contain ':' — `subject:CN:foo` — so only the
        // first separator delimits the predicate name.
        let Some((name, value)) = section.split_once(':') else {
            return Err(Error::TrustMaterial(format!(
                "did:x509 predicate '{section}' has no value"
            )));
        };
        predicates.push((name.to_string(), value.to_string()));
    }

    // A did:x509 with no predicates would assert only "somewhere under this
    // CA", which is almost never what an author means and is not permitted by
    // the grammar (`1*("::" predicate-name ":" predicate-value)`).
    if predicates.is_empty() {
        return Err(Error::TrustMaterial(
            "did:x509 carries no predicates, so it constrains only the CA and not the signer"
                .into(),
        ));
    }

    Ok(DidX509 {
        fingerprint_alg: fingerprint_alg.to_string(),
        fingerprint: fingerprint.to_string(),
        predicates,
    })
}

/// The outcome of matching a `did:x509` against a certificate chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The fingerprint matched a non-leaf certificate and every predicate held.
    Matched {
        /// Index in `x5chain` of the certificate the fingerprint identified.
        ca_index: usize,
    },
    /// The identifier is well-formed but does not describe this chain.
    Mismatch(String),
    /// The identifier uses something this build does not implement.
    ///
    /// Kept apart from [`Self::Mismatch`] on purpose. "I checked and it does
    /// not match" and "I do not know how to check this" must never collapse
    /// into the same report, because only one of them is evidence.
    Unsupported(String),
}

impl Resolution {
    pub fn matched(&self) -> bool {
        matches!(self, Self::Matched { .. })
    }
}

/// Match a parsed `did:x509` against a chain, leaf first.
///
/// This establishes only that the identifier *describes* the chain. It does
/// not establish that the chain is valid; run [`crate::chain::validate`] for
/// that. A fingerprint match over an unvalidated chain is worth nothing,
/// because nothing yet connects the named CA to the leaf that signed.
pub fn resolve(did: &DidX509, chain: &[Vec<u8>]) -> Result<Resolution> {
    // The grammar requires a CA distinct from the leaf, so a bare certificate
    // can never satisfy one. Reported as a mismatch rather than an error: the
    // chain is well-formed, it simply cannot be what the identifier describes.
    if chain.len() < 2 {
        return Ok(Resolution::Mismatch(format!(
            "did:x509 names a CA certificate, but the chain holds {} certificate(s); \
             at least a leaf and its issuer are required",
            chain.len()
        )));
    }

    let Some(ca_index) = find_ca(did, chain) else {
        return Ok(Resolution::Mismatch(format!(
            "no non-leaf certificate in the chain has {} fingerprint {}",
            did.fingerprint_alg, did.fingerprint
        )));
    };

    // `parse` refuses a predicate-less identifier, but `DidX509` can also be
    // built field by field. Re-checked here because the loop below is a no-op
    // on an empty list: a CA-only constraint would otherwise resolve as a
    // match, pinning the authority while asserting nothing about the leaf, and
    // any certificate that CA ever issued would satisfy it.
    if did.predicates.is_empty() {
        return Err(Error::TrustMaterial(
            "did:x509 carries no predicates, so it constrains only the CA and not the signer"
                .into(),
        ));
    }

    let leaf = &chain[0];
    for (name, value) in &did.predicates {
        match check_predicate(name, value, leaf)? {
            Resolution::Matched { .. } => {}
            other => return Ok(other),
        }
    }

    Ok(Resolution::Matched { ca_index })
}

/// Find the non-leaf certificate the fingerprint identifies.
///
/// Scans every index from 1 upward. See the module comment for why this must
/// not be pinned to index 1.
fn find_ca(did: &DidX509, chain: &[Vec<u8>]) -> Option<usize> {
    chain.iter().enumerate().skip(1).find_map(|(index, der)| {
        let digest = match did.fingerprint_alg.as_str() {
            "sha256" => Sha256::digest(der).to_vec(),
            "sha384" => Sha384::digest(der).to_vec(),
            "sha512" => Sha512::digest(der).to_vec(),
            _ => return None,
        };
        (base64_encode_no_padding(&digest) == did.fingerprint).then_some(index)
    })
}

/// Evaluate one predicate against the leaf certificate.
fn check_predicate(name: &str, value: &str, leaf_der: &[u8]) -> Result<Resolution> {
    match name {
        "eku" => check_eku(value, leaf_der),
        "subject" => check_subject(value, leaf_der),
        // Deliberately not implemented. `san` needs GeneralName decoding and
        // `fulcio-issuer` a Sigstore-specific extension; guessing at either
        // could turn a predicate that does not hold into one that appears to.
        // Refusing is the only outcome that cannot mislead.
        "san" | "fulcio-issuer" => Ok(Resolution::Unsupported(format!(
            "did:x509 predicate '{name}' is not implemented by this build"
        ))),
        other => Ok(Resolution::Unsupported(format!(
            "did:x509 predicate '{other}' is not defined by the method specification"
        ))),
    }
}

/// `eku` holds when the OID is among the leaf's extended key usages.
fn check_eku(value: &str, leaf_der: &[u8]) -> Result<Resolution> {
    let leaf = <tav_crypto::Crypto as CertificateBackend>::from_der(leaf_der)
        .map_err(|e| Error::Crypto(format!("leaf certificate is not valid DER: {e}")))?;
    let extension = <tav_crypto::Crypto as CertificateBackend>::get_extension_value_by_oid(
        &leaf,
        OID_EXTENDED_KEY_USAGE,
    )
    .map_err(|e| Error::Crypto(format!("could not read leaf extendedKeyUsage: {e}")))?;

    let Some(extension) = extension else {
        return Ok(Resolution::Mismatch(
            "did:x509 requires an extendedKeyUsage, but the leaf certificate has none".into(),
        ));
    };

    let oids = der::parse_eku_oids(&extension);
    if oids.iter().any(|oid| oid == value) {
        Ok(Resolution::Matched { ca_index: 0 })
    } else {
        Ok(Resolution::Mismatch(format!(
            "did:x509 requires extendedKeyUsage {value}, but the leaf certificate has [{}]",
            oids.join(", ")
        )))
    }
}

/// `subject` holds when every named attribute appears in the leaf's subject.
///
/// The specification's Rego uses `object.subset`, so the predicate is a subset
/// test and not equality: naming `CN` alone matches a subject that also
/// carries `O` and `C`.
fn check_subject(value: &str, leaf_der: &[u8]) -> Result<Resolution> {
    let leaf = <tav_crypto::Crypto as CertificateBackend>::from_der(leaf_der)
        .map_err(|e| Error::Crypto(format!("leaf certificate is not valid DER: {e}")))?;
    let subject_der = <tav_crypto::Crypto as CertificateBackend>::subject_name_der(&leaf)
        .map_err(|e| Error::Crypto(format!("could not read leaf subject: {e}")))?;
    let actual = der::parse_name_attributes(&subject_der);

    let items: Vec<&str> = value.split(':').collect();
    if items.is_empty() || items.len() % 2 != 0 {
        return Ok(Resolution::Mismatch(
            "did:x509 subject predicate is not a sequence of key:value pairs".into(),
        ));
    }

    let mut seen: Vec<&str> = Vec::new();
    for pair in items.chunks(2) {
        let (key, encoded) = (pair[0], pair[1]);
        // The specification forbids repeating a key; allowing it would make
        // the predicate's meaning depend on which occurrence won.
        if seen.contains(&key) {
            return Ok(Resolution::Mismatch(format!(
                "did:x509 subject predicate names '{key}' more than once"
            )));
        }
        seen.push(key);

        let Some(wanted) = percent_decode(encoded) else {
            return Ok(Resolution::Mismatch(format!(
                "did:x509 subject value for '{key}' is not valid percent-encoding"
            )));
        };
        if !actual.iter().any(|(k, v)| k == key && *v == wanted) {
            return Ok(Resolution::Mismatch(format!(
                "did:x509 requires subject {key}={wanted}, which the leaf certificate does not have"
            )));
        }
    }

    Ok(Resolution::Matched { ca_index: 0 })
}

/// Decode percent-encoding, rejecting malformed escapes.
///
/// Returns `None` rather than passing an invalid escape through, so that a
/// value like `%zz` cannot end up compared literally and quietly failing to
/// match for the wrong reason.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = value.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS_ROOT_FINGERPRINT: &str = "I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s";

    #[test]
    fn parses_a_real_code_transparency_service_identifier() {
        let did = parse(&format!(
            "did:x509:0:sha256:{MS_ROOT_FINGERPRINT}::eku:1.3.6.1.4.1.311.76.59.1.14"
        ))
        .unwrap();
        assert_eq!(did.fingerprint_alg, "sha256");
        assert_eq!(did.fingerprint, MS_ROOT_FINGERPRINT);
        assert_eq!(
            did.predicates,
            vec![("eku".to_string(), "1.3.6.1.4.1.311.76.59.1.14".to_string())]
        );
    }

    #[test]
    fn parses_multiple_predicates_and_values_containing_colons() {
        let did = parse("did:x509:0:sha256:abc::subject:C:US:O:Example%20Org::eku:1.2.3").unwrap();
        assert_eq!(
            did.predicates,
            vec![
                ("subject".to_string(), "C:US:O:Example%20Org".to_string()),
                ("eku".to_string(), "1.2.3".to_string()),
            ]
        );
    }

    #[test]
    fn rejects_malformed_identifiers() {
        assert!(parse("did:web:example.com").is_err());
        assert!(
            parse("did:x509:1:sha256:abc::eku:1.2.3").is_err(),
            "version 1"
        );
        assert!(parse("did:x509:0:md5:abc::eku:1.2.3").is_err(), "hash alg");
        assert!(parse("did:x509:0:sha256:::eku:1.2.3").is_err(), "empty fp");
        assert!(parse("did:x509:0:sha256:abc").is_err(), "no predicates");
        assert!(parse("did:x509:0:sha256:abc::eku").is_err(), "valueless");
    }

    #[test]
    fn percent_decoding_round_trips_and_rejects_bad_escapes() {
        assert_eq!(percent_decode("Example%20Org").unwrap(), "Example Org");
        assert_eq!(percent_decode("plain").unwrap(), "plain");
        assert_eq!(percent_decode("%2F").unwrap(), "/");
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%2"), None);
    }

    #[test]
    fn a_chain_shorter_than_two_cannot_satisfy_any_identifier() {
        let did = parse("did:x509:0:sha256:abc::eku:1.2.3").unwrap();
        let resolution = resolve(&did, &[vec![0x30, 0x00]]).unwrap();
        assert!(matches!(resolution, Resolution::Mismatch(_)));
        assert!(!resolve(&did, &[]).unwrap().matched());
    }

    /// The whole point of the module: the fingerprint is found wherever it
    /// sits above the leaf, not at a fixed index.
    #[test]
    fn the_fingerprint_is_matched_at_any_non_leaf_index() {
        let certs: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 8]).collect();
        for target in 1..certs.len() {
            let fingerprint = base64_encode_no_padding(&Sha256::digest(&certs[target]));
            let did = DidX509 {
                fingerprint_alg: "sha256".into(),
                fingerprint,
                predicates: Vec::new(),
            };
            assert_eq!(find_ca(&did, &certs), Some(target));
        }
    }

    /// A chain whose *leaf* hashes to the fingerprint must not match. The
    /// fingerprint names a certificate authority; letting the leaf answer for
    /// `parse` refuses a predicate-less identifier, but the struct is public
    /// and can be built field by field. A CA-only constraint pins the
    /// authority and says nothing about the signer, so every certificate that
    /// CA ever issued would satisfy it.
    #[test]
    fn a_predicate_less_identifier_is_refused_at_resolution_too() {
        let certs: Vec<Vec<u8>> = vec![vec![9; 8], vec![1; 8]];
        let did = DidX509 {
            fingerprint_alg: "sha256".into(),
            fingerprint: base64_encode_no_padding(&Sha256::digest(&certs[1])),
            predicates: Vec::new(),
        };
        assert!(resolve(&did, &certs).is_err());
    }

    /// it would let any signer pin itself.
    #[test]
    fn the_leaf_is_never_accepted_as_the_certificate_authority() {
        let certs: Vec<Vec<u8>> = vec![vec![9; 8], vec![1; 8]];
        let did = DidX509 {
            fingerprint_alg: "sha256".into(),
            fingerprint: base64_encode_no_padding(&Sha256::digest(&certs[0])),
            predicates: Vec::new(),
        };
        assert_eq!(find_ca(&did, &certs), None);
    }

    #[test]
    fn unimplemented_predicates_are_refused_rather_than_failed() {
        let leaf = vec![0x30, 0x00];
        assert!(matches!(
            check_predicate("san", "dns:example.com", &leaf).unwrap(),
            Resolution::Unsupported(_)
        ));
        assert!(matches!(
            check_predicate("fulcio-issuer", "accounts.google.com", &leaf).unwrap(),
            Resolution::Unsupported(_)
        ));
        assert!(matches!(
            check_predicate("invented", "x", &leaf).unwrap(),
            Resolution::Unsupported(_)
        ));
    }
}
