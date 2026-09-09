//! The transparent statement: a COSE_Sign1 with receipts attached.

use crate::cbor::{self, hex};
use crate::error::{Error, Result};
use crate::labels;
use sha2::{Digest, Sha256};
use tav_cose::CborValue;
use tav_crypto::{CertificateBackend, KeyBackend};

/// COSE_Sign1 CBOR tag.
pub const COSE_SIGN1_TAG: u64 = 18;

/// A parsed COSE_Sign1.
#[derive(Debug, Clone)]
pub struct Sign1 {
    pub was_tagged: bool,
    /// The protected bucket exactly as it appeared on the wire.
    ///
    /// Never re-encoded: the signature is over these bytes, so a canonicalising
    /// round-trip here would be a correctness bug even if it usually round-trips.
    pub protected_raw: Vec<u8>,
    pub protected: CborValue,
    pub unprotected: CborValue,
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl Sign1 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = CborValue::from_bytes(bytes)
            .map_err(|e| Error::Malformed(format!("not valid CBOR: {e:?}")))?;

        let (was_tagged, inner) = match value {
            CborValue::Tagged { tag, payload } if tag == COSE_SIGN1_TAG => (true, *payload),
            CborValue::Tagged { tag, .. } => {
                return Err(Error::Malformed(format!(
                    "CBOR tag {tag} is not COSE_Sign1 ({COSE_SIGN1_TAG})"
                )))
            }
            other => (false, other),
        };

        let items = cbor::as_array(&inner)
            .map_err(|_| Error::Malformed("COSE_Sign1 must be an array".into()))?;
        if items.len() != 4 {
            return Err(Error::Malformed(format!(
                "COSE_Sign1 must have 4 elements, found {}",
                items.len()
            )));
        }

        let protected_raw = cbor::as_bytes(&items[0])
            .map_err(|_| Error::Malformed("protected bucket must be a byte string".into()))?
            .to_vec();

        // An empty protected bucket is legal CBOR-wise but means the algorithm
        // is unauthenticated, which is not something a verifier should accept.
        let protected = if protected_raw.is_empty() {
            CborValue::Map(Vec::new())
        } else {
            CborValue::from_bytes(&protected_raw)
                .map_err(|e| Error::Malformed(format!("protected bucket is not CBOR: {e:?}")))?
        };

        let payload = match &items[2] {
            CborValue::ByteString(b) => Some(b.clone()),
            CborValue::Simple(_) => None, // detached
            other => {
                return Err(Error::Malformed(format!(
                    "payload must be bstr or nil, got {}",
                    cbor::type_name(other)
                )))
            }
        };

        let signature = cbor::as_bytes(&items[3])
            .map_err(|_| Error::Malformed("signature must be a byte string".into()))?
            .to_vec();

        Ok(Self {
            was_tagged,
            protected_raw,
            protected,
            unprotected: items[1].clone(),
            payload,
            signature,
        })
    }

    pub fn alg(&self) -> Result<i64> {
        cbor::opt_int_key(&self.protected, labels::ALG)
            .ok_or_else(|| Error::Malformed("protected headers carry no alg".into()))
            .and_then(cbor::as_int)
    }

    pub fn kid(&self) -> Option<String> {
        cbor::opt_int_key(&self.protected, labels::KID)
            .and_then(|v| cbor::as_kid(v).ok())
            .or_else(|| {
                cbor::opt_int_key(&self.unprotected, labels::KID).and_then(|v| cbor::as_kid(v).ok())
            })
    }

    /// CWT claims from the protected bucket, if present.
    pub fn cwt(&self) -> Option<CwtClaims> {
        let claims = cbor::opt_int_key(&self.protected, labels::CWT_CLAIMS)?;
        Some(CwtClaims {
            iss: cbor::opt_int_key(claims, labels::CWT_ISS)
                .and_then(|v| cbor::as_text(v).ok())
                .map(str::to_owned),
            sub: cbor::opt_int_key(claims, labels::CWT_SUB)
                .and_then(|v| cbor::as_text(v).ok())
                .map(str::to_owned),
            iat: cbor::opt_int_key(claims, labels::CWT_IAT)
                .and_then(|v| cbor::as_numeric_date(v).ok()),
            nbf: cbor::opt_int_key(claims, labels::CWT_NBF)
                .and_then(|v| cbor::as_numeric_date(v).ok()),
            exp: cbor::opt_int_key(claims, labels::CWT_EXP)
                .and_then(|v| cbor::as_numeric_date(v).ok()),
            svn: cbor::opt_text_key(claims, labels::CWT_SVN).and_then(|v| cbor::as_int(v).ok()),
            other: other_cwt_claims(claims),
        })
    }

    /// The declared media type of the payload, from the protected `cty` header.
    ///
    /// May be a string (`application/json`) or an integer from the CoAP
    /// Content-Format registry, which is why this returns text either way.
    pub fn content_type(&self) -> Option<String> {
        match cbor::opt_int_key(&self.protected, labels::CONTENT_TYPE)? {
            CborValue::TextString(s) => Some(s.clone()),
            CborValue::Int(i) => Some(format!("coap-content-format({i})")),
            _ => None,
        }
    }

    /// The COSE Hash Envelope payload hash algorithm (RFC 9995 label 258), if
    /// this statement is a hash envelope.
    ///
    /// Read from the **protected** bucket only. RFC 9995 §4 requires label 258
    /// there and forbids it in the unprotected bucket, and the reason is not
    /// pedantry: an attacker who could add an unprotected 258 would be choosing
    /// the hash function used to check the artifact.
    pub fn payload_hash_alg(&self) -> Option<i64> {
        cbor::opt_int_key(&self.protected, labels::PAYLOAD_HASH_ALG)
            .and_then(|v| cbor::as_int(v).ok())
    }

    /// Whether this statement is a COSE Hash Envelope — that is, whether its
    /// payload is a digest of some other resource rather than the resource.
    ///
    /// Label 258's presence is the discriminator, so a caller never has to be
    /// told which shape it is holding.
    pub fn is_hash_envelope(&self) -> bool {
        self.payload_hash_alg().is_some()
    }

    /// The content type of the bytes that were hashed (RFC 9995 label 259).
    ///
    /// This is *not* [`Self::content_type`]. Label 3 describes the payload,
    /// which in a hash envelope is a digest; label 259 describes the preimage.
    pub fn payload_preimage_content_type(&self) -> Option<String> {
        match cbor::opt_int_key(&self.protected, labels::PAYLOAD_PREIMAGE_CONTENT_TYPE)? {
            CborValue::TextString(s) => Some(s.clone()),
            CborValue::Int(i) => Some(format!("coap-content-format({i})")),
            _ => None,
        }
    }

    /// Where the preimage can be retrieved from (RFC 9995 label 260).
    ///
    /// A hint for a human. This tool is offline and will never fetch it.
    pub fn payload_location(&self) -> Option<String> {
        match cbor::opt_int_key(&self.protected, labels::PAYLOAD_LOCATION)? {
            CborValue::TextString(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// The `x5t` certificate thumbprint: the COSE hash algorithm and the digest.
    pub fn x5t(&self) -> Option<(i64, String)> {
        let value = cbor::opt_int_key(&self.protected, labels::X5T)?;
        let items = cbor::as_array(value).ok()?;
        if items.len() != 2 {
            return None;
        }
        let alg = cbor::as_int(&items[0]).ok()?;
        let digest = cbor::as_bytes(&items[1]).ok()?;
        Some((alg, hex(digest)))
    }

    /// Every label present in a header bucket, in wire order.
    ///
    /// Reported so that a reader can see headers this build does not interpret.
    /// A field nobody parses is exactly the field an attacker hopes nobody
    /// looks at.
    pub fn header_labels(bucket: &CborValue) -> Vec<String> {
        match bucket {
            CborValue::Map(entries) => entries
                .iter()
                .map(|(k, _)| match k {
                    CborValue::Int(i) => match labels::header_name(*i) {
                        Some(name) => format!("{i} ({name})"),
                        None => format!("{i} (not interpreted)"),
                    },
                    CborValue::TextString(s) => s.clone(),
                    other => cbor::type_name(other).to_string(),
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The DER certificate chain from the protected `x5chain` header, leaf first.
    pub fn x5chain(&self) -> Vec<Vec<u8>> {
        let Some(value) = cbor::opt_int_key(&self.protected, labels::X5CHAIN) else {
            return Vec::new();
        };
        match value {
            // A single certificate may be encoded bare rather than in an array.
            CborValue::ByteString(b) => vec![b.clone()],
            CborValue::Array(items) => items
                .iter()
                .filter_map(|i| cbor::as_bytes(i).ok().map(<[u8]>::to_vec))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Every receipt in the unprotected bucket.
    ///
    /// Returns all of them. A statement registered with more than one
    /// transparency service carries more than one receipt, and silently reading
    /// only the first would let a single weak service satisfy a policy that
    /// asked for two.
    pub fn receipts(&self) -> Vec<Vec<u8>> {
        let Some(value) = cbor::opt_int_key(&self.unprotected, labels::RECEIPTS) else {
            return Vec::new();
        };
        match value {
            CborValue::Array(items) => items
                .iter()
                .filter_map(|i| cbor::as_bytes(i).ok().map(<[u8]>::to_vec))
                .collect(),
            CborValue::ByteString(b) => vec![b.clone()],
            _ => Vec::new(),
        }
    }

    /// Re-encode this COSE_Sign1 with an empty unprotected bucket.
    ///
    /// This is the *signed statement*: the bytes the transparency service
    /// hashed at registration time. Receipts are added to the unprotected
    /// bucket afterwards, so they must be removed before hashing — otherwise
    /// the digest changes the moment a receipt is attached.
    pub fn signed_statement_bytes(&self) -> Result<Vec<u8>> {
        let inner = CborValue::Array(vec![
            CborValue::ByteString(self.protected_raw.clone()),
            CborValue::Map(Vec::new()),
            match &self.payload {
                Some(p) => CborValue::ByteString(p.clone()),
                None => CborValue::Simple(22), // null
            },
            CborValue::ByteString(self.signature.clone()),
        ]);

        let value = if self.was_tagged {
            CborValue::Tagged {
                tag: COSE_SIGN1_TAG,
                payload: Box::new(inner),
            }
        } else {
            inner
        };

        value
            .to_bytes()
            .map_err(|e| Error::Structure(format!("could not re-encode statement: {e:?}")))
    }

    /// SHA-256 over the signed statement bytes.
    ///
    /// This is what the receipt commits to. If it does not match the receipt's
    /// `claims_digest`, the receipt belongs to a different statement, however
    /// valid it is on its own.
    pub fn claim_digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.signed_statement_bytes()?).into())
    }

    /// Verify the issuer's signature over the statement.
    ///
    /// Only the signature is checked here. Whether the signing certificate is
    /// one you trust is a policy question, answered elsewhere.
    pub fn verify_signature(&self, spki_der: &[u8]) -> Result<bool> {
        let alg = self.alg()?;
        let algorithm = tav_cose::signature_key_algorithm_for_cose_alg(alg)
            .map_err(|_| Error::UnsupportedAlgorithm(alg))?;
        let key = <tav_crypto::Key as KeyBackend>::from_spki_der(spki_der, algorithm)
            .map_err(|e| Error::Crypto(format!("could not import public key: {e}")))?;

        let payload = self
            .payload
            .as_deref()
            .ok_or_else(|| Error::Structure("statement payload is detached".into()))?;

        Ok(tav_cose::synchronous::cose_verify1(
            &key,
            algorithm,
            &self.protected_raw,
            payload,
            &self.signature,
        )
        .is_ok())
    }

    /// SPKI of the leaf certificate in `x5chain`, if there is one.
    pub fn leaf_spki(&self) -> Result<Option<Vec<u8>>> {
        let chain = self.x5chain();
        let Some(leaf_der) = chain.first() else {
            return Ok(None);
        };
        let leaf = <tav_crypto::Crypto as CertificateBackend>::from_der(leaf_der)
            .map_err(|e| Error::Crypto(format!("leaf certificate is not valid DER: {e}")))?;
        let spki = <tav_crypto::Crypto as CertificateBackend>::get_public_key(&leaf)
            .map_err(|e| Error::Crypto(format!("could not read leaf public key: {e}")))?;
        Ok(Some(spki))
    }

    /// Subject and issuer names of the leaf certificate, for reporting.
    pub fn leaf_names(&self) -> Result<Option<(String, String)>> {
        let chain = self.x5chain();
        let Some(leaf_der) = chain.first() else {
            return Ok(None);
        };
        let leaf = <tav_crypto::Crypto as CertificateBackend>::from_der(leaf_der)
            .map_err(|e| Error::Crypto(format!("leaf certificate is not valid DER: {e}")))?;
        Ok(Some((
            <tav_crypto::Crypto as CertificateBackend>::subject_name(&leaf),
            <tav_crypto::Crypto as CertificateBackend>::issuer_name(&leaf),
        )))
    }

    /// Describe every certificate in `x5chain`, leaf first.
    ///
    /// Reporting only. Nothing here is a trust decision: a chain can be fully
    /// described and still end in a root nobody should accept.
    pub fn describe_chain(&self) -> Vec<CertificateSummary> {
        self.x5chain()
            .iter()
            .enumerate()
            .map(|(index, der)| describe_certificate(index, der))
            .collect()
    }
}

/// What a certificate says about itself.
#[derive(Debug, Clone, Default)]
pub struct CertificateSummary {
    pub index: usize,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    /// SHA-256 over the DER, the value most tools call a thumbprint.
    pub sha256: String,
    /// Zero-based X.509 version: 2 means v3.
    pub version: Option<u8>,
    pub extended_key_usage: Vec<String>,
    /// Whether the EKU extension is marked critical.
    ///
    /// Worth surfacing because a *critical* EKU is one of the critical
    /// extensions this build's chain policy does not handle, and a chain
    /// carrying one will be rejected at verify time.
    pub eku_critical: Option<bool>,
    /// `basicConstraints` as `(critical, ca, path_len_constraint)`.
    pub basic_constraints: Option<(bool, bool, Option<usize>)>,
    /// Whether `keyUsage` asserts `keyCertSign`.
    pub key_cert_sign: Option<bool>,
    /// Critical extensions the chain policy does not implement.
    ///
    /// Non-empty means `verify` will reject this chain, and this is the only
    /// place a reader can find that out before trying.
    pub unhandled_critical_extensions: Vec<String>,
    /// Why this certificate could not be described, if it could not be.
    pub problem: Option<String>,
}

/// Critical extensions the chain policy in `tav-crypto` implements.
///
/// Mirrors that crate's own list. Kept here so `inspect` can warn about a
/// chain `verify` will refuse; if the upstream list grows, this one is stale
/// in the safe direction — it over-reports rather than under-reports.
const HANDLED_CRITICAL_EXTENSIONS: &[&str] = &[
    "2.5.29.19", // basicConstraints
    "2.5.29.15", // keyUsage
];

pub fn describe_certificate(index: usize, der: &[u8]) -> CertificateSummary {
    let mut summary = CertificateSummary {
        index,
        sha256: hex(&Sha256::digest(der)),
        ..Default::default()
    };

    let cert = match <tav_crypto::Crypto as CertificateBackend>::from_der(der) {
        Ok(c) => c,
        Err(e) => {
            summary.problem = Some(format!("not valid DER: {e}"));
            return summary;
        }
    };

    summary.subject = Some(<tav_crypto::Crypto as CertificateBackend>::subject_name(
        &cert,
    ));
    summary.issuer = Some(<tav_crypto::Crypto as CertificateBackend>::issuer_name(
        &cert,
    ));
    summary.version = <tav_crypto::Crypto as CertificateBackend>::version(&cert).ok();
    summary.basic_constraints =
        <tav_crypto::Crypto as CertificateBackend>::basic_constraints(&cert)
            .ok()
            .flatten()
            .map(|bc| (bc.critical, bc.ca, bc.path_len_constraint));
    summary.key_cert_sign = <tav_crypto::Crypto as CertificateBackend>::key_usage(&cert)
        .ok()
        .flatten()
        .map(|ku| ku.key_cert_sign);
    summary.eku_critical = <tav_crypto::Crypto as CertificateBackend>::extension_criticality(
        &cert,
        labels::OID_EXTENDED_KEY_USAGE,
    )
    .ok()
    .flatten();

    summary.unhandled_critical_extensions =
        <tav_crypto::Crypto as CertificateBackend>::critical_extension_oids(&cert)
            .into_iter()
            .filter(|oid| !HANDLED_CRITICAL_EXTENSIONS.contains(&oid.as_str()))
            .collect();

    if let Ok(Some(raw)) = <tav_crypto::Crypto as CertificateBackend>::get_extension_value_by_oid(
        &cert,
        labels::OID_EXTENDED_KEY_USAGE,
    ) {
        summary.extended_key_usage = crate::der::parse_eku_oids(&raw);
    }

    summary
}

/// Facts asserted by the issuer in the CWT claims header.
///
/// These are *claims*, not conclusions. `iss` says who the signer says it is;
/// believing it requires the signature to verify and the certificate to be
/// trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CwtClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub exp: Option<i64>,
    pub svn: Option<i64>,
    /// Claims this build does not interpret, as `(label, rendered value)`.
    ///
    /// Kept rather than dropped. An issuer that puts something load-bearing in
    /// a private claim is telling a reader something, and a tool that silently
    /// discards it reports a smaller statement than the one it was given.
    pub other: Vec<(String, String)>,
}

/// Claims outside the set this crate names, rendered for display.
fn other_cwt_claims(claims: &CborValue) -> Vec<(String, String)> {
    let CborValue::Map(entries) = claims else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|(k, v)| {
            let label = match k {
                CborValue::Int(i) => {
                    if labels::cwt_claim_name(*i).is_some() {
                        return None;
                    }
                    i.to_string()
                }
                CborValue::TextString(s) => {
                    if s == labels::CWT_SVN {
                        return None;
                    }
                    s.clone()
                }
                other => cbor::type_name(other).to_string(),
            };
            Some((label, render_scalar(v)))
        })
        .collect()
}

/// A compact, non-recursive rendering of a CBOR value for reporting.
///
/// Containers are summarised rather than expanded: this is used for claims
/// whose meaning is unknown, and printing an unbounded nested structure into a
/// CI log is how a fifteen-line report becomes a thousand.
pub fn render_scalar(v: &CborValue) -> String {
    match v {
        CborValue::Int(i) => i.to_string(),
        CborValue::TextString(s) => s.clone(),
        CborValue::ByteString(b) => format!("{} bytes: {}", b.len(), hex_prefix(b)),
        CborValue::Simple(20) => "false".into(),
        CborValue::Simple(21) => "true".into(),
        CborValue::Simple(22) => "null".into(),
        CborValue::Simple(n) => format!("simple({n})"),
        CborValue::Array(a) => format!("array of {}", a.len()),
        CborValue::Map(m) => format!("map of {}", m.len()),
        CborValue::Tagged { tag, .. } => format!("tag({tag})"),
    }
}

/// Hex of at most the first 16 bytes, so an unknown blob cannot flood a log.
fn hex_prefix(bytes: &[u8]) -> String {
    if bytes.len() <= 16 {
        hex(bytes)
    } else {
        format!("{}…", hex(&bytes[..16]))
    }
}

/// Digest of an artifact, for binding a statement to the thing it describes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Digest `bytes` with a COSE hash algorithm identifier.
///
/// Returns `None` for algorithms this build cannot compute, so a caller
/// reports "not evaluated" rather than silently choosing a different function
/// than the signer named.
pub fn digest_with(cose_alg: i64, bytes: &[u8]) -> Option<Vec<u8>> {
    match cose_alg {
        labels::alg::SHA256 => Some(Sha256::digest(bytes).to_vec()),
        labels::alg::SHA384 => Some(sha2::Sha384::digest(bytes).to_vec()),
        labels::alg::SHA512 => Some(sha2::Sha512::digest(bytes).to_vec()),
        _ => None,
    }
}
