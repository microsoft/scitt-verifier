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
            iat: cbor::opt_int_key(claims, labels::CWT_IAT).and_then(|v| cbor::as_int(v).ok()),
            svn: cbor::opt_text_key(claims, labels::CWT_SVN).and_then(|v| cbor::as_int(v).ok()),
        })
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
    pub svn: Option<i64>,
}

/// Digest of an artifact, for binding a statement to the thing it describes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
