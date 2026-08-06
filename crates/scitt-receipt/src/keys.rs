//! Ledger signing keys, as published by a CCF-backed transparency service.
//!
//! A transparency service rotates its signing key. Any verifier that hard-codes
//! one key breaks on the next rotation, and any verifier that accepts *any* key
//! in a set regardless of which service issued it will happily verify a receipt
//! from the wrong ledger. Both failure modes are addressed here:
//!
//! * The key set is a set, and one unparseable entry does not poison the rest.
//! * Lookup is scoped to an issuer from the start, not filtered afterwards.

use crate::cbor::{self, hex};
use crate::der::{self, Curve};
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use tav_cose::CborValue;

/// COSE_Key label values (RFC 9052 §7).
const KTY: i64 = 1;
const KID: i64 = 2;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;
const KTY_EC2: i64 = 2;

/// A single ledger signing key, normalised to SPKI.
#[derive(Debug, Clone)]
pub struct LedgerKey {
    pub kid: String,
    pub curve: Curve,
    pub spki_der: Vec<u8>,
    /// SHA-256 of the SPKI, hex-encoded.
    pub spki_sha256: String,
    /// Whether `kid` equals `spki_sha256`.
    ///
    /// CCF derives the kid this way. When it does not hold we can still verify
    /// the signature, but we can no longer claim the kid *identifies* the key —
    /// so the caller is told rather than left to assume.
    pub kid_bound_to_key: bool,
}

/// The outcome of resolving a `kid` against a key set.
///
/// Deliberately not a `bool`. "The key set does not contain this kid" and "this
/// key is revoked" are different facts with different consequences, and
/// collapsing them is how a rotation gets reported as a compromise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLookup {
    Found,
    UnknownKid,
    Revoked,
    IssuerMismatch,
}

/// A set of signing keys scoped to exactly one transparency service.
#[derive(Debug, Clone)]
pub struct LedgerKeySet {
    /// The issuer these keys are valid for. `None` means unscoped, which the
    /// caller must treat as weaker evidence.
    pub issuer: Option<String>,
    pub keys: Vec<LedgerKey>,
    pub revoked_kids: Vec<String>,
    /// Entries that could not be parsed, kept for reporting.
    ///
    /// A rotation can introduce a key using a curve this build does not know.
    /// Refusing the whole set in that case would turn a routine rotation into
    /// an outage.
    pub skipped: Vec<String>,
}

impl LedgerKeySet {
    /// Parse a COSE_KeySet: a CBOR array of COSE_Key maps.
    pub fn from_cose_key_set(bytes: &[u8], issuer: Option<String>) -> Result<Self> {
        let value = CborValue::from_bytes(bytes)
            .map_err(|e| Error::TrustMaterial(format!("key set is not valid CBOR: {e:?}")))?;

        let entries = cbor::as_array(&value).map_err(|_| {
            Error::TrustMaterial("key set must be a CBOR array of COSE_Keys".into())
        })?;

        let mut keys = Vec::new();
        let mut skipped = Vec::new();

        for (index, entry) in entries.iter().enumerate() {
            match parse_cose_key(entry) {
                Ok(key) => keys.push(key),
                Err(e) => skipped.push(format!("key[{index}]: {e}")),
            }
        }

        if keys.is_empty() {
            return Err(Error::TrustMaterial(format!(
                "key set contains no usable keys ({} entries skipped: {})",
                skipped.len(),
                skipped.join("; ")
            )));
        }

        Ok(Self {
            issuer,
            keys,
            revoked_kids: Vec::new(),
            skipped,
        })
    }

    /// Resolve a kid, scoped to the receipt's issuer.
    ///
    /// `receipt_issuer` is checked *before* the kid, so a key that is legitimate
    /// for a different transparency service can never satisfy this receipt. That
    /// ordering is the point: filtering after a successful match is a check that
    /// is easy to accidentally remove.
    pub fn find(&self, kid: &str, receipt_issuer: Option<&str>) -> (KeyLookup, Option<&LedgerKey>) {
        if let Some(expected) = &self.issuer {
            match receipt_issuer {
                Some(actual) if actual == expected => {}
                _ => return (KeyLookup::IssuerMismatch, None),
            }
        }

        if self.revoked_kids.iter().any(|r| r == kid) {
            return (KeyLookup::Revoked, None);
        }

        match self.keys.iter().find(|k| k.kid == kid) {
            Some(key) => (KeyLookup::Found, Some(key)),
            None => (KeyLookup::UnknownKid, None),
        }
    }
}

fn parse_cose_key(entry: &CborValue) -> Result<LedgerKey> {
    if !matches!(entry, CborValue::Map(_)) {
        return Err(Error::TrustMaterial("COSE_Key must be a map".into()));
    }

    let kty = cbor::opt_int_key(entry, KTY)
        .ok_or_else(|| Error::TrustMaterial("COSE_Key has no kty".into()))
        .and_then(cbor::as_int)?;
    if kty != KTY_EC2 {
        return Err(Error::TrustMaterial(format!(
            "kty {kty} is not EC2; only EC2 ledger keys are supported"
        )));
    }

    let kid = cbor::opt_int_key(entry, KID)
        .ok_or_else(|| Error::TrustMaterial("COSE_Key has no kid".into()))
        .and_then(cbor::as_kid)?;
    if kid.len() != 64 || !kid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::TrustMaterial(format!(
            "kid '{kid}' is not 64 hex characters"
        )));
    }

    let crv = cbor::opt_int_key(entry, CRV)
        .ok_or_else(|| Error::TrustMaterial("COSE_Key has no crv".into()))
        .and_then(cbor::as_int)?;
    let curve = Curve::from_cose(crv)?;

    let x = cbor::opt_int_key(entry, X)
        .ok_or_else(|| Error::TrustMaterial("COSE_Key has no x".into()))
        .and_then(cbor::as_bytes)?;
    let y = cbor::opt_int_key(entry, Y)
        .ok_or_else(|| Error::TrustMaterial("COSE_Key has no y".into()))
        .and_then(cbor::as_bytes)?;

    let spki_der = der::spki_from_ec_point(curve, x, y)?;
    let spki_sha256 = hex(&Sha256::digest(&spki_der));
    let kid_bound_to_key = spki_sha256 == kid;

    Ok(LedgerKey {
        kid,
        curve,
        spki_der,
        spki_sha256,
        kid_bound_to_key,
    })
}
