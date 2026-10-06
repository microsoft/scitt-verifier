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
}

/// A set of transparency service signing keys.
///
/// The set is deliberately not scoped to an issuer. A receipt from another
/// service is signed by that service's key, so it fails signature verification
/// here; an issuer name checked alongside would add no evidence, and reporting
/// it as a trust failure would misdescribe a receipt that is merely unwanted.
/// Requiring a particular issuer is a relying-party rule, so it belongs in the
/// policy document, where it is versioned and reviewable.
#[derive(Debug, Clone)]
pub struct LedgerKeySet {
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
    pub fn from_cose_key_set(bytes: &[u8]) -> Result<Self> {
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
            keys,
            revoked_kids: Vec::new(),
            skipped,
        })
    }

    /// Resolve a kid to a signing key.
    pub fn find(&self, kid: &str) -> (KeyLookup, Option<&LedgerKey>) {
        if self.revoked_kids.iter().any(|r| r == kid) {
            return (KeyLookup::Revoked, None);
        }

        match self.keys.iter().find(|k| k.kid == kid) {
            Some(key) => (KeyLookup::Found, Some(key)),
            None => (KeyLookup::UnknownKid, None),
        }
    }

    /// The one key in this set that belongs to the service certificate whose
    /// public key hashes to `service_key_kid`.
    ///
    /// Comparing `kid` strings alone would be worthless: `kid` is a label
    /// chosen by whoever wrote the key set. What makes this meaningful is that
    /// each [`LedgerKey`] derives its expected identifier from its own key
    /// material, so an entry claiming the service's `kid` while holding a
    /// different point is already marked as unbound. Requiring both means the
    /// set must contain the actual public key from the certificate.
    ///
    /// Lives here rather than in the network crate because a caller that
    /// obtained the key set over a channel it cannot authenticate, such as a
    /// browser reading through a proxy, needs the same check and must not
    /// carry a second implementation of it.
    pub fn service_key(
        &self,
        service_key_kid: &str,
    ) -> std::result::Result<&LedgerKey, ServiceKeyMismatch> {
        let mut matching = self.keys.iter().filter(|k| k.kid == service_key_kid);
        let key = matching.next().ok_or(ServiceKeyMismatch::Absent)?;

        // Two entries claiming the same identifier make "the key with this
        // kid" ambiguous, and a verifier resolving a receipt by kid would pick
        // one of them for reasons no policy author ever stated.
        if matching.next().is_some() {
            return Err(ServiceKeyMismatch::Ambiguous);
        }

        if !key.kid_bound_to_key {
            return Err(ServiceKeyMismatch::Unbound);
        }

        Ok(key)
    }

    /// A set holding only `key`, keeping this set's revocations.
    ///
    /// For a caller that can vouch for one key and nothing else. Every other
    /// entry then resolves as an unknown `kid`, so a receipt signed by one of
    /// them is reported as unevaluated rather than verified on the word of
    /// whoever served the set.
    pub fn restricted_to(&self, key: &LedgerKey) -> LedgerKeySet {
        LedgerKeySet {
            keys: vec![key.clone()],
            revoked_kids: self.revoked_kids.clone(),
            skipped: Vec::new(),
        }
    }
}

/// Why a key set could not be tied to a service certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKeyMismatch {
    /// No entry claims the certificate's key identifier.
    Absent,
    /// More than one entry claims it.
    Ambiguous,
    /// The one entry claiming it holds different key material.
    Unbound,
}

impl ServiceKeyMismatch {
    /// A stable code for structured output.
    pub fn code(self) -> &'static str {
        match self {
            ServiceKeyMismatch::Absent => "absent",
            ServiceKeyMismatch::Ambiguous => "ambiguous",
            ServiceKeyMismatch::Unbound => "unbound",
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
