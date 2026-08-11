//! CCF receipt verification: inclusion proof, root signature, and the binding
//! back to the statement.
//!
//! Implements the `CCF_LEDGER_SHA256` verifiable data structure from
//! `draft-ietf-scitt-receipts-ccf-profile`.

use crate::cbor::{self, fixed_time_eq, hex};
use crate::error::{Error, Result};
use crate::keys::{KeyLookup, LedgerKeySet};
use crate::labels;
use crate::statement::Sign1;
use sha2::{Digest, Sha256};
use tav_cose::CborValue;
use tav_crypto::KeyBackend;

/// What a single receipt turned out to be.
#[derive(Debug, Clone, Default)]
pub struct ReceiptFacts {
    /// Issuer from the receipt's CWT claims.
    pub issuer: Option<String>,
    /// Key identifier the receipt says signed it.
    pub kid: Option<String>,
    /// Registration time from the CWT `iat` claim, as a Unix timestamp.
    pub registered_at: Option<i64>,
    /// COSE algorithm of the root signature.
    pub algorithm: Option<i64>,
    /// The verifiable data structure identifier found in the receipt.
    pub vds: Option<i64>,
    /// Merkle leaf hash computed from the receipt's own leaf components.
    pub leaf_hash: Option<String>,
    /// Merkle root reached by walking the inclusion proof.
    pub root: Option<String>,
    /// Number of steps in the Merkle path.
    pub path_length: Option<usize>,
    /// Whether the ledger's signature over the root verified.
    pub root_signature_valid: Option<bool>,
    /// Whether the receipt's `claims_digest` equals the statement's claim digest.
    ///
    /// A receipt with a perfect inclusion proof and a valid root signature that
    /// commits to a *different* statement proves nothing about this one. This
    /// field is the check that ties the two together.
    pub bound_to_statement: Option<bool>,
    /// The claims digest the receipt commits to.
    pub claims_digest: Option<String>,
    /// How the signing key was resolved.
    pub key_lookup: Option<KeyLookup>,
    /// Whether the resolved key's kid was derived from the key material.
    pub kid_bound_to_key: Option<bool>,
    /// Everything that stopped a check from running or made it fail.
    pub problems: Vec<String>,
}

impl ReceiptFacts {
    fn empty() -> Self {
        Self::default()
    }

    /// True only when every check that matters actually ran and passed.
    ///
    /// `None` is not treated as success anywhere. A check that could not run is
    /// a check that did not pass.
    pub fn fully_verified(&self) -> bool {
        self.root_signature_valid == Some(true)
            && self.bound_to_statement == Some(true)
            && self.key_lookup == Some(KeyLookup::Found)
    }
}

/// Verify one receipt against the statement it is attached to.
///
/// Returns facts rather than a verdict. Every failure that still leaves other
/// checks meaningful is recorded in `problems` and verification continues, so
/// the caller learns everything that is wrong in one run instead of one problem
/// per invocation.
pub fn verify_receipt(
    receipt_bytes: &[u8],
    statement: &Sign1,
    key_set: &LedgerKeySet,
) -> Result<ReceiptFacts> {
    let mut facts = ReceiptFacts::empty();

    let receipt = Sign1::parse(receipt_bytes)?;

    facts.kid = receipt.kid();
    facts.algorithm = receipt.alg().ok();
    if let Some(cwt) = receipt.cwt() {
        facts.issuer = cwt.iss;
        facts.registered_at = cwt.iat;
    }

    // The verifiable data structure identifier decides how to read everything
    // else. Guessing when it is absent, or proceeding when it is unrecognised,
    // would mean interpreting an unknown proof format as a known one.
    let vds = cbor::opt_int_key(&receipt.protected, labels::VERIFIABLE_DATA_STRUCTURE)
        .map(cbor::as_int)
        .transpose()?;
    facts.vds = vds;
    match vds {
        Some(labels::CCF_LEDGER_SHA256) => {}
        Some(other) => return Err(Error::UnsupportedVds(other)),
        None => {
            return Err(Error::Structure(
                "receipt declares no verifiable data structure (header 395)".into(),
            ))
        }
    }

    let proofs = cbor::opt_int_key(&receipt.unprotected, labels::VDP)
        .ok_or_else(|| Error::Structure("receipt carries no proofs bucket (header 396)".into()))?;
    let inclusion = cbor::opt_int_key(proofs, labels::PROOF_INCLUSION).ok_or_else(|| {
        Error::Structure("proofs bucket carries no inclusion proof (key -1)".into())
    })?;
    let inclusion_proofs = cbor::as_array(inclusion)?;

    if inclusion_proofs.is_empty() {
        return Err(Error::Structure("inclusion proof array is empty".into()));
    }
    if inclusion_proofs.len() > 1 {
        facts.problems.push(format!(
            "receipt carries {} inclusion proofs; only the first was evaluated",
            inclusion_proofs.len()
        ));
    }

    let proof_bytes = cbor::as_bytes(&inclusion_proofs[0])?;
    let proof = CborValue::from_bytes(proof_bytes)
        .map_err(|e| Error::Structure(format!("inclusion proof is not valid CBOR: {e:?}")))?;

    let (leaf_hash, claims_digest) = compute_leaf_hash(&proof)?;
    facts.leaf_hash = Some(hex(&leaf_hash));
    facts.claims_digest = Some(hex(&claims_digest));

    // Bind the receipt to this statement before spending effort on the proof:
    // this is the check that makes the rest of the receipt about *our* artifact.
    match statement.claim_digest() {
        Ok(expected) => {
            facts.bound_to_statement = Some(fixed_time_eq(&expected, &claims_digest));
            if facts.bound_to_statement == Some(false) {
                facts.problems.push(format!(
                    "receipt commits to claims digest {} but this statement hashes to {}",
                    hex(&claims_digest),
                    hex(&expected)
                ));
            }
        }
        Err(e) => facts.problems.push(format!(
            "could not compute the statement's claim digest: {e}"
        )),
    }

    let (root, path_length) = walk_merkle_path(&proof, leaf_hash)?;
    facts.root = Some(hex(&root));
    facts.path_length = Some(path_length);

    // Resolve the signing key, scoped to the receipt's issuer.
    let kid = match &facts.kid {
        Some(k) => k.clone(),
        None => {
            facts
                .problems
                .push("receipt carries no kid, so no signing key can be resolved".into());
            return Ok(facts);
        }
    };

    let (lookup, key) = key_set.find(&kid, facts.issuer.as_deref());
    facts.key_lookup = Some(lookup.clone());
    let Some(key) = key else {
        facts.problems.push(match lookup {
            KeyLookup::UnknownKid => format!(
                "kid '{kid}' is not in the key set; the service may have rotated its signing key"
            ),
            KeyLookup::Revoked => format!("kid '{kid}' is revoked"),
            KeyLookup::IssuerMismatch => format!(
                "the key set is scoped to '{}' but this receipt was issued by '{}'",
                key_set.issuer.as_deref().unwrap_or("(unscoped)"),
                facts.issuer.as_deref().unwrap_or("(none)")
            ),
            KeyLookup::Found => unreachable!("Found always carries a key"),
        });
        return Ok(facts);
    };
    facts.kid_bound_to_key = Some(key.kid_bound_to_key);
    if !key.kid_bound_to_key {
        facts.problems.push(format!(
            "kid '{kid}' does not equal SHA-256 of the key ({}), so it does not identify this key",
            key.spki_sha256
        ));
    }

    // The root signature is over the Merkle root as a detached payload.
    let alg = receipt.alg()?;
    if !matches!(
        alg,
        labels::alg::ES256 | labels::alg::ES384 | labels::alg::ES512
    ) {
        return Err(Error::UnsupportedAlgorithm(alg));
    }
    let algorithm = tav_cose::signature_key_algorithm_for_cose_alg(alg)
        .map_err(|_| Error::UnsupportedAlgorithm(alg))?;
    let public_key = <tav_crypto::Key as KeyBackend>::from_spki_der(&key.spki_der, algorithm)
        .map_err(|e| Error::Crypto(format!("could not import ledger key: {e}")))?;

    facts.root_signature_valid = Some(
        tav_cose::synchronous::cose_verify1(
            &public_key,
            algorithm,
            &receipt.protected_raw,
            &root,
            &receipt.signature,
        )
        .is_ok(),
    );
    if facts.root_signature_valid == Some(false) {
        facts
            .problems
            .push("the ledger's signature over the Merkle root did not verify".into());
    }

    Ok(facts)
}

/// CCF leaf hash: `SHA-256(write_set_digest || SHA-256(commit_evidence) || claims_digest)`.
///
/// `commit_evidence` is hashed rather than used raw, so the three components are
/// fixed width and cannot be re-split at a different boundary.
fn compute_leaf_hash(proof: &CborValue) -> Result<([u8; 32], [u8; 32])> {
    let leaf = cbor::req_int_key(proof, labels::PROOF_LEAF)?;
    let components = cbor::as_array(leaf)?;
    if components.len() != 3 {
        return Err(Error::Structure(format!(
            "leaf must have 3 components, found {}",
            components.len()
        )));
    }

    let write_set_digest = cbor::as_bytes(&components[0])?;
    let commit_evidence = cbor::as_text(&components[1])?;
    let claims_digest = cbor::as_bytes(&components[2])?;

    if claims_digest.len() != 32 {
        return Err(Error::Structure(format!(
            "claims digest must be 32 bytes, found {}",
            claims_digest.len()
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(write_set_digest);
    hasher.update(Sha256::digest(commit_evidence.as_bytes()));
    hasher.update(claims_digest);

    let mut claims = [0u8; 32];
    claims.copy_from_slice(claims_digest);
    Ok((hasher.finalize().into(), claims))
}

/// Walk the Merkle path from the leaf to the root.
///
/// Each step is `[is_left, digest]`. `is_left` says which side the sibling sits
/// on; getting it backwards produces a root that simply will not verify, which
/// is the intended failure mode.
fn walk_merkle_path(proof: &CborValue, leaf_hash: [u8; 32]) -> Result<([u8; 32], usize)> {
    let path = cbor::req_int_key(proof, labels::PROOF_PATH)?;
    let steps = cbor::as_array(path)?;

    let mut current = leaf_hash;
    for (index, step) in steps.iter().enumerate() {
        let pair = cbor::as_array(step)?;
        if pair.len() != 2 {
            return Err(Error::Structure(format!(
                "path step {index} must be [is_left, digest], found {} elements",
                pair.len()
            )));
        }

        // CCF has emitted this flag as both a CBOR bool and an integer.
        let is_left = match &pair[0] {
            CborValue::Simple(21) => true,
            CborValue::Simple(20) => false,
            CborValue::Int(i) => *i != 0,
            other => {
                return Err(Error::Structure(format!(
                    "path step {index} direction must be bool or int, got {}",
                    cbor::type_name(other)
                )))
            }
        };

        let sibling = cbor::as_bytes(&pair[1])?;
        if sibling.len() != 32 {
            return Err(Error::Structure(format!(
                "path step {index} digest must be 32 bytes, found {}",
                sibling.len()
            )));
        }

        let mut hasher = Sha256::new();
        if is_left {
            hasher.update(sibling);
            hasher.update(current);
        } else {
            hasher.update(current);
            hasher.update(sibling);
        }
        current = hasher.finalize().into();
    }

    Ok((current, steps.len()))
}
