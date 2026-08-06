//! # scitt-receipt
//!
//! Verification core for SCITT transparent statements registered on a CCF
//! ledger.
//!
//! ## What this crate is for
//!
//! A signature tells you who produced an artifact. It does not tell you that
//! anyone else can see that they did. A *transparent statement* adds a receipt
//! proving the signed statement was registered on an append-only ledger, so a
//! signature made in secret cannot pass as a signature made in public.
//!
//! This crate answers one question about a pile of bytes:
//!
//! > Was this exact statement registered on this ledger, and does it describe
//! > the artifact I am about to deploy?
//!
//! ## What this crate deliberately does not do
//!
//! * No I/O. Callers supply bytes.
//! * No clock. Freshness is a policy question; the crate reports `iat`.
//! * No exit codes, no severities, no verdicts.
//! * No policy. Whether `iss` is an issuer *you* trust is not decidable here.
//!
//! The reason is reuse: the same core has to serve an offline deployment gate
//! and a browser-based ledger explorer. Anything that assumes a process, a
//! terminal, or a trust decision belongs to the caller.
//!
//! ## Verification order
//!
//! 1. Parse the statement, keeping the protected bucket's exact bytes.
//! 2. Re-encode with an empty unprotected bucket and hash: the claim digest.
//! 3. Verify the issuer's signature over the statement.
//! 4. For each receipt: compute the leaf, walk the Merkle path, resolve the
//!    signing key by kid scoped to the issuer, verify the root signature, and
//!    check the receipt's `claims_digest` against step 2.
//! 5. Return facts.
//!
//! Step 4's last check is the one that is easy to omit and fatal to omit. A
//! receipt that verifies perfectly against the ledger but commits to a
//! different statement is evidence about a different artifact.

pub mod cbor;
pub mod der;
pub mod error;
pub mod keys;
pub mod labels;
pub mod receipt;
pub mod statement;

pub use error::{Error, Result};
pub use keys::{KeyLookup, LedgerKey, LedgerKeySet};
pub use receipt::{verify_receipt, ReceiptFacts};
pub use statement::{sha256_hex, CwtClaims, Sign1};

/// Everything learned about one transparent statement.
#[derive(Debug, Clone)]
pub struct StatementFacts {
    pub alg: Option<i64>,
    pub cwt: CwtClaims,
    pub claim_digest: String,
    pub signed_statement_len: usize,
    pub payload_len: Option<usize>,
    /// Whether the issuer's signature over the statement verified.
    pub signature_valid: Option<bool>,
    pub certificate_chain_len: usize,
    pub leaf_subject: Option<String>,
    pub leaf_issuer: Option<String>,
    pub receipts: Vec<ReceiptFacts>,
    pub problems: Vec<String>,
}

/// Verify a transparent statement end to end, minus policy.
pub fn verify_statement(statement_bytes: &[u8], key_set: &LedgerKeySet) -> Result<StatementFacts> {
    let statement = Sign1::parse(statement_bytes)?;
    let mut problems = Vec::new();

    let claim_digest = statement.claim_digest()?;
    let signed_statement_len = statement.signed_statement_bytes()?.len();

    let chain = statement.x5chain();
    let (leaf_subject, leaf_issuer) = match statement.leaf_names() {
        Ok(Some((s, i))) => (Some(s), Some(i)),
        Ok(None) => (None, None),
        Err(e) => {
            problems.push(e.to_string());
            (None, None)
        }
    };

    // The statement signature is verified against the key in its own leaf
    // certificate. That proves internal consistency only; whether the chain
    // ends in a root you trust is checked by the caller.
    let signature_valid = match statement.leaf_spki() {
        Ok(Some(spki)) => match statement.verify_signature(&spki) {
            Ok(valid) => {
                if !valid {
                    problems
                        .push("the issuer's signature over the statement did not verify".into());
                }
                Some(valid)
            }
            Err(e) => {
                problems.push(format!("statement signature could not be checked: {e}"));
                None
            }
        },
        Ok(None) => {
            problems
                .push("statement carries no x5chain, so its signature could not be checked".into());
            None
        }
        Err(e) => {
            problems.push(e.to_string());
            None
        }
    };

    let receipt_blobs = statement.receipts();
    if receipt_blobs.is_empty() {
        problems.push("statement carries no receipts; it is signed but not transparent".into());
    }

    let mut receipts = Vec::new();
    for (index, blob) in receipt_blobs.iter().enumerate() {
        match verify_receipt(blob, &statement, key_set) {
            Ok(facts) => receipts.push(facts),
            // One unverifiable receipt must not hide a verifiable one, so the
            // failure is recorded and the loop continues.
            Err(e) => problems.push(format!("receipt[{index}] could not be evaluated: {e}")),
        }
    }

    Ok(StatementFacts {
        alg: statement.alg().ok(),
        cwt: statement.cwt().unwrap_or_default(),
        claim_digest: cbor::hex(&claim_digest),
        signed_statement_len,
        payload_len: statement.payload.as_ref().map(Vec::len),
        signature_valid,
        certificate_chain_len: chain.len(),
        leaf_subject,
        leaf_issuer,
        receipts,
        problems,
    })
}
