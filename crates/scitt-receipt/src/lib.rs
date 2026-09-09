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

pub mod binding;
pub mod cbor;
pub mod der;
pub mod error;
pub mod external;
pub mod keys;
pub mod labels;
pub mod receipt;
pub mod statement;

pub use binding::{bind, Binding, BindingMode, BindingReason, BindingReport};
pub use error::{Error, Result};
pub use keys::{KeyLookup, LedgerKey, LedgerKeySet};
pub use receipt::{
    describe_inclusion_proof, describe_receipt, verify_receipt, InclusionProof, ProofStep,
    ReceiptFacts, ReceiptSummary,
};
pub use statement::{
    describe_certificate, digest_with, render_scalar, sha256_hex, CertificateSummary, CwtClaims,
    Sign1,
};

/// Re-exported so consumers can walk headers without depending on `tav-cose`
/// directly, and so the CBOR representation stays this crate's concern.
pub use tav_cose::CborValue;

/// Everything learned about one transparent statement.
#[derive(Debug, Clone, Default)]
pub struct StatementFacts {
    pub alg: Option<i64>,
    pub cwt: CwtClaims,
    pub claim_digest: String,
    pub signed_statement_len: usize,
    pub payload_len: Option<usize>,
    /// The payload bytes themselves.
    ///
    /// Held so a policy can check a detached signature carried in a protected
    /// header against what it claims to cover. `payload_len` answers "how
    /// big", which is all most callers want; this answers "which bytes", which
    /// only a cryptographic check needs. Not serialised into `--facts` or
    /// `--result` — those are built field by field in the verifier's record,
    /// and a 40 KB base64 blob in a pipeline log helps nobody.
    pub payload: Option<Vec<u8>>,
    /// Whether the issuer's signature over the statement verified.
    pub signature_valid: Option<bool>,
    pub certificate_chain_len: usize,
    pub leaf_subject: Option<String>,
    pub leaf_issuer: Option<String>,
    /// The statement's protected header bucket, exactly as it was parsed.
    ///
    /// Kept whole rather than reduced to the labels this build names, because
    /// a relying party may need to assert on a header the tool has no opinion
    /// about — a vendor label, or a profile that did not exist when this
    /// binary was compiled. Every byte here is inside `protected_raw`, so the
    /// issuer's signature covers it and the receipt's claim digest carries it;
    /// this is the strongest material a policy can read.
    ///
    /// `None` only when no statement was parsed.
    pub protected: Option<CborValue>,
    /// Every receipt found in the statement, verified or not.
    ///
    /// Receipts arrive in the statement's *unprotected* header bucket, which
    /// no signature covers, so anyone who handles the file can append one.
    /// Reach for [`Self::verified_receipts`] instead unless you specifically
    /// mean "everything present", as `inspect` and the record's receipt
    /// listing do.
    pub receipts: Vec<ReceiptFacts>,
    /// How many receipt blobs the statement carried, evaluable or not.
    ///
    /// `receipts` holds only those that got far enough to produce facts, so a
    /// blob that failed to parse is missing from it. A caller asking about the
    /// *shape* of the envelope needs the number that arrived, not the number
    /// that survived — otherwise appending an unparseable blob looks identical
    /// to appending nothing.
    pub receipts_present: usize,
    pub problems: Vec<String>,
}

impl StatementFacts {
    /// Only the receipts that actually proved something.
    ///
    /// Any decision that grants trust must read this rather than `receipts`.
    /// A receipt that did not verify carries no more authority than a text
    /// file an attacker attached, because that is exactly what it might be.
    pub fn verified_receipts(&self) -> impl Iterator<Item = &ReceiptFacts> {
        self.receipts.iter().filter(|r| r.fully_verified())
    }

    /// Whether anything in this statement establishes transparency at all.
    pub fn any_receipt_verified(&self) -> bool {
        self.verified_receipts().next().is_some()
    }
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
        payload: statement.payload.clone(),
        signature_valid,
        certificate_chain_len: chain.len(),
        leaf_subject,
        leaf_issuer,
        protected: Some(statement.protected.clone()),
        receipts,
        receipts_present: receipt_blobs.len(),
        problems,
    })
}
