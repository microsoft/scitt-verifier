//! The evidence record.
//!
//! Two audiences, one document. A human wants to know whether to deploy; an
//! auditor six months later wants to know exactly what was checked and what was
//! not. The second audience is the harder one, which is why `notChecked` is a
//! first-class field rather than something you infer from silence.

use scitt_policy::{Outcome, PolicyDecision};
use scitt_receipt::{KeyLookup, ReceiptFacts, StatementFacts};
use serde_json::{json, Map, Value};

use crate::cli::{BindingMode, VerifyArgs};
use crate::Verdict;

pub fn build(
    args: &VerifyArgs,
    facts: &StatementFacts,
    decision: Option<&PolicyDecision>,
    binding: &BindingResult,
    verdict: Verdict,
    now: i64,
) -> Value {
    let mut root = Map::new();

    root.insert("schemaVersion".into(), json!("scitt-verifier/evidence/v1"));
    root.insert(
        "tool".into(),
        json!({
            "name": "scitt-verifier",
            "version": env!("CARGO_PKG_VERSION"),
        }),
    );
    root.insert("evaluatedAt".into(), json!(now));
    root.insert("verdict".into(), json!(verdict.as_str()));
    root.insert("exitCode".into(), json!(verdict.exit_code()));

    root.insert(
        "inputs".into(),
        json!({
            "statement": args.statement.display().to_string(),
            "scittKeys": args.scitt_keys.display().to_string(),
            "policy": args.policy.display().to_string(),
            "artifact": args.artifact.as_ref().map(|p| p.display().to_string()),
            "issuerScope": args.issuer,
        }),
    );

    root.insert(
        "statement".into(),
        json!({
            "claimDigest": facts.claim_digest,
            "signedStatementBytes": facts.signed_statement_len,
            "payloadBytes": facts.payload_len,
            "algorithm": facts.alg.map(scitt_receipt::labels::alg::name),
            "signatureValid": facts.signature_valid,
            "certificateChainLength": facts.certificate_chain_len,
            "signerSubject": facts.leaf_subject,
            "signerIssuer": facts.leaf_issuer,
            "cwt": {
                "iss": facts.cwt.iss,
                "sub": facts.cwt.sub,
                "iat": facts.cwt.iat,
                "svn": facts.cwt.svn,
            },
        }),
    );

    root.insert(
        "receipts".into(),
        Value::Array(facts.receipts.iter().map(receipt_json).collect()),
    );

    root.insert(
        "artifactBinding".into(),
        json!({
            // Always recorded as declared, never inferred. A future reader must
            // be able to tell that the operator asserted this relationship
            // rather than the tool guessing it from file extensions.
            "mode": match args.binding_mode {
                BindingMode::None => "none",
                BindingMode::PayloadBytes => "payload-bytes",
            },
            "declared": args.artifact.is_some(),
            "bound": binding.bound,
            "detail": binding.detail,
        }),
    );

    root.insert(
        "policy".into(),
        match decision {
            Some(d) => json!({
                "policyId": d.policy_id,
                "policyVersion": d.policy_version,
                "satisfied": d.satisfied(),
                "assertions": d.results,
            }),
            None => json!({ "evaluated": false }),
        },
    );

    root.insert("problems".into(), json!(facts.problems));
    root.insert(
        "notChecked".into(),
        json!(not_checked(facts, decision, args)),
    );

    Value::Object(root)
}

fn receipt_json(r: &ReceiptFacts) -> Value {
    json!({
        "issuer": r.issuer,
        "kid": r.kid,
        "registeredAt": r.registered_at,
        "algorithm": r.algorithm.map(scitt_receipt::labels::alg::name),
        "verifiableDataStructure": r.vds,
        "leafHash": r.leaf_hash,
        "merkleRoot": r.root,
        "merklePathLength": r.path_length,
        "rootSignatureValid": r.root_signature_valid,
        "boundToStatement": r.bound_to_statement,
        "claimsDigest": r.claims_digest,
        "keyLookup": r.key_lookup.as_ref().map(key_lookup_name),
        "kidBoundToKey": r.kid_bound_to_key,
        "fullyVerified": r.fully_verified(),
        "problems": r.problems,
    })
}

fn key_lookup_name(lookup: &KeyLookup) -> &'static str {
    match lookup {
        KeyLookup::Found => "found",
        KeyLookup::UnknownKid => "unknownKid",
        KeyLookup::Revoked => "revoked",
        KeyLookup::IssuerMismatch => "issuerMismatch",
    }
}

/// What this run did *not* establish.
///
/// Reported unconditionally, including on success. A green result that quietly
/// skipped the artifact binding is more dangerous than a red one, because
/// nobody goes looking for the caveat.
fn not_checked(
    facts: &StatementFacts,
    decision: Option<&PolicyDecision>,
    args: &VerifyArgs,
) -> Vec<String> {
    let mut gaps = Vec::new();

    if args.binding_mode == BindingMode::None {
        gaps.push(
            "No artifact binding was requested, so this run does not establish which artifact \
             the statement describes."
                .into(),
        );
    }

    if args.issuer.is_none() {
        gaps.push(
            "The key set was not scoped to an issuer (--issuer), so a receipt from a different \
             transparency service using a known kid would not be rejected on issuer grounds."
                .into(),
        );
    }

    // The statement signature is checked against the key in its own certificate.
    // Chain validation to a trusted root is a separate question this release
    // does not answer, and saying so is the whole point of this section.
    if facts.certificate_chain_len > 0 {
        gaps.push(
            "The signing certificate chain was not validated to a trusted root; the statement \
             signature was checked against the leaf certificate embedded in the statement itself."
                .into(),
        );
    }

    if facts.certificate_chain_len == 0 {
        gaps.push("The statement carried no certificate chain.".into());
    }

    gaps.push("Certificate revocation was not checked (this tool runs offline).".into());

    if let Some(d) = decision {
        for r in &d.results {
            if r.outcome == Outcome::CannotEvaluate {
                gaps.push(format!(
                    "Policy assertion '{}' could not be evaluated: {}",
                    r.name, r.detail
                ));
            }
        }
    } else {
        gaps.push("No policy was evaluated.".into());
    }

    gaps
}

/// Outcome of comparing the statement to the artifact on disk.
pub struct BindingResult {
    /// `None` means no binding was requested — not that it failed.
    pub bound: Option<bool>,
    pub detail: String,
}
