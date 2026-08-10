//! The evidence record.
//!
//! Two audiences, one document. A human wants to know whether to deploy; an
//! auditor six months later wants to know exactly what was checked and what was
//! not. The second audience is the harder one, which is why `notChecked` is a
//! first-class field rather than something you infer from silence.
//!
//! This record is produced on *every* path, including runs that failed before
//! a signature was checked. A pipeline that archives evidence on `always()`
//! must get a file when things go wrong — that is the only time anyone reads
//! it closely.

use scitt_receipt::{KeyLookup, ReceiptFacts, StatementFacts};
use serde_json::{json, Map, Value};

use crate::cli::{BindingMode, VerifyArgs};
use crate::outcome::{Assessment, Checks, Diagnostic, Gap, Trust};

/// Bumped from v1 alongside the artifact-aware verdicts. A v1 consumer looking
/// for `"verdict": "verified"` would silently stop matching, so the version
/// has to move with it.
const SCHEMA_VERSION: &str = "scitt-verifier/evidence/v2";

pub fn build(args: &VerifyArgs, assessment: &Assessment, now: i64) -> Value {
    let mut root = Map::new();

    root.insert("schemaVersion".into(), json!(SCHEMA_VERSION));
    root.insert(
        "tool".into(),
        json!({
            "name": "scitt-verifier",
            "version": env!("CARGO_PKG_VERSION"),
        }),
    );
    root.insert("evaluatedAt".into(), json!(now));
    root.insert("verdict".into(), json!(assessment.verdict.as_str()));
    root.insert("exitCode".into(), json!(assessment.verdict.exit_code()));

    // The single field that answers "what stopped my deployment". Everything
    // else in this document is supporting detail for that one question.
    root.insert(
        "primaryDiagnostic".into(),
        match &assessment.primary {
            Some(d) => diagnostic_json(d),
            None => Value::Null,
        },
    );

    root.insert("trust".into(), trust_json(&assessment.trust));
    root.insert("checks".into(), checks_json(&assessment.checks));

    root.insert(
        "diagnostics".into(),
        Value::Array(assessment.diagnostics.iter().map(diagnostic_json).collect()),
    );
    root.insert(
        "notChecked".into(),
        Value::Array(assessment.not_checked.iter().map(gap_json).collect()),
    );

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

    let mut details = Map::new();

    details.insert(
        "statement".into(),
        match &assessment.facts {
            Some(facts) => statement_json(facts),
            None => Value::Null,
        },
    );

    details.insert(
        "receipts".into(),
        match &assessment.facts {
            Some(facts) => Value::Array(facts.receipts.iter().map(receipt_json).collect()),
            None => Value::Null,
        },
    );

    details.insert(
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
            "bound": assessment.binding.bound,
            "detail": assessment.binding.detail,
        }),
    );

    details.insert(
        "policy".into(),
        match &assessment.decision {
            Some(d) => json!({
                "policyId": d.policy_id,
                "policyVersion": d.policy_version,
                "satisfied": d.satisfied(),
                "assertions": d.results,
            }),
            None => json!({ "evaluated": false }),
        },
    );

    details.insert(
        "problems".into(),
        match &assessment.facts {
            Some(facts) => json!(facts.problems),
            None => json!([]),
        },
    );

    root.insert("details".into(), Value::Object(details));

    Value::Object(root)
}

fn diagnostic_json(d: &Diagnostic) -> Value {
    json!({
        "code": d.code,
        "category": d.category.as_str(),
        "severity": d.severity.as_str(),
        "message": d.message,
        "action": d.action,
    })
}

fn gap_json(g: &Gap) -> Value {
    json!({
        "code": g.code,
        "category": g.category.as_str(),
        "message": g.message,
        "impact": g.impact,
    })
}

/// How the trust material arrived, promoted out of prose.
///
/// "The receipt signature is valid" means nothing without "valid under whose
/// key, and who vouched for it". A consumer auditing a fleet needs to be able
/// to query for runs that trusted an unsigned key set.
fn trust_json(t: &Trust) -> Value {
    json!({
        "mode": t.mode,
        "issuerScope": t.issuer_scope,
        "limitations": t.limitations,
    })
}

fn checks_json(c: &Checks) -> Value {
    json!({
        "statementSignature": c.statement_signature.as_str(),
        "receiptInclusion": c.receipt_inclusion.as_str(),
        "artifactBinding": c.artifact_binding.as_str(),
        "policy": c.policy.as_str(),
    })
}

fn statement_json(facts: &StatementFacts) -> Value {
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
    })
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
