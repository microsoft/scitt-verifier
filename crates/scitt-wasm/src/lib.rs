// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WebAssembly bindings for `scitt-receipt`.
//!
//! ## What this crate is
//!
//! The browser's consumer layer. `scitt-verifier` turns facts into exit codes
//! for a terminal; this turns the same facts into JSON for a web page. Both sit
//! *outside* the core for the same reason: a verdict is a consumer's opinion,
//! and the core is deliberately free of them.
//!
//! ## Why the API is synchronous
//!
//! Built with `crypto_pure_rust`, every signature check is a plain function
//! call. That keeps `verify_statement` synchronous here, which matters more
//! than it looks: WebCrypto's `SubtleCrypto` is async-only, so a WebCrypto
//! backend makes the whole call stack async — through `verify_receipt`, through
//! `verify_statement`, and out into every caller. The pure-Rust backend is what
//! lets one source tree serve a static binary and a browser without the two
//! consumers disagreeing about function colour.
//!
//! ## Why JSON, and not `serde_wasm_bindgen`
//!
//! The core carries no `serde` derives, and adding them for this would put a
//! wire format in a crate whose whole discipline is having no consumer
//! concerns. So the mapping lives here, next to the consumer that wants it —
//! exactly as `scitt-verifier` keeps its own in `report.rs`.

use scitt_receipt::{
    describe_certificate, describe_receipt, keys::KeyLookup, labels, CertificateSummary, CwtClaims,
    LedgerKeySet, ReceiptFacts, Sign1, StatementFacts,
};
use serde_json::{json, Map, Value};
use wasm_bindgen::prelude::*;

/// The verification core's version, so a page can report what verified it.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Verify a transparent statement against a COSE_KeySet.
///
/// `issuer`, when supplied, scopes the key set to one transparency service.
/// Leaving it `None` is weaker evidence and the result says so, because an
/// unscoped key set will happily verify a receipt from the wrong ledger.
///
/// Returns a JSON document. Errors are returned as JS exceptions only when
/// nothing could be established at all; a statement that parses but fails
/// verification is a *result*, not an error, and callers must render it.
#[wasm_bindgen(js_name = verifyStatement)]
pub fn verify_statement(
    statement: &[u8],
    key_set: &[u8],
    issuer: Option<String>,
) -> Result<String, JsValue> {
    let keys = LedgerKeySet::from_cose_key_set(key_set, issuer).map_err(to_js)?;

    let facts = scitt_receipt::verify_statement(statement, &keys).map_err(to_js)?;

    // Re-parsing to describe the chain costs a few hundred microseconds and
    // saves the caller a second entry point. The chain is what a human looks
    // at first when a signature fails to verify.
    let chain = Sign1::parse(statement)
        .map(|s| s.describe_chain())
        .unwrap_or_default();

    let mut out = statement_facts_json(&facts);
    out["certificateChain"] = Value::Array(chain.iter().map(certificate_json).collect());
    out["keySet"] = json!({
        "issuer": keys.issuer,
        "keyCount": keys.keys.len(),
        "revokedKids": keys.revoked_kids,
        // A rotation can introduce a curve this build does not know. Refusing
        // the whole set would turn a routine rotation into an outage, so the
        // skipped entries are reported instead of being fatal.
        "skipped": keys.skipped,
        "scoped": keys.issuer.is_some(),
    });

    serde_json::to_string(&out).map_err(to_js)
}

/// Describe a statement without trust material.
///
/// Answers "what is in this file?" and deliberately not "should I trust it?".
/// Nothing here is evidence: with no key set, no receipt signature can be
/// checked, so every verification field is absent rather than false.
#[wasm_bindgen(js_name = inspectStatement)]
pub fn inspect_statement(statement: &[u8]) -> Result<String, JsValue> {
    let parsed = Sign1::parse(statement).map_err(to_js)?;

    let receipts: Vec<Value> = parsed
        .receipts()
        .iter()
        .map(|blob| match describe_receipt(blob) {
            Ok(summary) => json!({
                "algorithm": alg_json(summary.algorithm),
                "kid": summary.kid,
                "issuer": summary.issuer,
                "subject": summary.subject,
                "registeredAt": summary.registered_at,
                "vds": summary.vds,
                "ccfTxId": summary.ccf_txid,
                "claimsDigest": summary.claims_digest,
                "commitEvidence": summary.commit_evidence,
                "writeSetDigest": summary.write_set_digest,
                "pathLength": summary.path_length,
                "protectedLabels": summary.protected_labels,
                "unprotectedLabels": summary.unprotected_labels,
                "inclusionProof": summary.inclusion_proof.as_ref().map(|p| json!({
                    "writeSetDigest": p.write_set_digest,
                    "commitEvidence": p.commit_evidence,
                    "claimsDigest": p.claims_digest,
                    "path": p.path.iter().map(|step| json!({
                        "siblingLeft": step.sibling_left,
                        "digest": step.digest,
                    })).collect::<Vec<_>>(),
                })),
                "problems": summary.problems,
            }),
            Err(e) => json!({ "problems": [e.to_string()] }),
        })
        .collect();

    // `claim_digest()` already returns the digest. Hex-encode it; hashing it
    // again would produce a plausible-looking string that matches nothing.
    let claim_digest = parsed
        .claim_digest()
        .ok()
        .map(|d| scitt_receipt::cbor::hex(&d));

    let out = json!({
        "wasTagged": parsed.was_tagged,
        "algorithm": alg_json(parsed.alg().ok()),
        "contentType": parsed.content_type(),
        "isHashEnvelope": parsed.is_hash_envelope(),
        "payloadHashAlg": alg_json(parsed.payload_hash_alg()),
        "payloadPreimageContentType": parsed.payload_preimage_content_type(),
        "payloadLocation": parsed.payload_location(),
        "payloadLength": parsed.payload.as_ref().map(Vec::len),
        "signedStatementLength": parsed.signed_statement_bytes().map(|b| b.len()).ok(),
        "claimDigest": claim_digest,
        "cwt": cwt_json(&parsed.cwt().unwrap_or_default()),
        "protectedLabels": Sign1::header_labels(&parsed.protected),
        "unprotectedLabels": Sign1::header_labels(&parsed.unprotected),
        "certificateChain": parsed.describe_chain().iter().map(certificate_json).collect::<Vec<_>>(),
        "receiptsPresent": receipts.len(),
        "receipts": receipts,
    });

    serde_json::to_string(&out).map_err(to_js)
}

fn statement_facts_json(facts: &StatementFacts) -> Value {
    json!({
        "algorithm": alg_json(facts.alg),
        "cwt": cwt_json(&facts.cwt),
        "claimDigest": facts.claim_digest,
        "signedStatementLength": facts.signed_statement_len,
        "payloadLength": facts.payload_len,
        "signatureValid": facts.signature_valid,
        "certificateChainLength": facts.certificate_chain_len,
        "leafSubject": facts.leaf_subject,
        "leafIssuer": facts.leaf_issuer,
        // `receiptsPresent` counts blobs that arrived; `receipts` holds those
        // that produced facts. A blob that failed to parse is missing from the
        // second, so reporting only that makes an unparseable append look
        // identical to appending nothing.
        "receiptsPresent": facts.receipts_present,
        "receipts": facts.receipts.iter().map(receipt_facts_json).collect::<Vec<_>>(),
        "verifiedReceiptCount": facts.verified_receipts().count(),
        "anyReceiptVerified": facts.any_receipt_verified(),
        "problems": facts.problems,
    })
}

fn receipt_facts_json(facts: &ReceiptFacts) -> Value {
    json!({
        "issuer": facts.issuer,
        "kid": facts.kid,
        "registeredAt": facts.registered_at,
        "algorithm": alg_json(facts.algorithm),
        "vds": facts.vds,
        "leafHash": facts.leaf_hash,
        "root": facts.root,
        "pathLength": facts.path_length,
        // Every check is tri-state. `null` means the check did not run, and it
        // must never be rendered as a pass: a check that fails to run should
        // degrade the verdict, not disappear from it.
        "rootSignatureValid": facts.root_signature_valid,
        // The binding back to the statement. A receipt can have a valid
        // inclusion proof and a verifying root signature and still be evidence
        // about a different artifact. This is the field that catches that.
        "boundToStatement": facts.bound_to_statement,
        "claimsDigest": facts.claims_digest,
        "keyLookup": facts.key_lookup.as_ref().map(key_lookup_str),
        "kidBoundToKey": facts.kid_bound_to_key,
        "fullyVerified": facts.fully_verified(),
        "problems": facts.problems,
    })
}

/// Kept distinct on purpose. A rotated key and a forged receipt are different
/// events — one is an operational chore, the other an incident — and a UI
/// that renders them identically trains its users to ignore both.
fn key_lookup_str(lookup: &KeyLookup) -> &'static str {
    match lookup {
        KeyLookup::Found => "found",
        KeyLookup::UnknownKid => "unknown-kid",
        KeyLookup::Revoked => "revoked",
        KeyLookup::IssuerMismatch => "issuer-mismatch",
    }
}

fn cwt_json(cwt: &CwtClaims) -> Value {
    let mut other = Map::new();
    for (k, v) in &cwt.other {
        other.insert(k.clone(), Value::String(v.clone()));
    }
    json!({
        "iss": cwt.iss,
        "sub": cwt.sub,
        // Reported, never judged. Freshness is a policy question and the core
        // does not read the clock; neither does this.
        "iat": cwt.iat,
        "nbf": cwt.nbf,
        "exp": cwt.exp,
        "svn": cwt.svn,
        "other": Value::Object(other),
    })
}

fn certificate_json(cert: &CertificateSummary) -> Value {
    json!({
        "index": cert.index,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "sha256": cert.sha256,
        "version": cert.version,
        "extendedKeyUsage": cert.extended_key_usage,
        "ekuCritical": cert.eku_critical,
        "basicConstraints": cert.basic_constraints.map(|(critical, ca, path_len)| json!({
            "critical": critical,
            "ca": ca,
            "pathLenConstraint": path_len,
        })),
        "keyCertSign": cert.key_cert_sign,
        "unhandledCriticalExtensions": cert.unhandled_critical_extensions,
        "problem": cert.problem,
    })
}

/// Both the numeric COSE label and its name, because the number is what the
/// bytes say and the name is what a human reads.
fn alg_json(alg: Option<i64>) -> Value {
    match alg {
        Some(a) => json!({ "value": a, "name": labels::alg::name(a) }),
        None => Value::Null,
    }
}

fn to_js<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Convenience for callers that only need the identity of the bytes, such as a
/// ledger explorer matching a statement against a transaction it already holds.
#[wasm_bindgen(js_name = claimDigest)]
pub fn claim_digest(statement: &[u8]) -> Result<String, JsValue> {
    let parsed = Sign1::parse(statement).map_err(to_js)?;
    let digest = parsed.claim_digest().map_err(to_js)?;
    Ok(scitt_receipt::cbor::hex(&digest))
}

/// Describe a bare receipt blob that arrived outside a statement.
#[wasm_bindgen(js_name = describeReceipt)]
pub fn describe_receipt_blob(receipt: &[u8]) -> Result<String, JsValue> {
    let summary = describe_receipt(receipt).map_err(to_js)?;
    let out = json!({
        "algorithm": alg_json(summary.algorithm),
        "kid": summary.kid,
        "issuer": summary.issuer,
        "subject": summary.subject,
        "registeredAt": summary.registered_at,
        "vds": summary.vds,
        "ccfTxId": summary.ccf_txid,
        "claimsDigest": summary.claims_digest,
        "commitEvidence": summary.commit_evidence,
        "writeSetDigest": summary.write_set_digest,
        "pathLength": summary.path_length,
        "problems": summary.problems,
    });
    serde_json::to_string(&out).map_err(to_js)
}

/// Describe a single certificate in isolation, for a UI that lets a user click
/// into a chain entry.
#[wasm_bindgen(js_name = describeCertificate)]
pub fn describe_certificate_der(index: usize, der: &[u8]) -> Result<String, JsValue> {
    serde_json::to_string(&certificate_json(&describe_certificate(index, der))).map_err(to_js)
}
