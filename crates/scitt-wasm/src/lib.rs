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

use scitt_policy::Policy;
use scitt_receipt::{
    base64::Alphabet, binding::BindingMode, chain, describe_certificate, describe_receipt,
    keys::KeyLookup, labels, CertificateSummary, CwtClaims, LedgerKeySet, ReceiptFacts, Sign1,
    StatementFacts, VerifyOptions,
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
/// The key set is deliberately not scoped to an issuer. A receipt from some
/// other transparency service is signed by *that* service's key, so it fails
/// signature verification here on its own merits. Which issuer a caller is
/// willing to accept is a policy question, and the receipt's `issuer` is
/// reported below for the caller to assert on.
///
/// Returns a JSON document. Errors are returned as JS exceptions only when
/// nothing could be established at all; a statement that parses but fails
/// verification is a *result*, not an error, and callers must render it.
///
/// `trustedRoots` is optional PEM holding one or more CA certificates. Without
/// it the signing chain is still validated, but only to the root the statement
/// itself carries, and `chainValidation.anchoredExternally` says so. With it,
/// the chain must lead to one of those roots. Roots that cannot be read are an
/// exception, not a result: running the weaker check under the stronger
/// request would report something nobody asked for.
#[wasm_bindgen(js_name = verifyStatement)]
pub fn verify_statement(
    statement: &[u8],
    key_set: &[u8],
    trusted_roots: Option<String>,
) -> Result<String, JsValue> {
    let options = verify_options(trusted_roots.as_deref())?;
    let keys = LedgerKeySet::from_cose_key_set(key_set).map_err(to_js)?;

    let facts = scitt_receipt::verify_statement_with(statement, &keys, &options).map_err(to_js)?;

    // Re-parsing to describe the chain costs a few hundred microseconds and
    // saves the caller a second entry point. The chain is what a human looks
    // at first when a signature fails to verify.
    let chain = Sign1::parse(statement)
        .map(|s| s.describe_chain())
        .unwrap_or_default();

    let mut out = statement_facts_json(&facts);
    out["certificateChain"] = Value::Array(chain.iter().map(certificate_json).collect());
    out["keySet"] = json!({
        "keyCount": keys.keys.len(),
        "revokedKids": keys.revoked_kids,
        // A rotation can introduce a curve this build does not know. Refusing
        // the whole set would turn a routine rotation into an outage, so the
        // skipped entries are reported instead of being fatal.
        "skipped": keys.skipped,
    });

    serde_json::to_string(&out).map_err(to_js)
}

/// Verify a statement using only the key the service certificate vouches for.
///
/// For a page that fetched the key set through a channel it cannot
/// authenticate, such as a proxy in front of a ledger whose TLS certificate a
/// browser will not accept. The service certificate comes from somewhere the
/// page *can* authenticate, typically the identity service over the public web
/// PKI, and is the only trust anchor here. The command-line tool gets the same
/// assurance by pinning the ledger connection to that certificate; a browser
/// cannot pin, so the binding is checked over the bytes instead.
///
/// Two consequences:
///
/// - The key set must contain exactly one entry whose `kid` is the hash of the
///   certificate's public key and whose material hashes to that `kid`. If it
///   does not, nothing is verified and `serviceKey.bound` is `false` with a
///   `mismatch` code. This is a finding about the key set, and is returned as
///   a result rather than an exception so a page can render it.
/// - Every other key in the set is discarded before verification. Whoever
///   served the set could have added one, so a receipt signed by any other key
///   (for example one that predates a disaster recovery) is reported as an
///   unknown `kid` and left unevaluated, never verified.
///
/// `serviceCert` is PEM holding exactly one certificate: the
/// `ledgerTlsCertificate` field of the identity service's response.
/// `trustedRoots` is as for `verifyStatement`, and anchors the *signer's*
/// chain; it has nothing to do with the service certificate.
#[wasm_bindgen(js_name = verifyStatementWithServiceCert)]
pub fn verify_statement_with_service_cert(
    statement: &[u8],
    key_set: &[u8],
    service_cert: &str,
    trusted_roots: Option<String>,
) -> Result<String, JsValue> {
    let options = verify_options(trusted_roots.as_deref())?;
    let (service_key_kid, service_cert_sha256) = service_cert_identity(service_cert)?;

    let keys = LedgerKeySet::from_cose_key_set(key_set).map_err(to_js)?;

    let key_set_json = json!({
        "keyCount": keys.keys.len(),
        "revokedKids": keys.revoked_kids,
        "skipped": keys.skipped,
    });

    let key = match keys.service_key(&service_key_kid) {
        Ok(key) => key,
        Err(mismatch) => {
            let out = json!({
                "serviceKey": {
                    "kid": service_key_kid,
                    "certificateSha256": service_cert_sha256,
                    "bound": false,
                    "mismatch": mismatch.code(),
                },
                "keySet": key_set_json,
            });
            return serde_json::to_string(&out).map_err(to_js);
        }
    };

    let only = keys.restricted_to(key);
    let facts = scitt_receipt::verify_statement_with(statement, &only, &options).map_err(to_js)?;

    let chain = Sign1::parse(statement)
        .map(|s| s.describe_chain())
        .unwrap_or_default();

    let mut out = statement_facts_json(&facts);
    out["certificateChain"] = Value::Array(chain.iter().map(certificate_json).collect());
    out["serviceKey"] = json!({
        "kid": service_key_kid,
        "certificateSha256": service_cert_sha256,
        "bound": true,
        "mismatch": Value::Null,
    });
    out["keySet"] = key_set_json;
    // How many served keys were set aside. A non-zero count is normal after a
    // rotation and is reported so a page can explain an unevaluated receipt.
    out["keySet"]["unvouchedKeyCount"] = json!(keys.keys.len() - 1);

    serde_json::to_string(&out).map_err(to_js)
}

/// The `kid` a service certificate vouches for, and the certificate's digest.
fn service_cert_identity(service_cert: &str) -> Result<(String, String), JsValue> {
    let certs = chain::parse_pem_certificates(service_cert).map_err(to_js)?;
    let [cert] = certs.as_slice() else {
        return Err(to_js(format!(
            "serviceCert must hold exactly one certificate, found {}",
            certs.len()
        )));
    };
    let spki = scitt_receipt::spki_from_certificate_der(cert).map_err(to_js)?;
    Ok((
        scitt_receipt::sha256_hex(&spki),
        scitt_receipt::sha256_hex(cert),
    ))
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
        // The same shape the CLI's `--facts` reports under `certificateChain`.
        // Named differently here only because that key already holds the
        // described certificates in this API.
        "chainValidation": chain_validation_json(facts.chain_outcome.as_ref()),
        // From the ledger's countersigned registration times, never the
        // statement's own `iat`, which the signer chooses.
        "certificatesValidAtRegistration": facts.certificates_valid_at_signing_time,
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

/// Chain validation always runs, as it does in the CLI. Skipping it when no
/// roots were supplied would leave a page with nothing to say about the chain,
/// when "consistent with its own embedded root" is both true and worth saying
/// next to "not anchored to anything you trust".
fn verify_options(trusted_roots: Option<&str>) -> Result<VerifyOptions, JsValue> {
    let mut chain = chain::Options::default();
    if let Some(pem) = trusted_roots {
        chain.trusted_roots =
            chain::parse_pem_certificates(pem).map_err(|e| to_js(format!("trustedRoots: {e}")))?;
    }
    Ok(VerifyOptions { chain: Some(chain) })
}

/// Projected the way the CLI's record projects it, so a page and `--facts`
/// can be compared field by field.
fn chain_validation_json(outcome: Option<&chain::Outcome>) -> Value {
    let Some(outcome) = outcome else {
        return json!({ "status": "notEvaluated" });
    };
    match outcome {
        chain::Outcome::Valid(details) => json!({
            "status": "evaluated",
            "outcome": "valid",
            "rootSha256": scitt_receipt::cbor::hex(&details.root_sha256),
            "anchoredExternally": details.anchored_externally,
            "validatedAt": details.validated_at,
            "pathLength": details.path_len,
            "pathNotBefore": details.path_not_before,
            "pathNotAfter": details.path_not_after,
        }),
        chain::Outcome::Invalid(reason) => {
            json!({ "status": "evaluated", "outcome": "invalid", "reason": reason })
        }
        chain::Outcome::Insufficient(reason) => {
            json!({ "status": "evaluated", "outcome": "insufficient", "reason": reason })
        }
        chain::Outcome::Unsupported(reason) => {
            json!({ "status": "evaluated", "outcome": "unsupported", "reason": reason })
        }
    }
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

/// The statement's payload, decoded for display.
///
/// Split out rather than folded into `inspectStatement` because payloads are
/// routinely large — a hardware BOM statement can carry tens of KB of SPDX — and a
/// caller rendering a summary should not have to receive and discard the whole
/// document to do it.
///
/// Two distinctions are load-bearing:
///
/// **A detached payload is not an empty one.** `{"detached": true}` means the
/// bytes travel separately, so there is nothing here to show and nothing has
/// gone wrong. Rendering that as an empty document would invite the reader to
/// conclude the statement says nothing.
///
/// **A hash envelope's payload is a digest, not content** (RFC 9995). For one
/// of those, `sha256` is deliberately absent: it would be the hash of a hash —
/// a number that looks exactly like the artifact digest a reader is hunting
/// for, sitting next to a field called `sha256`, and it identifies nothing. The
/// digest itself is published under `hashEnvelope.digest` instead, which is the
/// value that actually means something.
#[wasm_bindgen(js_name = statementPayload)]
pub fn statement_payload(statement: &[u8]) -> Result<String, JsValue> {
    let parsed = Sign1::parse(statement).map_err(to_js)?;

    let Some(bytes) = parsed.payload.as_deref() else {
        return serde_json::to_string(&json!({ "detached": true })).map_err(to_js);
    };

    let mut out = Map::new();
    out.insert("detached".into(), json!(false));
    out.insert("length".into(), json!(bytes.len()));
    out.insert("contentType".into(), json!(parsed.content_type()));

    if let Some(alg) = parsed.payload_hash_alg() {
        out.insert(
            "hashEnvelope".into(),
            json!({
                "hashAlg": labels::alg::name(alg),
                "hashAlgLabel": alg,
                "digest": scitt_receipt::cbor::hex(bytes),
                "preimageContentType": parsed.payload_preimage_content_type(),
                "preimageLocation": parsed.payload_location(),
            }),
        );
        // Deliberately no `text`, `hex` or `sha256`: see above.
        return serde_json::to_string(&Value::Object(out)).map_err(to_js);
    }

    out.insert("hashEnvelope".into(), Value::Null);
    out.insert("sha256".into(), json!(scitt_receipt::sha256_hex(bytes)));

    // Text when it is text. Handing back base64 of a JSON document gives the
    // caller a second thing to decode before it can read the first, and every
    // caller would then decode it the same way.
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            out.insert("text".into(), json!(text));
            out.insert("hex".into(), Value::Null);
        }
        Err(_) => {
            out.insert("text".into(), Value::Null);
            out.insert("hex".into(), json!(scitt_receipt::cbor::hex(bytes)));
        }
    }

    serde_json::to_string(&Value::Object(out)).map_err(to_js)
}

/// Decode one encoded claim inside a JSON payload, and report its digest.
///
/// The browser counterpart of `inspect --decode`, reading the claim through
/// the same extraction (`scitt_policy::claim::encoded_claim_bytes`), so a
/// digest shown on a page and one printed in CI are over the same bytes by
/// construction.
///
/// `path` is written the way `inspect` prints it, `['security-policy-base64']`.
/// `encoding` is `base64` or `base64url` and is required: nothing is decoded
/// that the caller did not name, and no encoding is guessed from the value.
///
/// Decoding is not verification. The bytes inherit whatever status the
/// statement has, and a page that shows this beside a failed signature must
/// not let the digest read as an endorsement.
///
/// A claim that cannot be read — a detached or non-JSON payload, a path that
/// reaches nothing, a value that is not the named encoding — is an exception
/// whose message is a sentence about this statement.
#[wasm_bindgen(js_name = decodeClaim)]
pub fn decode_claim(statement: &[u8], path: &str, encoding: &str) -> Result<String, JsValue> {
    let segments = scitt_policy::parse_path(path).map_err(to_js)?;
    let alphabet = Alphabet::parse(encoding).map_err(to_js)?;
    let parsed = Sign1::parse(statement).map_err(to_js)?;

    let at = scitt_policy::describe_path(&segments);
    let bytes = scitt_policy::claim::encoded_claim_bytes(&parsed, &segments, alphabet)
        .map_err(|why| to_js(format!("{at}: {}", why.describe())))?;

    // Text when it is text, hex when it is not, and never a lossy conversion:
    // replacement characters would render content that is not in the bytes,
    // beside a digest of bytes that are.
    let (text, hex) = match std::str::from_utf8(&bytes) {
        Ok(t) => (Some(t.to_string()), None),
        Err(_) => (None, Some(scitt_receipt::cbor::hex(&bytes))),
    };

    let out = json!({
        "path": at,
        "encoding": alphabet.name(),
        "length": bytes.len(),
        "sha256": scitt_receipt::sha256_hex(&bytes),
        "utf8": text.is_some(),
        "text": text,
        "hex": hex,
    });
    serde_json::to_string(&out).map_err(to_js)
}

/// Compare an artifact against what a statement says about it.
///
/// This is the check that turns "the statement is genuine" into "the statement
/// is about the file I am holding" — two claims that are routinely confused
/// and that fail independently. A statement can verify perfectly and describe
/// something else entirely.
///
/// The comparison itself is `scitt_receipt::bind`, the same code path the
/// command-line tool takes. Reimplementing it here in JavaScript was the
/// obvious shortcut and the wrong one: a browser and a pipeline that disagreed
/// about a hash envelope or a detached payload would surface the disagreement
/// as a release that should have been stopped.
///
/// `mode` is required and never inferred from the statement. Choosing
/// `payload-digest` for the caller because the statement happens to be a hash
/// envelope would report a relationship the operator never asserted; the CLI
/// refuses to guess for the same reason.
///
/// Three outcomes, and the third is the one that matters most:
///
/// - `bound` — the artifact is the one the statement describes.
/// - `mismatch` — it is not. This is a finding about the artifact.
/// - `cannotCompare` — the question could not be answered: a detached payload,
///   a mode that does not fit, or a hash this build cannot compute. This is a
///   fact about the comparison, **not** about the artifact, and a caller that
///   renders it as a failure is accusing an operator of shipping the wrong
///   file when the real fault is the request.
#[wasm_bindgen(js_name = bindArtifact)]
pub fn bind_artifact(
    statement: &[u8],
    artifact: &[u8],
    mode: &str,
    artifact_name: &str,
) -> Result<String, JsValue> {
    let mode = match mode {
        "payload-bytes" => BindingMode::PayloadBytes,
        "payload-digest" => BindingMode::PayloadDigest,
        other => {
            return Err(to_js(format!(
                "unknown binding mode '{other}'; expected 'payload-bytes' or 'payload-digest'"
            )))
        }
    };

    let parsed = Sign1::parse(statement).map_err(to_js)?;
    let report = scitt_receipt::bind(&parsed, artifact, mode);

    // Prose that names nothing reads as though some unnamed file was compared,
    // so fall back to a phrase rather than emitting an empty name.
    let name = if artifact_name.is_empty() {
        "the artifact"
    } else {
        artifact_name
    };

    let out = json!({
        "mode": mode.as_str(),
        "outcome": report.outcome.as_str(),
        "reason": report.reason.code(),
        "detail": report.reason.describe(name),
        "artifactName": name,
        "artifactLength": artifact.len(),
        "artifactSha256": scitt_receipt::sha256_hex(artifact),
    });
    serde_json::to_string(&out).map_err(to_js)
}

/// Evaluate a caller-supplied relying-party policy over a statement's facts.
///
/// ## Why this is not a verdict
///
/// The return value is one `outcome` per assertion, plus the three aggregate
/// predicates those outcomes support. It is not a pass/fail for the statement,
/// and there is no field here that a caller can render as one. Turning
/// outcomes into a verdict is `decide()`'s job in `scitt-verifier`, and the
/// equivalent choice belongs to whoever consumes this — which is the same
/// division of labour the rest of this crate observes.
///
/// ## Why it re-verifies rather than taking facts back from JavaScript
///
/// Policy is evaluated over `StatementFacts`, and the only trustworthy source
/// of those is this module. Accepting them back across the boundary as JSON
/// would let a page evaluate policy against facts it had edited, which is a
/// verifier that can be talked out of its own findings. Re-deriving them costs
/// a few milliseconds and keeps every call stateless — no handles to leak, and
/// a re-evaluation loop that cannot drift from the bytes it started with.
///
/// `now` is a Unix timestamp in seconds, supplied by the caller because the
/// core does not read the clock. Pass `Math.floor(Date.now() / 1000)` for live
/// use, or a fixed value to make a run reproducible — the same reason the CLI
/// offers `--now`.
///
/// It is taken as a `f64` rather than an `i64` so that callers pass a plain
/// number instead of a `BigInt`; seconds since the epoch are nowhere near
/// `Number.MAX_SAFE_INTEGER`, so nothing is lost. A non-integral or non-finite
/// value is rejected rather than truncated: `now` decides freshness, and a
/// clock that is silently wrong is worse than one that refuses.
///
/// `trustedRoots` is as for `verifyStatement`. Pass the same value to both, or
/// `certificateChainValidated` and `requireChainToRootSha256` will be answered
/// about a different chain from the one the page displays.
///
/// `serviceCert` is as for `verifyStatementWithServiceCert`, and restricts the
/// key set the same way. A page that verified through the service certificate
/// must pass it here too; otherwise policy is evaluated over receipts checked
/// against keys the page itself just declined to trust. A key set holding no
/// key bound to the certificate is an exception here, because there are no
/// facts to evaluate; `verifyStatementWithServiceCert` reports it as a result.
#[wasm_bindgen(js_name = evaluatePolicy)]
pub fn evaluate_policy(
    statement: &[u8],
    key_set: &[u8],
    policy: &[u8],
    now: f64,
    trusted_roots: Option<String>,
    service_cert: Option<String>,
) -> Result<String, JsValue> {
    if !now.is_finite() || now.fract() != 0.0 || now.abs() > 9_007_199_254_740_991.0 {
        return Err(JsValue::from_str(
            "now must be a whole number of seconds since the Unix epoch",
        ));
    }
    let now = now as i64;

    // A malformed policy is a usage error, not a finding: nothing was
    // evaluated, so there is no result to render and an exception is honest.
    let policy = Policy::from_json(policy).map_err(to_js)?;
    let options = verify_options(trusted_roots.as_deref())?;

    let keys = LedgerKeySet::from_cose_key_set(key_set).map_err(to_js)?;
    let keys = match service_cert.as_deref() {
        Some(pem) => {
            let (kid, _) = service_cert_identity(pem)?;
            let key = keys.service_key(&kid).map_err(|m| {
                to_js(format!(
                    "the key set holds no key bound to the service certificate ({})",
                    m.code()
                ))
            })?;
            keys.restricted_to(key)
        }
        None => keys,
    };
    let facts = scitt_receipt::verify_statement_with(statement, &keys, &options).map_err(to_js)?;

    let decision = policy.evaluate(&facts, now);

    let out = json!({
        "policyId": decision.policy_id,
        "policyVersion": decision.policy_version,
        // All three are reported because `satisfied == false` does not say
        // which kind of false. A statement that claims too low an SVN and one
        // that claims none at all are different events, and a UI that shows a
        // single negative badge for both is the "unexplained check" this tool
        // exists to avoid.
        "satisfied": decision.satisfied(),
        "failed": decision.failed(),
        "unevaluable": decision.unevaluable(),
        "assertions": decision.results,
    });

    serde_json::to_string(&out).map_err(to_js)
}
