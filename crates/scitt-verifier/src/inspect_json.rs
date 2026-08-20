//! Machine-readable rendering of a statement's contents, without verification.
//!
//! The shape mirrors the COSE envelope — `protected`, `unprotected`, `payload`
//! — so that what you read here maps onto what is actually on the wire, and so
//! that headers this build does not interpret still appear rather than being
//! dropped. A field nobody renders is a field nobody audits.
//!
//! Two properties matter more than prettiness:
//!
//! 1. **Nothing here is verified.** The document says so in its own body, at
//!    the top, because a JSON blob outlives the command line that produced it.
//!    Someone who finds this file on disk must not be able to mistake it for
//!    the output of `verify --facts`, which requires a full verification.
//! 2. **Large blobs are summarised unless asked for.** A 56 KB base64 payload
//!    dumped by default makes the interesting 200 bytes unreadable and makes
//!    the tool useless in a terminal. `--verbose` opts in.

use scitt_receipt::cbor::{self, hex};
use scitt_receipt::{labels, CborValue, CertificateSummary, Sign1};
use serde_json::{json, Map, Value};

/// Text longer than this is summarised unless `--verbose` is given.
const TEXT_LIMIT: usize = 128;
/// Byte strings longer than this are summarised unless `--verbose` is given.
const BYTES_LIMIT: usize = 64;

/// Build the inspect document for a statement.
pub fn document(statement: &Sign1, verbose: bool) -> Value {
    let mut root = Map::new();

    root.insert("format".into(), json!("scitt-verifier/inspect/v1"));
    // First, and unconditional. This is the load-bearing field of the whole
    // document: everything below it is an unauthenticated assertion by whoever
    // produced the file.
    root.insert("verified".into(), json!(false));
    root.insert(
        "note".into(),
        json!("inspect does not verify anything. Use `verify` to make a decision."),
    );
    root.insert("verbose".into(), json!(verbose));
    root.insert("tagged".into(), json!(statement.was_tagged));

    root.insert(
        "protected".into(),
        header_bucket(&statement.protected, verbose),
    );
    root.insert(
        "unprotected".into(),
        header_bucket(&statement.unprotected, verbose),
    );
    root.insert("payload".into(), payload(statement, verbose));
    root.insert(
        "signature".into(),
        blob(&statement.signature, verbose, "signature"),
    );

    if let Ok(digest) = statement.claim_digest() {
        root.insert("claimDigest".into(), json!(hex(&digest)));
    }
    if let Ok(signed) = statement.signed_statement_bytes() {
        root.insert("signedBytes".into(), json!(signed.len()));
    }

    Value::Object(root)
}

/// Render a COSE header bucket, naming the labels this build understands.
///
/// Unknown labels are kept under their raw key rather than discarded, and are
/// listed in `notInterpreted` so a reader can tell at a glance that the tool
/// passed something through without understanding it.
fn header_bucket(bucket: &CborValue, verbose: bool) -> Value {
    let CborValue::Map(entries) = bucket else {
        return json!({});
    };

    let mut out = Map::new();
    let mut not_interpreted = Vec::new();

    for (key, value) in entries {
        let (name, known) = match key {
            CborValue::Int(i) => match labels::header_name(*i) {
                Some(name) => (name.to_string(), true),
                None => (i.to_string(), false),
            },
            CborValue::TextString(s) => (s.clone(), false),
            other => (cbor::type_name(other).to_string(), false),
        };
        if !known {
            not_interpreted.push(json!(name));
        }
        out.insert(name, header_value(key, value, verbose));
    }

    if !not_interpreted.is_empty() {
        out.insert("notInterpreted".into(), Value::Array(not_interpreted));
    }
    Value::Object(out)
}

/// Render one header, special-casing the labels with real structure.
fn header_value(key: &CborValue, value: &CborValue, verbose: bool) -> Value {
    let CborValue::Int(label) = key else {
        return generic(value, verbose);
    };
    match *label {
        labels::ALG => match cbor::as_int(value) {
            Ok(alg) => json!({ "id": alg, "name": labels::alg::name(alg) }),
            Err(_) => generic(value, verbose),
        },
        labels::CWT_CLAIMS => cwt_claims(value, verbose),
        // A CCF `kid` is a byte string holding ASCII hex, not raw digest
        // bytes. Hex-encoding it again would print the hex of the hex.
        labels::KID => match cbor::as_kid(value) {
            Ok(kid) => json!(kid),
            Err(_) => generic(value, verbose),
        },
        labels::X5CHAIN => x5chain(value, verbose),
        labels::X5T => x5t(value, verbose),
        labels::VDP => proofs(value, verbose),
        labels::RECEIPTS => receipts(value, verbose),
        _ => generic(value, verbose),
    }
}

fn cwt_claims(value: &CborValue, verbose: bool) -> Value {
    let CborValue::Map(entries) = value else {
        return generic(value, verbose);
    };
    let mut out = Map::new();
    for (key, v) in entries {
        let name = match key {
            CborValue::Int(i) => labels::cwt_claim_name(*i)
                .map(str::to_owned)
                .unwrap_or_else(|| i.to_string()),
            CborValue::TextString(s) => s.clone(),
            other => cbor::type_name(other).to_string(),
        };
        // Dates are rendered as numbers, not strings, and are unwrapped from
        // CBOR tag 1 where the producer used it. A timestamp that arrives as
        // a quoted string is a timestamp nothing will compare correctly.
        let rendered = match name.as_str() {
            "iat" | "nbf" | "exp" => match cbor::as_numeric_date(v) {
                Ok(seconds) => json!(seconds),
                Err(_) => generic(v, verbose),
            },
            _ => generic(v, verbose),
        };
        out.insert(name, rendered);
    }
    Value::Object(out)
}

/// The certificate chain, described rather than dumped.
///
/// Raw DER is available under `--verbose`, but the useful content of a chain
/// is its names, validity constraints and EKUs, so those are always present.
fn x5chain(value: &CborValue, verbose: bool) -> Value {
    let Ok(items) = cbor::as_array(value) else {
        return generic(value, verbose);
    };
    let certificates: Vec<Value> = items
        .iter()
        .enumerate()
        .map(|(index, item)| match cbor::as_bytes(item) {
            Ok(der) => certificate(
                &scitt_receipt::describe_certificate(index, der),
                der,
                verbose,
            ),
            Err(_) => generic(item, verbose),
        })
        .collect();
    Value::Array(certificates)
}

fn certificate(summary: &CertificateSummary, der: &[u8], verbose: bool) -> Value {
    let mut out = Map::new();
    out.insert("index".into(), json!(summary.index));
    out.insert("sha256".into(), json!(summary.sha256));
    out.insert("subject".into(), json!(summary.subject));
    out.insert("issuer".into(), json!(summary.issuer));
    out.insert("version".into(), json!(summary.version));
    out.insert("extendedKeyUsage".into(), json!(summary.extended_key_usage));
    out.insert("ekuCritical".into(), json!(summary.eku_critical));
    out.insert(
        "basicConstraints".into(),
        match summary.basic_constraints {
            Some((critical, ca, path_len)) => {
                json!({ "critical": critical, "ca": ca, "pathLenConstraint": path_len })
            }
            None => Value::Null,
        },
    );
    out.insert("keyCertSign".into(), json!(summary.key_cert_sign));
    // Non-empty means `verify` will reject this chain. Surfaced here so a
    // consumer can predict that without running it.
    out.insert(
        "unhandledCriticalExtensions".into(),
        json!(summary.unhandled_critical_extensions),
    );
    if let Some(problem) = &summary.problem {
        out.insert("problem".into(), json!(problem));
    }
    if verbose {
        out.insert("der".into(), json!(hex(der)));
    }
    Value::Object(out)
}

fn x5t(value: &CborValue, verbose: bool) -> Value {
    let Ok(items) = cbor::as_array(value) else {
        return generic(value, verbose);
    };
    if items.len() != 2 {
        return generic(value, verbose);
    }
    match (cbor::as_int(&items[0]), cbor::as_bytes(&items[1])) {
        (Ok(alg), Ok(digest)) => json!({
            "alg": alg,
            "algName": labels::alg::name(alg),
            "hash": hex(digest),
        }),
        _ => generic(value, verbose),
    }
}

/// Receipts, parsed as the nested COSE_Sign1 envelopes they are.
///
/// Recursing matters: a receipt's own headers carry the ledger identity, the
/// transaction id and the commit evidence, and leaving them as an opaque byte
/// string is how the interesting half of a transparent statement goes unread.
fn receipts(value: &CborValue, verbose: bool) -> Value {
    let Ok(items) = cbor::as_array(value) else {
        return generic(value, verbose);
    };
    let rendered: Vec<Value> = items
        .iter()
        .map(|item| {
            let Ok(bytes) = cbor::as_bytes(item) else {
                return generic(item, verbose);
            };
            match Sign1::parse(bytes) {
                Ok(receipt) => {
                    let mut out = Map::new();
                    out.insert(
                        "protected".into(),
                        header_bucket(&receipt.protected, verbose),
                    );
                    out.insert(
                        "unprotected".into(),
                        header_bucket(&receipt.unprotected, verbose),
                    );
                    out.insert(
                        "payload".into(),
                        match &receipt.payload {
                            Some(p) => blob(p, verbose, "payload"),
                            None => Value::Null,
                        },
                    );
                    out.insert(
                        "signature".into(),
                        blob(&receipt.signature, verbose, "signature"),
                    );
                    if let Ok(summary) = scitt_receipt::describe_receipt(bytes) {
                        out.insert(
                            "ccf".into(),
                            json!({
                                "txid": summary.ccf_txid,
                                "commitEvidence": summary.commit_evidence,
                                "writeSetDigest": summary.write_set_digest,
                                "claimsDigest": summary.claims_digest,
                                "inclusionPathLength": summary.path_length,
                            }),
                        );
                        if !summary.problems.is_empty() {
                            out.insert("problems".into(), json!(summary.problems));
                        }
                    }
                    Value::Object(out)
                }
                Err(e) => json!({
                    "problem": format!("receipt is not a decodable COSE_Sign1: {e}"),
                    "bytes": bytes.len(),
                }),
            }
        })
        .collect();
    Value::Array(rendered)
}

/// The verifiable data proofs bucket, with the inclusion proof named.
///
/// The wire key is `-1`, which tells a reader nothing. Naming it costs nothing
/// and is the difference between a proof somebody reads and a proof somebody
/// scrolls past.
fn proofs(value: &CborValue, verbose: bool) -> Value {
    let CborValue::Map(entries) = value else {
        return generic(value, verbose);
    };
    let mut out = Map::new();
    for (key, item) in entries {
        if matches!(key, CborValue::Int(i) if *i == labels::PROOF_INCLUSION) {
            out.insert("inclusionProof".into(), inclusion_proofs(item, verbose));
            continue;
        }
        let name = match key {
            CborValue::Int(i) => i.to_string(),
            CborValue::TextString(s) => s.clone(),
            other => cbor::type_name(other).to_string(),
        };
        out.insert(name, generic(item, verbose));
    }
    Value::Object(out)
}

/// Inclusion proofs: summarised by default, decoded under `--verbose`.
///
/// The decoded form is what the receipt stores, not what it implies. No hash is
/// computed and no root is reached here — printing a Merkle root next to an
/// unverified proof is how a reader talks themselves into believing it.
fn inclusion_proofs(value: &CborValue, verbose: bool) -> Value {
    let Ok(items) = cbor::as_array(value) else {
        return generic(value, verbose);
    };
    let rendered: Vec<Value> = items
        .iter()
        .map(|item| {
            let Ok(bytes) = cbor::as_bytes(item) else {
                return generic(item, verbose);
            };
            if !verbose {
                return json!({
                    "bytes": bytes.len(),
                    "sha256": scitt_receipt::sha256_hex(bytes),
                    "elided": true,
                    "what": "inclusionProof",
                });
            }
            match scitt_receipt::describe_inclusion_proof(bytes) {
                Ok(proof) => json!({
                    "leaf": {
                        "writeSetDigest": proof.write_set_digest,
                        "commitEvidence": proof.commit_evidence,
                        "claimsDigest": proof.claims_digest,
                    },
                    "path": proof
                        .path
                        .iter()
                        .map(|step| json!({
                            "sibling": if step.sibling_left { "left" } else { "right" },
                            "digest": step.digest,
                        }))
                        .collect::<Vec<_>>(),
                }),
                Err(e) => json!({
                    "problem": format!("inclusion proof could not be decoded: {e}"),
                    "bytes": bytes.len(),
                }),
            }
        })
        .collect();
    Value::Array(rendered)
}

/// The payload, decoded when it is text and asked for.
///
/// Emitting the decoded bytes rather than base64 is deliberate: base64 of a
/// JSON document is a second thing to decode before anyone can read the first.
fn payload(statement: &Sign1, verbose: bool) -> Value {
    let Some(bytes) = &statement.payload else {
        return json!({ "detached": true });
    };
    let mut out = Map::new();
    out.insert("bytes".into(), json!(bytes.len()));
    out.insert("sha256".into(), json!(scitt_receipt::sha256_hex(bytes)));
    if let Some(cty) = statement.content_type() {
        out.insert("contentType".into(), json!(cty));
    }

    if verbose {
        match std::str::from_utf8(bytes) {
            Ok(text) => match serde_json::from_str::<Value>(text) {
                Ok(parsed) => {
                    out.insert("json".into(), parsed);
                }
                Err(_) => {
                    out.insert("text".into(), json!(text));
                }
            },
            Err(_) => {
                out.insert("hex".into(), json!(hex(bytes)));
            }
        }
    } else {
        out.insert("elided".into(), json!(true));
    }
    Value::Object(out)
}

/// Summarise a byte string, or render it in full when asked.
fn blob(bytes: &[u8], verbose: bool, what: &str) -> Value {
    if verbose || bytes.len() <= BYTES_LIMIT {
        json!({ "bytes": bytes.len(), "hex": hex(bytes) })
    } else {
        json!({
            "bytes": bytes.len(),
            "sha256": scitt_receipt::sha256_hex(bytes),
            "elided": true,
            "what": what,
        })
    }
}

/// Render any CBOR value, eliding anything large unless `--verbose`.
fn generic(value: &CborValue, verbose: bool) -> Value {
    match value {
        CborValue::Int(i) => json!(i),
        CborValue::TextString(s) => {
            if verbose || s.len() <= TEXT_LIMIT {
                json!(s)
            } else {
                json!({
                    "chars": s.len(),
                    "sha256": scitt_receipt::sha256_hex(s.as_bytes()),
                    "preview": format!("{}…", &s[..char_boundary(s, 32)]),
                    "elided": true,
                })
            }
        }
        CborValue::ByteString(b) => blob(b, verbose, "value"),
        CborValue::Array(items) => {
            Value::Array(items.iter().map(|v| generic(v, verbose)).collect())
        }
        CborValue::Map(entries) => {
            let mut out = Map::new();
            for (k, v) in entries {
                let key = match k {
                    CborValue::Int(i) => i.to_string(),
                    CborValue::TextString(s) => s.clone(),
                    other => cbor::type_name(other).to_string(),
                };
                out.insert(key, generic(v, verbose));
            }
            Value::Object(out)
        }
        CborValue::Tagged { tag, payload } => json!({
            "tag": tag,
            "value": generic(payload, verbose),
        }),
        CborValue::Simple(20) => json!(false),
        CborValue::Simple(21) => json!(true),
        CborValue::Simple(22) => Value::Null,
        CborValue::Simple(n) => json!({ "simple": n }),
    }
}

/// Largest char boundary at or below `limit`, so slicing cannot panic.
fn char_boundary(s: &str, limit: usize) -> usize {
    if limit >= s.len() {
        return s.len();
    }
    let mut end = limit;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_text_header_is_summarised_but_not_dropped() {
        let long = "A".repeat(TEXT_LIMIT + 50);
        let value = CborValue::TextString(long.clone());

        let elided = generic(&value, false);
        assert_eq!(elided["chars"], json!(long.len()));
        assert_eq!(elided["elided"], json!(true));
        assert!(elided["preview"].as_str().unwrap().ends_with('…'));

        assert_eq!(generic(&value, true), json!(long));
    }

    #[test]
    fn a_short_value_is_identical_in_both_modes() {
        let value = CborValue::TextString("application/json".into());
        assert_eq!(generic(&value, false), generic(&value, true));
    }

    #[test]
    fn eliding_a_multibyte_string_does_not_split_a_character() {
        let value = CborValue::TextString("é".repeat(TEXT_LIMIT));
        let elided = generic(&value, false);
        // Reaching this assertion at all is the test: slicing on a non-boundary
        // would have panicked above.
        assert_eq!(elided["elided"], json!(true));
    }

    #[test]
    fn a_tagged_date_is_a_number_not_a_string() {
        let claims = CborValue::Map(vec![(
            CborValue::Int(labels::CWT_IAT),
            CborValue::Tagged {
                tag: 1,
                payload: Box::new(CborValue::Int(1_786_995_989)),
            },
        )]);
        assert_eq!(cwt_claims(&claims, false)["iat"], json!(1_786_995_989));
    }
}
