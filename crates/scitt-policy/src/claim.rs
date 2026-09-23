//! Read the exact bytes of an encoded claim out of a statement's payload.
//!
//! A producer that embeds a nested document — a build policy, an SBOM, a
//! confidential-container execution policy — does it by encoding the bytes
//! into a JSON string. Two very different callers need those bytes back:
//!
//! * `inspect --decode`, which shows them to a person and prints their digest;
//! * an adapter, which hashes them and compares the digest against something
//!   an attested environment says it is enforcing.
//!
//! Those two must extract *identically*. If they did not, a person could
//! inspect a statement, read a digest, and compare it by hand against a value
//! the adapter derived from different bytes of the same field — and the
//! disagreement would look like a policy mismatch rather than like a bug here.
//! So extraction lives in one place, and both callers go through it.
//!
//! What this module does not do is authenticate anything. It is handed a
//! parsed statement and returns what a field contains. Whether that statement
//! was signed by someone the caller trusts is a question answered before these
//! bytes are worth anything, and is answered elsewhere.

use crate::PathSegment;
use scitt_receipt::base64::Alphabet;
use scitt_receipt::Sign1;

/// Why a claim's bytes could not be read.
///
/// Carried as a typed reason rather than a formatted sentence so a caller can
/// decide how to present it — `inspect` writes it into an error message, an
/// adapter turns it into a check state — without either of them re-deriving
/// what went wrong by matching on prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// The statement has no payload to read.
    DetachedPayload,
    /// Nothing declares the payload to be JSON.
    NoContentType,
    /// The payload is declared to be something other than JSON.
    NotJson { declared: String },
    /// The payload does not parse as JSON, despite the declared content type.
    Malformed { why: String },
    /// The path could not be walked.
    UnresolvablePath { why: String },
    /// The path walked cleanly and arrived at nothing.
    NoSuchClaim,
    /// The claim exists but is not a string, so it cannot carry an encoding.
    NotAString { found: &'static str },
    /// The string is not valid in the encoding it was said to be in.
    NotEncoded { encoding: &'static str, why: String },
}

impl ClaimError {
    /// A sentence about this statement, without the claim path.
    ///
    /// Callers prepend the path, because they differ in how they render it.
    pub fn describe(&self) -> String {
        match self {
            Self::DetachedPayload => {
                "the statement has a detached payload, so there is nothing here to read".to_string()
            }
            Self::NoContentType => {
                "the statement declares no content type, so nothing says its payload is JSON"
                    .to_string()
            }
            Self::NotJson { declared } => format!(
                "the statement declares its payload to be '{declared}', not JSON, so it has no \
                 claims to address"
            ),
            Self::Malformed { why } => {
                format!("the payload is not valid JSON, despite the declared content type: {why}")
            }
            Self::UnresolvablePath { why } => why.clone(),
            Self::NoSuchClaim => "no such claim".to_string(),
            Self::NotAString { found } => {
                format!("the claim is {found}, and only a string can carry an encoded value")
            }
            Self::NotEncoded { encoding, why } => {
                format!("the claim is not valid {encoding}: {why}")
            }
        }
    }
}

/// Decode the claim at `path`, returning the exact bytes it encodes.
///
/// `alphabet` is supplied by the caller and never inferred. Sniffing a string
/// to guess whether it looks like base64 would decode values the producer
/// never said were encoded, against attacker-supplied bytes, on every run.
pub fn encoded_claim_bytes(
    statement: &Sign1,
    path: &[PathSegment],
    alphabet: Alphabet,
) -> Result<Vec<u8>, ClaimError> {
    let Some(payload) = &statement.payload else {
        return Err(ClaimError::DetachedPayload);
    };

    // The same rule `payloadJson` and the claim listing follow: only a payload
    // the statement *declares* to be JSON is parsed. Sniffing the bytes would
    // decode a structure the issuer never claimed was there.
    let Some(content_type) = statement.content_type() else {
        return Err(ClaimError::NoContentType);
    };
    if !crate::declares_json(&content_type) {
        return Err(ClaimError::NotJson {
            declared: content_type,
        });
    }

    // The strict parser, not `serde_json::from_slice`. It refuses duplicate
    // object keys, which matters here more than anywhere: a payload carrying
    // `{"policy":"YQ==","policy":"Yg=="}` has two answers for one path, and a
    // permissive parser silently takes the last. A digest would then be
    // published for one of two values the producer offered, while a
    // `payloadJson` rule over the same document refused it as ambiguous.
    // Extraction and evaluation must agree about what a document says.
    let document =
        crate::parse_payload_json(payload).map_err(|why| ClaimError::Malformed { why })?;

    let found = crate::resolve_json_path(&document, path)
        .map_err(|why| ClaimError::UnresolvablePath { why })?;

    let Some(value) = found else {
        return Err(ClaimError::NoSuchClaim);
    };

    let serde_json::Value::String(encoded) = value else {
        return Err(ClaimError::NotAString {
            found: describe_type(value),
        });
    };

    scitt_receipt::base64::decode(alphabet, encoded).map_err(|why| ClaimError::NotEncoded {
        encoding: alphabet.name(),
        why: why.to_string(),
    })
}

/// SHA-256 over the exact bytes the claim at `path` encodes.
///
/// This is the number an adapter compares against a value an attested
/// environment reports it is enforcing, so three things about it are
/// load-bearing:
///
/// * it is over the **decoded** bytes, not the base64 text that carried them,
///   not a preview, and not a re-indented rendering;
/// * it is returned as bytes, so the comparison is against a digest rather
///   than against a rendering of one;
/// * it comes from the same extraction `inspect --decode` prints, so a digest
///   a person reads on screen and a digest an adapter compares are over the
///   same bytes by construction.
///
/// Producers publish this digest alongside the encoded field — a statement
/// carrying `security-policy-base64` carries `security-policy-sha256` beside
/// it — and the value here is directly comparable to the published one.
///
/// Computing a digest is not authenticating one. Whether the statement these
/// bytes came from was signed by anyone in particular is decided elsewhere,
/// and this number is worth nothing until it has been.
pub fn encoded_claim_digest(
    statement: &Sign1,
    path: &[PathSegment],
    alphabet: Alphabet,
) -> Result<[u8; 32], ClaimError> {
    let bytes = encoded_claim_bytes(statement, path, alphabet)?;
    Ok(scitt_receipt::sha256(&bytes))
}

/// How a JSON value is named in an error a person has to act on.
pub fn describe_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scitt_receipt::labels;
    use scitt_receipt::CborValue;

    /// A statement whose payload is `body` and whose content type is `ct`.
    ///
    /// Built as a struct literal rather than parsed from encoded CBOR because
    /// nothing here touches the signature or the protected bytes — this module
    /// reads a declared content type and a payload, and those are exactly what
    /// varies across these cases.
    fn statement(ct: Option<&str>, body: &[u8]) -> Sign1 {
        let mut protected = Vec::new();
        if let Some(ct) = ct {
            protected.push((
                CborValue::Int(labels::CONTENT_TYPE),
                CborValue::TextString(ct.to_string()),
            ));
        }
        Sign1 {
            was_tagged: false,
            protected_raw: Vec::new(),
            protected: CborValue::Map(protected),
            unprotected: CborValue::Map(Vec::new()),
            payload: Some(body.to_vec()),
            signature: Vec::new(),
        }
    }

    fn path(name: &str) -> Vec<PathSegment> {
        vec![PathSegment::Text(name.to_string())]
    }

    #[test]
    fn the_bytes_are_what_the_field_encodes() {
        // "hello" in standard base64.
        let s = statement(Some("application/json"), br#"{"p":"aGVsbG8="}"#);
        let bytes = encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn a_duplicate_key_is_refused_rather_than_resolved() {
        // Two answers for one path is not a value; it is an ambiguity. Taking
        // the last would publish a digest for one of two offered values.
        let s = statement(Some("application/json"), br#"{"p":"YQ==","p":"Yg=="}"#);
        let err = encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap_err();
        assert!(matches!(err, ClaimError::Malformed { .. }), "{err:?}");
    }

    #[test]
    fn a_payload_not_declared_json_is_not_sniffed() {
        let s = statement(Some("application/cose"), br#"{"p":"aGVsbG8="}"#);
        let err = encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap_err();
        assert_eq!(
            err,
            ClaimError::NotJson {
                declared: "application/cose".to_string()
            }
        );
    }

    #[test]
    fn an_undeclared_content_type_is_not_assumed_to_be_json() {
        let s = statement(None, br#"{"p":"aGVsbG8="}"#);
        assert_eq!(
            encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap_err(),
            ClaimError::NoContentType
        );
    }

    #[test]
    fn a_missing_claim_is_distinct_from_an_unreadable_one() {
        let s = statement(Some("application/json"), br#"{"q":"aGVsbG8="}"#);
        assert_eq!(
            encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap_err(),
            ClaimError::NoSuchClaim
        );
    }

    #[test]
    fn a_non_string_claim_cannot_carry_an_encoding() {
        let s = statement(Some("application/json"), br#"{"p":123}"#);
        assert_eq!(
            encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap_err(),
            ClaimError::NotAString { found: "a number" }
        );
    }

    #[test]
    fn the_declared_alphabet_is_honoured_not_guessed() {
        // "~~~" base64url-decodes to nothing valid; standard base64 would
        // reject it too. What matters is that the caller's choice is used
        // rather than a per-value guess.
        let s = statement(Some("application/json"), br#"{"p":"!!!!"}"#);
        let err = encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap_err();
        assert!(matches!(err, ClaimError::NotEncoded { .. }), "{err:?}");
    }

    #[test]
    fn a_detached_payload_reads_nothing() {
        let mut s = statement(Some("application/json"), b"{}");
        s.payload = None;
        assert_eq!(
            encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap_err(),
            ClaimError::DetachedPayload
        );
    }

    #[test]
    fn the_digest_is_over_the_decoded_bytes_not_the_encoding() {
        let s = statement(Some("application/json"), br#"{"p":"aGVsbG8="}"#);
        let got = encoded_claim_digest(&s, &path("p"), Alphabet::Standard).unwrap();

        // SHA-256 of "hello". Written out rather than computed here, because a
        // test that hashes the same way the code does would agree with it even
        // if both hashed the base64 text.
        let expected =
            hex_to_32("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(got, expected);

        // And is emphatically not the digest of the base64 that carried them.
        assert_ne!(got, scitt_receipt::sha256(b"aGVsbG8="));
    }

    #[test]
    fn the_digest_and_the_bytes_cannot_disagree() {
        let s = statement(Some("application/json"), br#"{"p":"cG9saWN5"}"#);
        let bytes = encoded_claim_bytes(&s, &path("p"), Alphabet::Standard).unwrap();
        let digest = encoded_claim_digest(&s, &path("p"), Alphabet::Standard).unwrap();
        assert_eq!(digest, scitt_receipt::sha256(&bytes));
    }

    #[test]
    fn a_claim_that_cannot_be_read_yields_no_digest() {
        // The failure has to propagate: a digest of zero bytes, or of an empty
        // default, would be a real-looking number for a claim that is absent.
        let s = statement(Some("application/json"), br#"{"q":"YQ=="}"#);
        assert_eq!(
            encoded_claim_digest(&s, &path("p"), Alphabet::Standard).unwrap_err(),
            ClaimError::NoSuchClaim
        );
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
