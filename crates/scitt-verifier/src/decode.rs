//! Decode an encoded claim inside a statement's JSON payload.
//!
//! A producer that embeds a build policy, an SBOM or a nested document does it
//! by encoding the bytes into a JSON string, so the thing a consumer actually
//! wants — those bytes, and their digest — is two steps removed from anything
//! `inspect` prints. Copying a 25 KB base64 field out of a terminal and
//! decoding it by hand is where that consumer currently goes, and every step
//! of that detour is a chance to hash something other than what was signed.
//!
//! Three properties make this safe to offer:
//!
//! 1. **The digest is over the exact decoded bytes.** Not over the base64
//!    text, not over a preview, not over a re-indented or newline-normalised
//!    rendering. Producers publish that digest alongside the field — a real
//!    statement carrying `security-policy-base64` carries
//!    `security-policy-sha256` beside it — so the number here is directly
//!    comparable to the one they published, and is worth nothing if it is
//!    computed over anything else.
//! 2. **Nothing is decoded unless it was asked for.** The claim is named by
//!    the caller, and so is the encoding. Scanning a payload for strings that
//!    look like base64 would decode values the producer never said were
//!    encoded, and would do it on every run against attacker-supplied bytes.
//! 3. **Decoding is not verification.** `inspect` authenticates nothing, and
//!    the decoded bytes inherit exactly that status. A digest computed here
//!    says "this is what the field contains", never "this is what was signed".

use scitt_policy::PathSegment;
use scitt_receipt::base64::Alphabet;
use scitt_receipt::Sign1;

/// Preview characters shown without `--verbose`.
///
/// Large enough to show what a policy or manifest actually is — the first few
/// rules of a Rego document, the head of a manifest — and small enough that it
/// cannot bury the digest and byte count printed above it. `--verbose` prints
/// all of it; `--decode-out` is how the exact bytes leave the process.
const PREVIEW_CHARS: usize = 400;

/// Bytes of a non-text value shown as hex without `--verbose`.
const PREVIEW_BYTES: usize = 64;

/// What the caller asked to be decoded.
#[derive(Debug, Clone)]
pub struct Request {
    /// The claim to read, as `inspect` prints its path.
    pub path: Vec<PathSegment>,
    /// The encoding the caller says the value is in. Never inferred.
    pub alphabet: Alphabet,
}

/// The result of decoding one claim.
pub struct Decoded {
    /// The path, echoed in the form a policy rule would use.
    pub path: String,
    pub encoding: &'static str,
    /// The exact decoded bytes. The digest and any export come from these.
    pub bytes: Vec<u8>,
    pub sha256: String,
    /// Whether the decoded bytes are valid UTF-8, stated rather than assumed.
    pub utf8: bool,
    /// A bounded, escaped rendering. Never an input to the digest.
    pub preview: String,
    pub preview_truncated: bool,
}

/// Decode the requested claim, or explain why it could not be read.
///
/// Every failure is a sentence about this statement, because every one of them
/// is: a payload that is not JSON, a path that reaches nothing, a claim that is
/// not a string, a string that is not the encoding it was said to be.
pub fn decode(statement: &Sign1, request: &Request, verbose: bool) -> Result<Decoded, String> {
    let at = scitt_policy::describe_path(&request.path);

    let Some(payload) = &statement.payload else {
        return Err(format!(
            "{at}: the statement has a detached payload, so there is nothing here to read"
        ));
    };

    // The same rule `payloadJson` and the claim listing follow: only a payload
    // the statement *declares* to be JSON is parsed. Sniffing the bytes would
    // decode a structure the issuer never claimed was there.
    let Some(content_type) = statement.content_type() else {
        return Err(format!(
            "{at}: the statement declares no content type, so nothing says its payload is JSON"
        ));
    };
    if !scitt_policy::declares_json(&content_type) {
        return Err(format!(
            "{at}: the statement declares its payload to be '{content_type}', not JSON, so it has \
             no claims to address"
        ));
    }

    let document: serde_json::Value = serde_json::from_slice(payload).map_err(|why| {
        format!("{at}: the payload is not valid JSON, despite the declared content type: {why}")
    })?;

    let found = scitt_policy::resolve_json_path(&document, &request.path)
        .map_err(|why| format!("{at}: {why}"))?;

    let Some(value) = found else {
        return Err(format!("{at}: no such claim"));
    };

    let serde_json::Value::String(encoded) = value else {
        return Err(format!(
            "{at}: the claim is {}, and only a string can carry an encoded value",
            describe_type(value)
        ));
    };

    let bytes = scitt_receipt::base64::decode(request.alphabet, encoded).map_err(|why| {
        format!(
            "{at}: the claim is not valid {}: {why}",
            request.alphabet.name()
        )
    })?;

    let sha256 = scitt_receipt::sha256_hex(&bytes);
    let (preview, preview_truncated, utf8) = preview(&bytes, verbose);

    Ok(Decoded {
        path: at,
        encoding: request.alphabet.name(),
        bytes,
        sha256,
        utf8,
        preview,
        preview_truncated,
    })
}

/// Render decoded bytes for a human, safely and without lying about length.
///
/// Returns the rendering, whether it was cut short, and whether the bytes were
/// text at all. Invalid UTF-8 is reported as such and shown as hex rather than
/// passed through a lossy conversion: replacement characters would render as
/// content that is not in the bytes, beside a digest of bytes that are.
fn preview(bytes: &[u8], verbose: bool) -> (String, bool, bool) {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            let limit = if verbose { usize::MAX } else { PREVIEW_CHARS };
            let mut out = String::new();
            let mut truncated = false;
            for (taken, c) in text.chars().enumerate() {
                if taken >= limit {
                    truncated = true;
                    break;
                }
                out.push_str(&escape(c));
            }
            (out, truncated, true)
        }
        Err(_) => {
            let limit = if verbose { bytes.len() } else { PREVIEW_BYTES };
            let shown = &bytes[..limit.min(bytes.len())];
            (
                scitt_receipt::cbor::hex(shown),
                shown.len() < bytes.len(),
                false,
            )
        }
    }
}

/// Escape a character that would otherwise act on the terminal.
///
/// The decoded bytes are attacker-supplied, and this output lands in a
/// terminal and in CI logs. An escape sequence in a build policy could
/// repaint the line above it — including a verdict — so control characters are
/// printed as their code points. Newline and tab survive, because a policy
/// rendered as one line is unreadable and neither can forge output.
fn escape(c: char) -> String {
    match c {
        '\n' | '\t' => c.to_string(),
        c if c.is_control() => format!("\\u{{{:04x}}}", c as u32),
        c => c.to_string(),
    }
}

fn describe_type(value: &serde_json::Value) -> &'static str {
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

    fn decoded(bytes: &[u8], verbose: bool) -> (String, bool, bool) {
        preview(bytes, verbose)
    }

    #[test]
    fn a_terminal_escape_cannot_survive_into_the_preview() {
        // The decoded bytes are attacker-supplied and this lands in CI logs.
        // A raw escape here could repaint the verdict printed above it.
        let (out, _, utf8) = decoded(b"before\x1b[2Kafter", false);
        assert!(utf8);
        assert!(!out.contains('\u{1b}'), "{out}");
        assert!(out.contains("\\u{001b}"), "{out}");
    }

    #[test]
    fn newlines_and_tabs_survive_because_a_policy_is_unreadable_on_one_line() {
        let (out, _, _) = decoded(b"package policy\n\tallow", false);
        assert!(out.contains('\n') && out.contains('\t'), "{out:?}");
    }

    #[test]
    fn a_long_preview_reports_that_it_was_cut_rather_than_ending_silently() {
        let long = "a".repeat(PREVIEW_CHARS * 2);
        let (out, truncated, _) = decoded(long.as_bytes(), false);
        assert!(truncated);
        assert_eq!(out.chars().count(), PREVIEW_CHARS);

        let (full, truncated, _) = decoded(long.as_bytes(), true);
        assert!(!truncated);
        assert_eq!(full.chars().count(), long.chars().count());
    }

    #[test]
    fn bytes_that_are_not_text_are_said_to_be_bytes_rather_than_mangled() {
        // Lossy conversion would show replacement characters that are not in
        // the bytes, next to a digest of bytes that are.
        let (out, _, utf8) = decoded(&[0xFF, 0xFE, 0x00], false);
        assert!(!utf8);
        assert_eq!(out, "fffe00");
    }

    #[test]
    fn a_preview_is_never_what_gets_hashed() {
        // The property the whole feature rests on: truncating the rendering
        // must not touch the bytes the digest is taken over.
        let long = vec![b'a'; PREVIEW_CHARS * 3];
        let (_, truncated, _) = decoded(&long, false);
        assert!(truncated);
        assert_eq!(
            scitt_receipt::sha256_hex(&long),
            scitt_receipt::sha256_hex(&vec![b'a'; PREVIEW_CHARS * 3])
        );
    }
}
