//! Small CBOR access helpers over `tav_cose::CborValue`.
//!
//! These exist so the verification code reads like the spec rather than like
//! pattern matching.

use crate::error::{Error, Result};
use tav_cose::CborValue;

pub fn as_bytes(v: &CborValue) -> Result<&[u8]> {
    match v {
        CborValue::ByteString(b) => Ok(b),
        other => Err(Error::Structure(format!(
            "expected byte string, got {}",
            type_name(other)
        ))),
    }
}

pub fn as_text(v: &CborValue) -> Result<&str> {
    match v {
        CborValue::TextString(s) => Ok(s),
        other => Err(Error::Structure(format!(
            "expected text string, got {}",
            type_name(other)
        ))),
    }
}

pub fn as_int(v: &CborValue) -> Result<i64> {
    match v {
        CborValue::Int(i) => Ok(*i),
        other => Err(Error::Structure(format!(
            "expected integer, got {}",
            type_name(other)
        ))),
    }
}

/// A CWT NumericDate: a bare integer, or one wrapped in CBOR tag 1.
///
/// RFC 8392 §3.1.1 permits either encoding, and MST uses both — receipts carry
/// a bare integer while statements tag theirs. Accepting only the bare form
/// makes a present timestamp look absent, which is the most dangerous way for
/// a parser to be wrong about a date.
pub fn as_numeric_date(v: &CborValue) -> Result<i64> {
    match v {
        CborValue::Tagged { tag: 1, payload } => as_int(payload),
        other => as_int(other),
    }
}

pub fn as_array(v: &CborValue) -> Result<&Vec<CborValue>> {
    match v {
        CborValue::Array(a) => Ok(a),
        other => Err(Error::Structure(format!(
            "expected array, got {}",
            type_name(other)
        ))),
    }
}

/// Optional map lookup by integer key. Absent is not an error.
pub fn opt_int_key(map: &CborValue, key: i64) -> Option<&CborValue> {
    match map {
        CborValue::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, CborValue::Int(i) if *i == key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// Optional map lookup by text key. Absent is not an error.
pub fn opt_text_key<'a>(map: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    match map {
        CborValue::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, CborValue::TextString(s) if s == key))
            .map(|(_, v)| v),
        _ => None,
    }
}

pub fn req_int_key(map: &CborValue, key: i64) -> Result<&CborValue> {
    opt_int_key(map, key).ok_or_else(|| Error::Structure(format!("missing map key {key}")))
}

/// A `kid` may be a byte string of ASCII hex or a text string.
pub fn as_kid(v: &CborValue) -> Result<String> {
    match v {
        CborValue::ByteString(b) => Ok(b.iter().map(|c| *c as char).collect()),
        CborValue::TextString(s) => Ok(s.clone()),
        other => Err(Error::Structure(format!(
            "kid must be bstr or tstr, got {}",
            type_name(other)
        ))),
    }
}

pub fn type_name(v: &CborValue) -> &'static str {
    match v {
        CborValue::Int(_) => "Int",
        CborValue::Simple(_) => "Simple",
        CborValue::ByteString(_) => "ByteString",
        CborValue::TextString(_) => "TextString",
        CborValue::Array(_) => "Array",
        CborValue::Map(_) => "Map",
        CborValue::Tagged { .. } => "Tagged",
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time comparison for digest equality.
///
/// Digests here are public values, so this is defence in depth rather than a
/// strict requirement — but a verifier that leaks comparison timing on *any*
/// path invites questions it should not have to answer.
pub fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: MST statements tag `iat` with CBOR tag 1, and reading only
    /// bare integers made a present timestamp look absent.
    #[test]
    fn a_numeric_date_is_read_whether_or_not_it_is_tagged() {
        let bare = CborValue::Int(1_786_995_989);
        let tagged = CborValue::Tagged {
            tag: 1,
            payload: Box::new(CborValue::Int(1_786_995_989)),
        };
        assert_eq!(as_numeric_date(&bare).unwrap(), 1_786_995_989);
        assert_eq!(as_numeric_date(&tagged).unwrap(), 1_786_995_989);
    }

    #[test]
    fn an_unrelated_tag_is_not_silently_unwrapped_into_a_date() {
        let wrong_tag = CborValue::Tagged {
            tag: 61,
            payload: Box::new(CborValue::Int(7)),
        };
        assert!(as_numeric_date(&wrong_tag).is_err());
    }
}
