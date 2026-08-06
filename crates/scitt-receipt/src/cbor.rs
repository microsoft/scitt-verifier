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
