//! Minimal DER writer, used for exactly one thing: turning the raw `x`/`y`
//! coordinates of a COSE_Key into a SubjectPublicKeyInfo that the crypto
//! backend can import.
//!
//! CCF publishes its ledger signing keys as a COSE_KeySet of bare EC points.
//! Every X.509 and crypto API wants SPKI. Rather than pull in a curve-specific
//! elliptic-curve crate per curve just to re-encode a point we already have,
//! we emit the ~90 bytes of ASN.1 directly. The structure is fixed:
//!
//! ```text
//! SubjectPublicKeyInfo ::= SEQUENCE {
//!     algorithm   SEQUENCE { OID id-ecPublicKey, OID namedCurve },
//!     subjectPublicKey BIT STRING  -- 0x04 || X || Y
//! }
//! ```

use crate::error::{Error, Result};

const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

/// Curves this release accepts for CCF ledger signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    /// COSE `crv` values (RFC 9053 §7.1).
    pub fn from_cose(crv: i64) -> Result<Self> {
        match crv {
            1 => Ok(Curve::P256),
            2 => Ok(Curve::P384),
            3 => Ok(Curve::P521),
            other => Err(Error::TrustMaterial(format!(
                "unsupported COSE curve {other}"
            ))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
        }
    }

    /// Expected size of each coordinate, in bytes.
    pub fn coordinate_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    fn oid(self) -> &'static [u8] {
        match self {
            Curve::P256 => OID_P256,
            Curve::P384 => OID_P384,
            Curve::P521 => OID_P521,
        }
    }
}

fn len_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut be = len.to_be_bytes().to_vec();
        while be.first() == Some(&0) {
            be.remove(0);
        }
        let mut out = vec![0x80 | be.len() as u8];
        out.extend_from_slice(&be);
        out
    }
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&len_bytes(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// Build a SubjectPublicKeyInfo DER blob from an uncompressed EC point.
///
/// Coordinates are left-padded to the curve's fixed width. CBOR encoders are
/// allowed to strip leading zero bytes from a byte string's *value* only in
/// buggy implementations, but CCF has been observed to emit short coordinates,
/// and a short coordinate silently shifts every subsequent byte of the point.
pub fn spki_from_ec_point(curve: Curve, x: &[u8], y: &[u8]) -> Result<Vec<u8>> {
    let n = curve.coordinate_len();
    if x.len() > n || y.len() > n {
        return Err(Error::TrustMaterial(format!(
            "{} coordinate too long: x={} y={} bytes, expected at most {}",
            curve.name(),
            x.len(),
            y.len(),
            n
        )));
    }

    let mut point = Vec::with_capacity(1 + 2 * n);
    point.push(0x04); // uncompressed
    point.extend(std::iter::repeat(0u8).take(n - x.len()));
    point.extend_from_slice(x);
    point.extend(std::iter::repeat(0u8).take(n - y.len()));
    point.extend_from_slice(y);

    let mut alg_id = Vec::new();
    alg_id.extend_from_slice(OID_EC_PUBLIC_KEY);
    alg_id.extend_from_slice(curve.oid());
    let alg_id = tlv(0x30, &alg_id);

    // BIT STRING contents are prefixed with the count of unused trailing bits.
    let mut bit_string = vec![0x00];
    bit_string.extend_from_slice(&point);
    let bit_string = tlv(0x03, &bit_string);

    let mut body = alg_id;
    body.extend_from_slice(&bit_string);
    Ok(tlv(0x30, &body))
}

/// Extract the OIDs from a DER-encoded ExtendedKeyUsage extension value.
///
/// Reporting only, so a value that does not parse yields fewer OIDs rather
/// than an error: a malformed EKU must not stop a reader from seeing the rest
/// of the certificate. Anything that *gates* on an EKU must not use this
/// without first deciding what an unparseable extension means.
///
/// The value is `SEQUENCE OF OBJECT IDENTIFIER`. Some backends hand back the
/// extension's `OCTET STRING` wrapper still attached, so that is unwrapped
/// first when present.
pub fn parse_eku_oids(value: &[u8]) -> Vec<String> {
    let inner = match read_tlv(value) {
        // OCTET STRING wrapper around the real extension value.
        Some((0x04, contents, _)) => match read_tlv(contents) {
            Some((0x30, seq, _)) => seq,
            _ => return Vec::new(),
        },
        Some((0x30, seq, _)) => seq,
        _ => return Vec::new(),
    };

    let mut oids = Vec::new();
    let mut rest = inner;
    while let Some((tag, contents, remainder)) = read_tlv(rest) {
        if tag == 0x06 {
            if let Some(oid) = decode_oid(contents) {
                oids.push(oid);
            }
        }
        rest = remainder;
    }
    oids
}

/// Split one DER TLV, returning `(tag, contents, remainder)`.
fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let first_len = *bytes.get(1)? as usize;

    let (len, header) = if first_len < 0x80 {
        (first_len, 2)
    } else {
        let count = first_len & 0x7F;
        // Indefinite length is not legal in DER, and a length wider than a
        // usize cannot describe a buffer we are holding.
        if count == 0 || count > 8 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = len.checked_shl(8)? | *bytes.get(2 + i)? as usize;
        }
        (len, 2 + count)
    };

    let end = header.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some((tag, &bytes[header..end], &bytes[end..]))
}

/// Decode OBJECT IDENTIFIER contents to dotted-decimal.
///
/// The first subidentifier encodes two arcs as `40*arc1 + arc2`, and — this is
/// the part that is easy to get wrong — it is itself base-128, so it may span
/// several bytes. OID `2.999` encodes as `0x88 0x37`; treating the first byte
/// as the whole subidentifier yields `3.16.55`, a plausible-looking OID that
/// is not the one in the certificate.
fn decode_oid(contents: &[u8]) -> Option<String> {
    let mut subidentifiers = Vec::new();
    let mut value: u64 = 0;
    let mut in_progress = false;
    for byte in contents {
        // Guard the shift rather than wrapping: a hostile OID arc must not
        // silently alias onto a legitimate one.
        value = value.checked_shl(7)? | u64::from(byte & 0x7F);
        in_progress = true;
        if byte & 0x80 == 0 {
            subidentifiers.push(value);
            value = 0;
            in_progress = false;
        }
    }
    // A final byte with the continuation bit set means the encoding was cut off.
    if in_progress {
        return None;
    }

    let (first, rest) = subidentifiers.split_first()?;
    let (arc1, arc2) = match *first {
        v if v < 40 => (0, v),
        v if v < 80 => (1, v - 40),
        v => (2, v - 80),
    };

    let mut out = format!("{arc1}.{arc2}");
    for sub in rest {
        out.push('.');
        out.push_str(&sub.to_string());
    }
    Some(out)
}

#[cfg(test)]
mod eku_tests {
    use super::*;

    #[test]
    fn parses_a_sequence_of_oids() {
        // SEQUENCE { OID 1.3.6.1.4.1.311.76.59.1.1, OID 2.5.29.37.0 }
        let der = &[
            0x30, 0x13, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4C, 0x3B, 0x01,
            0x01, 0x06, 0x04, 0x55, 0x1D, 0x25, 0x00,
        ];
        assert_eq!(
            parse_eku_oids(der),
            vec![
                "1.3.6.1.4.1.311.76.59.1.1".to_string(),
                "2.5.29.37.0".to_string()
            ]
        );
    }

    #[test]
    fn unwraps_an_octet_string_wrapper() {
        let inner = [0x30u8, 0x04, 0x06, 0x02, 0x2A, 0x03];
        let mut wrapped = vec![0x04, inner.len() as u8];
        wrapped.extend_from_slice(&inner);
        assert_eq!(parse_eku_oids(&wrapped), vec!["1.2.3".to_string()]);
    }

    #[test]
    fn malformed_input_yields_no_oids_rather_than_panicking() {
        assert!(parse_eku_oids(&[]).is_empty());
        assert!(parse_eku_oids(&[0x30, 0xFF]).is_empty());
        assert!(parse_eku_oids(&[0x30, 0x02, 0x06, 0x7F]).is_empty());
    }

    #[test]
    fn truncated_oid_is_rejected() {
        // Final byte still has the continuation bit set.
        assert_eq!(decode_oid(&[0x2A, 0x86]), None);
    }

    /// Regression, found on a real AMD HBOM statement whose leaf carries EKU
    /// `2.999`. The first subidentifier is 1079, which needs two bytes; a
    /// single-byte reading produced `3.16.55` instead.
    #[test]
    fn a_multibyte_first_subidentifier_decodes_to_the_right_arcs() {
        assert_eq!(decode_oid(&[0x88, 0x37]).unwrap(), "2.999");
    }

    #[test]
    fn the_first_byte_splits_into_two_arcs_across_all_three_ranges() {
        assert_eq!(decode_oid(&[0x06]).unwrap(), "0.6");
        assert_eq!(decode_oid(&[0x2A]).unwrap(), "1.2");
        assert_eq!(decode_oid(&[0x55]).unwrap(), "2.5");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_spki_has_expected_prefix_and_length() {
        let spki = spki_from_ec_point(Curve::P256, &[1u8; 32], &[2u8; 32]).unwrap();
        // 26 bytes of header + 65 bytes of point + 2 bytes of BIT STRING TLV.
        assert_eq!(spki.len(), 91);
        assert_eq!(spki[0], 0x30);
        assert_eq!(spki[spki.len() - 65], 0x04);
    }

    #[test]
    fn short_coordinates_are_left_padded() {
        let spki = spki_from_ec_point(Curve::P256, &[0xAB], &[0xCD]).unwrap();
        assert_eq!(spki.len(), 91);
        let point = &spki[spki.len() - 65..];
        assert_eq!(point[0], 0x04);
        assert_eq!(
            point[32], 0xAB,
            "x must be right-aligned in its 32-byte slot"
        );
        assert_eq!(
            point[64], 0xCD,
            "y must be right-aligned in its 32-byte slot"
        );
    }

    #[test]
    fn oversized_coordinates_are_rejected() {
        assert!(spki_from_ec_point(Curve::P256, &[0u8; 33], &[0u8; 32]).is_err());
    }

    #[test]
    fn long_form_lengths_are_encoded() {
        assert_eq!(len_bytes(0x7F), vec![0x7F]);
        assert_eq!(len_bytes(0x80), vec![0x81, 0x80]);
        assert_eq!(len_bytes(0x1234), vec![0x82, 0x12, 0x34]);
    }
}
