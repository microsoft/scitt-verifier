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

/// Extract the OIDs from an ExtendedKeyUsage extension value, strictly.
///
/// The counterpart to [`parse_eku_oids`], for the callers that *gate* on the
/// result. Every difference is deliberate: the whole value must be consumed,
/// every item must be an OBJECT IDENTIFIER that decodes, and the sequence must
/// not be empty — RFC 5280 requires at least one `KeyPurposeId`.
///
/// The tolerant parser stops at the first byte it cannot read and returns what
/// it gathered before that point, so `SEQUENCE { OID 1.2.3, <truncated> }`
/// yields `["1.2.3"]`. For a report that is the right trade; for identity
/// matching it means an attacker can park a wanted OID in front of garbage the
/// outer certificate parser never looks at, because the extension value is an
/// opaque `OCTET STRING` to it. This refuses that input instead of matching on
/// it.
pub fn parse_eku_oids_strict(value: &[u8]) -> Result<Vec<String>> {
    let malformed =
        |what: &str| Error::TrustMaterial(format!("extendedKeyUsage is malformed: {what}"));

    let inner = match read_tlv(value) {
        // OCTET STRING wrapper around the real extension value.
        Some((0x04, contents, remainder)) => {
            if !remainder.is_empty() {
                return Err(malformed("trailing bytes after the extension value"));
            }
            match read_tlv(contents) {
                Some((0x30, seq, [])) => seq,
                _ => return Err(malformed("the value is not a single SEQUENCE")),
            }
        }
        Some((0x30, seq, remainder)) => {
            if !remainder.is_empty() {
                return Err(malformed("trailing bytes after the SEQUENCE"));
            }
            seq
        }
        _ => return Err(malformed("the value is not a SEQUENCE")),
    };

    let mut oids = Vec::new();
    let mut rest = inner;
    while !rest.is_empty() {
        let Some((tag, contents, remainder)) = read_tlv(rest) else {
            return Err(malformed("an item is not a well-formed TLV"));
        };
        if tag != 0x06 {
            return Err(malformed("an item is not an OBJECT IDENTIFIER"));
        }
        let Some(oid) = decode_oid(contents) else {
            return Err(malformed("an OBJECT IDENTIFIER does not decode"));
        };
        oids.push(oid);
        rest = remainder;
    }

    if oids.is_empty() {
        return Err(malformed("the sequence names no key purpose"));
    }
    Ok(oids)
}

/// The `notBefore` and `notAfter` of a certificate, as Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
}

/// Read the validity window out of a DER certificate.
///
/// The crypto backend offers `is_valid_at`, a predicate, but not the window
/// itself. A predicate alone cannot answer "is there *any* instant at which
/// this whole path was simultaneously valid", and that question is what lets
/// path structure be judged separately from expiry — the separation MST makes
/// by disabling time entirely, and that this crate makes explicit instead.
///
/// Unlike [`parse_eku_oids`], a malformed input is an error rather than an
/// empty answer. This value gates a check, and a certificate whose validity
/// cannot be read must not silently become one that is valid forever.
pub fn parse_validity(der: &[u8]) -> Result<Validity> {
    let malformed = || Error::TrustMaterial("certificate validity could not be read".into());

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (0x30, certificate, _) = read_tlv(der).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (0x30, tbs, _) = read_tlv(certificate).ok_or_else(malformed)? else {
        return Err(malformed());
    };

    // TBSCertificate ::= SEQUENCE {
    //     version [0] EXPLICIT DEFAULT v1, serialNumber INTEGER,
    //     signature AlgorithmIdentifier, issuer Name, validity Validity, ... }
    //
    // `version` is absent in a v1 certificate, so it is skipped by tag rather
    // than by position; counting fields blindly reads `issuer` as `validity`.
    let mut rest = tbs;
    if let Some((0xA0, _, remainder)) = read_tlv(rest) {
        rest = remainder;
    }
    // serialNumber, then the AlgorithmIdentifier and Name that precede validity.
    for expected in [0x02u8, 0x30, 0x30] {
        let (tag, _, remainder) = read_tlv(rest).ok_or_else(malformed)?;
        if tag != expected {
            return Err(malformed());
        }
        rest = remainder;
    }

    let (0x30, validity, _) = read_tlv(rest).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (not_before_tag, not_before, after) = read_tlv(validity).ok_or_else(malformed)?;
    let (not_after_tag, not_after, _) = read_tlv(after).ok_or_else(malformed)?;

    Ok(Validity {
        not_before: parse_time(not_before_tag, not_before).ok_or_else(malformed)?,
        not_after: parse_time(not_after_tag, not_after).ok_or_else(malformed)?,
    })
}

/// The OID of the algorithm a certificate's signature was made with.
///
/// Read so that an algorithm the crypto backend cannot verify is reported as
/// a limit of this build rather than as a bad chain. The two are not the same
/// claim, and only one of them accuses the signer of anything.
///
/// Malformed input is an error for the same reason as [`parse_validity`]: a
/// certificate whose algorithm cannot be read must not be waved through as if
/// it were supported.
pub fn parse_signature_algorithm_oid(der: &[u8]) -> Result<String> {
    let malformed =
        || Error::TrustMaterial("certificate signature algorithm could not be read".into());

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    //
    // The outer `signatureAlgorithm` is read rather than the one inside the
    // TBSCertificate. RFC 5280 requires them to match, and this one is what
    // the signature was actually made with.
    let (0x30, certificate, _) = read_tlv(der).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (0x30, _tbs, after_tbs) = read_tlv(certificate).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (0x30, algorithm, _) = read_tlv(after_tbs).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (0x06, oid, _) = read_tlv(algorithm).ok_or_else(malformed)? else {
        return Err(malformed());
    };

    decode_oid(oid).ok_or_else(malformed)
}

/// The exact `TBSCertificate` bytes the signature was made over, paired with
/// the signature itself.
///
/// Both are returned as borrowed slices of the original encoding, never
/// re-encoded. A signature covers the bytes the issuer actually signed, and
/// any re-encoding — a different length form, a dropped default — would change
/// them and turn a genuine certificate into an invalid one.
///
/// The signature is returned as the contents of the `BIT STRING` with its
/// unused-bits octet removed, which for every signature algorithm in use is
/// the DER the verifier expects. A non-zero unused-bit count is refused rather
/// than silently stripped: it is not a valid signature encoding, and guessing
/// at the intent of one would be inventing input.
pub fn tbs_and_signature(der: &[u8]) -> Result<(&[u8], &[u8])> {
    let malformed = || Error::TrustMaterial("certificate structure could not be read".into());

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (0x30, certificate, _) = read_tlv(der).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (0x30, _tbs_contents, after_tbs) = read_tlv(certificate).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    // The signed bytes are the whole TLV, header included, not its contents.
    // `read_tlv` hands back the contents and the remainder, so the element is
    // what lies between them.
    let tbs_len = certificate
        .len()
        .checked_sub(after_tbs.len())
        .ok_or_else(malformed)?;
    let tbs = certificate.get(..tbs_len).ok_or_else(malformed)?;

    let (0x30, _algorithm, after_algorithm) = read_tlv(after_tbs).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (0x03, signature_bits, _) = read_tlv(after_algorithm).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (unused, signature) = signature_bits.split_first().ok_or_else(malformed)?;
    if *unused != 0 {
        return Err(Error::TrustMaterial(
            "certificate signature is not a whole number of octets".into(),
        ));
    }

    Ok((tbs, signature))
}

/// Decode an X.509 `Time`, which is a CHOICE of two encodings.
///
/// UTCTime carries a two-digit year, and RFC 5280 §4.1.2.5.1 fixes the pivot:
/// 50 and above mean 19xx, below 50 means 20xx. Guessing the other way turns a
/// certificate that expired in 1998 into one valid until 2098.
fn parse_time(tag: u8, contents: &[u8]) -> Option<i64> {
    let text = core::str::from_utf8(contents).ok()?;
    let (year, rest) = match tag {
        // UTCTime: YYMMDDHHMMSSZ
        0x17 => {
            let yy: i64 = text.get(..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, text.get(2..)?)
        }
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        0x18 => (text.get(..4)?.parse().ok()?, text.get(4..)?),
        _ => return None,
    };

    // Seconds are optional in GeneralizedTime, and fractional seconds and
    // non-`Z` offsets are not accepted: a certificate using them is reported
    // as unreadable rather than silently placed in the wrong century.
    if !rest.ends_with('Z') {
        return None;
    }
    let digits = &rest[..rest.len() - 1];
    if digits.len() != 10 && digits.len() != 8 {
        return None;
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |i: usize| -> Option<i64> { digits.get(i..i + 2)?.parse().ok() };
    let (month, day, hour, minute) = (field(0)?, field(2)?, field(4)?, field(6)?);
    let second = if digits.len() == 10 { field(8)? } else { 0 };

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // 60 is a leap second, which is legal in the encoding.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil`. Written out rather than pulled from a
/// date crate because the core is forbidden to depend on a clock, and every
/// such crate brings one along.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Decode an X.509 `Name` into `(key, value)` attribute pairs.
///
/// Keys use the RFC 4514 short label where did:x509 defines one, and the
/// dotted OID otherwise, which is exactly the shape the `subject` predicate
/// matches against.
///
/// This reads the DER rather than re-parsing a rendered RFC 4514 string.
/// Rendering is lossy in the direction that matters: a value containing `,`
/// or `+` is escaped on the way out, and splitting the rendered form back on
/// those characters turns one attribute into two. Comparing structure avoids
/// inventing an unescaping rule that has to agree exactly with whatever
/// produced the string.
///
/// Attributes whose value is not a UTF-8-compatible string type are skipped;
/// a predicate naming one simply fails to match, which is the safe direction.
pub fn parse_name_attributes(name_der: &[u8]) -> Vec<(String, String)> {
    // Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    // AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }
    let Some((0x30, rdn_sequence, _)) = read_tlv(name_der) else {
        return Vec::new();
    };

    let mut attributes = Vec::new();
    let mut rdns = rdn_sequence;
    while let Some((tag, rdn, remainder)) = read_tlv(rdns) {
        rdns = remainder;
        if tag != 0x31 {
            continue;
        }
        let mut pairs = rdn;
        while let Some((pair_tag, pair, pair_remainder)) = read_tlv(pairs) {
            pairs = pair_remainder;
            if pair_tag != 0x30 {
                continue;
            }
            let Some((0x06, oid_bytes, after_oid)) = read_tlv(pair) else {
                continue;
            };
            let Some(oid) = decode_oid(oid_bytes) else {
                continue;
            };
            let Some((value_tag, value_bytes, _)) = read_tlv(after_oid) else {
                continue;
            };
            // PrintableString, UTF8String, IA5String, T61String. BMPString and
            // UniversalString are wide encodings and are left out rather than
            // mangled into something that might accidentally compare equal.
            if !matches!(value_tag, 0x13 | 0x0C | 0x16 | 0x14) {
                continue;
            }
            let Ok(value) = core::str::from_utf8(value_bytes) else {
                continue;
            };
            attributes.push((name_label(&oid), value.to_string()));
        }
    }
    attributes
}

/// RFC 4514 short labels for the attribute types did:x509 names.
fn name_label(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        other => return other.to_string(),
    }
    .to_string()
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

    /// The reason the strict parser exists. The tolerant one keeps the OID it
    /// managed to read and stops quietly at the garbage behind it, so a
    /// predicate gating on `1.2.3` would match this value. The outer
    /// certificate parser cannot catch it either: an extension value is an
    /// opaque OCTET STRING to it.
    #[test]
    fn a_wanted_oid_in_front_of_garbage_matches_loosely_and_is_refused_strictly() {
        // SEQUENCE { OID 1.2.3, <truncated TLV> }
        let der = &[0x30, 0x05, 0x06, 0x02, 0x2A, 0x03, 0xFF];

        assert_eq!(parse_eku_oids(der), vec!["1.2.3".to_string()]);
        assert!(
            parse_eku_oids_strict(der).is_err(),
            "a value with trailing garbage must not decide an identity predicate"
        );
    }

    #[test]
    fn the_strict_parser_accepts_a_well_formed_sequence() {
        let der = &[0x30, 0x04, 0x06, 0x02, 0x2A, 0x03];
        assert_eq!(
            parse_eku_oids_strict(der).unwrap(),
            vec!["1.2.3".to_string()]
        );

        let mut wrapped = vec![0x04, der.len() as u8];
        wrapped.extend_from_slice(der);
        assert_eq!(
            parse_eku_oids_strict(&wrapped).unwrap(),
            vec!["1.2.3".to_string()]
        );
    }

    /// RFC 5280 requires at least one `KeyPurposeId`. An empty sequence would
    /// otherwise answer "no match" for every predicate, which reads as a
    /// finding about the certificate rather than a malformed extension.
    #[test]
    fn the_strict_parser_refuses_an_empty_sequence_and_stray_items() {
        assert!(parse_eku_oids_strict(&[0x30, 0x00]).is_err());
        // SEQUENCE { INTEGER 1 } — an item that is not an OID at all.
        assert!(parse_eku_oids_strict(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_err());
        // Trailing bytes after a well-formed SEQUENCE.
        assert!(parse_eku_oids_strict(&[0x30, 0x04, 0x06, 0x02, 0x2A, 0x03, 0x00]).is_err());
    }

    #[test]
    fn truncated_oid_is_rejected() {
        // Final byte still has the continuation bit set.
        assert_eq!(decode_oid(&[0x2A, 0x86]), None);
    }

    /// Regression, found on a statement in the field whose leaf carries EKU
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
mod validity_tests {
    use super::*;

    #[test]
    fn days_from_civil_anchors_at_the_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    /// 2000 is a leap year and 1900 is not; the era arithmetic is what gets
    /// this right, and an off-by-one day here shifts every expiry check.
    #[test]
    fn days_from_civil_handles_the_century_leap_rule() {
        assert_eq!(
            days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 28),
            2
        );
        assert_eq!(
            days_from_civil(1900, 3, 1) - days_from_civil(1900, 2, 28),
            1
        );
    }

    #[test]
    fn utctime_decodes() {
        // 2026-04-23T00:00:00Z
        assert_eq!(parse_time(0x17, b"260423000000Z").unwrap(), 1776902400);
    }

    /// RFC 5280 §4.1.2.5.1: two-digit years of 50 and above are 19xx.
    #[test]
    fn utctime_year_pivots_at_fifty() {
        let y1999 = parse_time(0x17, b"991231235959Z").unwrap();
        let y2000 = parse_time(0x17, b"000101000000Z").unwrap();
        assert!(y1999 < y2000, "99 must mean 1999, not 2099");
        assert_eq!(y2000 - y1999, 1);
    }

    #[test]
    fn generalizedtime_decodes_with_and_without_seconds() {
        assert_eq!(parse_time(0x18, b"20260423000000Z").unwrap(), 1776902400);
        assert_eq!(parse_time(0x18, b"202604230000Z").unwrap(), 1776902400);
    }

    #[test]
    fn unsupported_or_malformed_times_are_rejected() {
        // Neither UTCTime nor GeneralizedTime.
        assert_eq!(parse_time(0x04, b"260423000000Z"), None);
        // A local-time offset, which RFC 5280 forbids.
        assert_eq!(parse_time(0x17, b"260423000000+0100"), None);
        // Fractional seconds.
        assert_eq!(parse_time(0x18, b"20260423000000.5Z"), None);
        assert_eq!(parse_time(0x17, b"2604230000ZZ"), None);
        assert_eq!(parse_time(0x17, b"261323000000Z"), None, "month 13");
        assert_eq!(parse_time(0x17, b"260423250000Z"), None, "hour 25");
        assert_eq!(parse_time(0x17, b""), None);
    }

    #[test]
    fn malformed_certificates_are_an_error_not_a_default() {
        assert!(parse_validity(&[]).is_err());
        assert!(parse_validity(&[0x30, 0x00]).is_err());
        // A SEQUENCE whose contents are not a TBSCertificate.
        assert!(parse_validity(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());
    }

    #[test]
    fn reads_the_outer_signature_algorithm_oid() {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, ... }
        // with an empty TBS and sha256WithRSAEncryption as the algorithm.
        let der = [
            0x30, 0x0F, // Certificate SEQUENCE
            0x30, 0x00, // tbsCertificate, contents irrelevant here
            0x30, 0x0B, // AlgorithmIdentifier SEQUENCE
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        assert_eq!(
            parse_signature_algorithm_oid(&der).unwrap(),
            "1.2.840.113549.1.1.11"
        );
    }

    #[test]
    fn an_unreadable_signature_algorithm_is_an_error_not_a_guess() {
        assert!(parse_signature_algorithm_oid(&[]).is_err());
        assert!(parse_signature_algorithm_oid(&[0x30, 0x00]).is_err());
        // Present but not an AlgorithmIdentifier.
        assert!(parse_signature_algorithm_oid(&[0x30, 0x04, 0x30, 0x00, 0x05, 0x00]).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The TBS bytes must be the exact encoded element, header included, and
    /// must sit where the certificate's own bytes say they do.
    ///
    /// Built by hand rather than taken from a real certificate so the expected
    /// boundaries are stated independently of the parser under test: a fixture
    /// would only show that the function agrees with itself about where the
    /// element ends.
    #[test]
    fn tbs_and_signature_return_the_exact_encoded_elements() {
        let tbs = [0x30u8, 0x02, 0xAA, 0xBB];
        let algorithm = [0x30u8, 0x01, 0x01];
        // BIT STRING: zero unused bits, then the signature.
        let signature = [0x03u8, 0x03, 0x00, 0xC1, 0xC2];
        let body = [tbs.as_slice(), &algorithm, &signature].concat();
        let cert = [&[0x30u8, body.len() as u8], body.as_slice()].concat();

        let (got_tbs, got_sig) = tbs_and_signature(&cert).unwrap();
        assert_eq!(got_tbs, tbs, "the signed bytes include the TLV header");
        assert_eq!(got_sig, [0xC1, 0xC2], "the unused-bits octet is removed");
    }

    /// A signature that is not a whole number of octets is refused rather than
    /// silently trimmed. It is not a valid encoding, and guessing at the
    /// intent would mean verifying bytes nobody wrote.
    #[test]
    fn a_partial_octet_signature_is_refused() {
        let body = [
            [0x30u8, 0x00].as_slice(),
            &[0x30, 0x00],
            &[0x03, 0x02, 0x03, 0xF8],
        ]
        .concat();
        let cert = [&[0x30u8, body.len() as u8], body.as_slice()].concat();
        assert!(tbs_and_signature(&cert).is_err());
    }

    #[test]
    fn a_truncated_certificate_is_refused() {
        assert!(tbs_and_signature(&[0x30, 0x02, 0x30]).is_err());
        assert!(tbs_and_signature(&[]).is_err());
    }

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
