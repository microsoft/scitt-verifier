//! COSE and CWT header labels used by SCITT and CCF.

/// COSE protected header labels (RFC 9052 / IANA).
pub const ALG: i64 = 1;
pub const CONTENT_TYPE: i64 = 3;
pub const KID: i64 = 4;
pub const CWT_CLAIMS: i64 = 15;
pub const X5CHAIN: i64 = 33;
/// Certificate thumbprint: `[hash-alg, digest]`.
pub const X5T: i64 = 34;

/// The signature inside a detached-signature descriptor.
///
/// Not an IANA COSE header parameter. Producers that carry a second party's
/// signature in a protected header reuse COSE's labels for the parts that have
/// them — `1`, `33`, `34` — and there is no registered label for a bare
/// signature, so `-1` is convention rather than standard. Named here so that
/// the convention is visible in one place instead of appearing as a literal.
pub const DETACHED_SIGNATURE: i64 = -1;

/// COSE Hash Envelope (RFC 9995). The payload is the *digest* of some other
/// resource rather than the resource itself.
///
/// Note that RFC 9995 §4 forbids [`CONTENT_TYPE`] in either bucket of a hash
/// envelope, precisely because label 3 describes the payload while
/// [`PAYLOAD_PREIMAGE_CONTENT_TYPE`] describes what was hashed to produce it.
/// Confusing the two is how a verifier ends up comparing an artifact against a
/// digest.
///
/// The hash algorithm used to produce the payload. REQUIRED in the protected
/// header, and its presence is what identifies a hash envelope.
pub const PAYLOAD_HASH_ALG: i64 = 258;
/// The content type of the bytes that were hashed (the preimage).
pub const PAYLOAD_PREIMAGE_CONTENT_TYPE: i64 = 259;
/// Where the original resource (the preimage) can be retrieved from.
pub const PAYLOAD_LOCATION: i64 = 260;

/// SCITT receipts, carried in the statement's *unprotected* bucket.
pub const RECEIPTS: i64 = 394;
/// Verifiable data structure identifier.
pub const VERIFIABLE_DATA_STRUCTURE: i64 = 395;
/// Verifiable data proofs bucket (RFC 9942 calls this `vdp`), in the receipt's
/// unprotected headers.
pub const VDP: i64 = 396;

/// `CCF_LEDGER_SHA256` — the only verifiable data structure this release verifies.
pub const CCF_LEDGER_SHA256: i64 = 2;

/// Inclusion proofs live under key -1 of the proofs bucket.
pub const PROOF_INCLUSION: i64 = -1;

/// Within an inclusion proof: leaf components.
pub const PROOF_LEAF: i64 = 1;
/// Within an inclusion proof: the Merkle path.
pub const PROOF_PATH: i64 = 2;

/// CWT claim keys (RFC 8392).
pub const CWT_ISS: i64 = 1;
pub const CWT_SUB: i64 = 2;
pub const CWT_EXP: i64 = 4;
pub const CWT_NBF: i64 = 5;
pub const CWT_IAT: i64 = 6;

/// Human-readable name for a registered CWT claim key.
///
/// Returns `None` for keys this crate does not recognise, so a caller can show
/// the number rather than inventing a name for it.
pub fn cwt_claim_name(key: i64) -> Option<&'static str> {
    match key {
        CWT_ISS => Some("iss"),
        CWT_SUB => Some("sub"),
        3 => Some("aud"),
        CWT_EXP => Some("exp"),
        CWT_NBF => Some("nbf"),
        CWT_IAT => Some("iat"),
        7 => Some("cti"),
        _ => None,
    }
}

/// Human-readable name for a COSE header label this crate recognises.
///
/// These double as JSON object keys, so they are identifier-shaped rather than
/// prose. Returns `None` for anything else, so a caller shows the raw label
/// rather than implying the tool understood a header it did not read.
pub fn header_name(label: i64) -> Option<&'static str> {
    match label {
        ALG => Some("alg"),
        2 => Some("crit"),
        CONTENT_TYPE => Some("contentType"),
        KID => Some("kid"),
        CWT_CLAIMS => Some("cwtClaims"),
        X5CHAIN => Some("x5chain"),
        X5T => Some("x5t"),
        PAYLOAD_HASH_ALG => Some("payloadHashAlg"),
        PAYLOAD_PREIMAGE_CONTENT_TYPE => Some("payloadPreimageContentType"),
        PAYLOAD_LOCATION => Some("payloadLocation"),
        RECEIPTS => Some("receipts"),
        VERIFIABLE_DATA_STRUCTURE => Some("verifiableDataStructure"),
        VDP => Some("verifiableDataProofs"),
        _ => None,
    }
}

/// Prose name for a COSE header label, for human-readable output.
///
/// Deliberately separate from [`header_name`]: that one doubles as a JSON
/// object key and must stay identifier-shaped, while a person reading a
/// terminal is better served by "content type" than by "contentType". Keep the
/// two in step when adding a label.
pub fn header_display_name(label: i64) -> Option<&'static str> {
    match label {
        ALG => Some("alg"),
        2 => Some("crit"),
        CONTENT_TYPE => Some("content type"),
        KID => Some("kid"),
        CWT_CLAIMS => Some("cwt claims"),
        X5CHAIN => Some("x5chain"),
        X5T => Some("x5t"),
        PAYLOAD_HASH_ALG => Some("payload hash alg"),
        PAYLOAD_PREIMAGE_CONTENT_TYPE => Some("preimage cty"),
        PAYLOAD_LOCATION => Some("payload location"),
        RECEIPTS => Some("receipts"),
        VERIFIABLE_DATA_STRUCTURE => Some("data structure"),
        VDP => Some("proofs"),
        _ => None,
    }
}

/// CCF's private header bucket in a receipt's protected headers.
pub const CCF_V1: &str = "ccf.v1";
/// Inside [`CCF_V1`]: the transaction identifier, `<view>.<seqno>`.
///
/// This is the seqno of the *receipt* transaction, not of the entry it covers.
/// The entry's own seqno appears only in the leaf's commit evidence.
pub const CCF_TXID: &str = "txid";

/// Extended Key Usage extension (RFC 5280 §4.2.1.12).
pub const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";

/// Security version number, used for anti-rollback assertions.
pub const CWT_SVN: &str = "svn";

/// COSE algorithm identifiers.
pub mod alg {
    pub const ES256: i64 = -7;
    pub const ES384: i64 = -35;
    pub const ES512: i64 = -36;
    pub const PS256: i64 = -37;
    pub const PS384: i64 = -38;
    pub const PS512: i64 = -39;
    pub const RS256: i64 = -257;

    /// Hash algorithms from the same registry, used by `x5t` and by the COSE
    /// Hash Envelope payload hash (RFC 9995 label 258).
    pub const SHA256: i64 = -16;
    pub const SHA384: i64 = -43;
    pub const SHA512: i64 = -44;

    pub fn name(alg: i64) -> String {
        match alg {
            ES256 => "ES256".into(),
            ES384 => "ES384".into(),
            ES512 => "ES512".into(),
            PS256 => "PS256".into(),
            PS384 => "PS384".into(),
            PS512 => "PS512".into(),
            RS256 => "RS256".into(),
            -258 => "RS384".into(),
            -259 => "RS512".into(),
            -8 => "EdDSA".into(),
            SHA256 => "SHA-256".into(),
            SHA384 => "SHA-384".into(),
            SHA512 => "SHA-512".into(),
            other => format!("alg({other})"),
        }
    }

    /// Every name [`name`] can produce, paired with its identifier.
    ///
    /// Held as one table so the two directions cannot drift: a name this build
    /// prints but will not accept back would break the path from `inspect` to a
    /// policy, which is the reason the names are usable at all.
    pub const NAMED: &[(&str, i64)] = &[
        ("ES256", ES256),
        ("ES384", ES384),
        ("ES512", ES512),
        ("PS256", PS256),
        ("PS384", PS384),
        ("PS512", PS512),
        ("RS256", RS256),
        ("RS384", -258),
        ("RS512", -259),
        ("EdDSA", -8),
        ("SHA-256", SHA256),
        ("SHA-384", SHA384),
        ("SHA-512", SHA512),
    ];

    /// Resolve an algorithm name to its COSE identifier.
    ///
    /// Deliberately case-sensitive and exact. `es256` and `ES-256` are refused
    /// rather than repaired, because the registry spells these one way and a
    /// policy that accepts near-misses invites a name that looks right, reads
    /// right in review, and is not the algorithm anyone meant.
    pub fn from_name(name: &str) -> Option<i64> {
        NAMED
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, alg)| *alg)
    }
}

#[cfg(test)]
mod tests {
    use super::alg;

    /// `inspect` prints a name and a policy accepts one. If the two tables
    /// disagree, the discovery path this build advertises — read the name off
    /// the report, write it into the rule — silently stops working for that
    /// algorithm, and only for that algorithm.
    #[test]
    fn every_printed_algorithm_name_resolves_back_to_its_identifier() {
        for (name, id) in alg::NAMED {
            assert_eq!(
                alg::from_name(name),
                Some(*id),
                "'{name}' is printed but not accepted"
            );
            assert_eq!(&alg::name(*id), name, "{id} does not print as '{name}'");
        }
    }

    /// An identifier with no name renders as `alg(n)`. That is legible, but it
    /// is not a name, and accepting it back would invent a spelling the
    /// registry does not have.
    #[test]
    fn an_unnamed_identifier_has_no_name_to_resolve() {
        assert_eq!(alg::name(-9999), "alg(-9999)");
        assert_eq!(alg::from_name("alg(-9999)"), None);
    }
}
