//! COSE and CWT header labels used by SCITT and CCF.

/// COSE protected header labels (RFC 9052 / IANA).
pub const ALG: i64 = 1;
pub const CONTENT_TYPE: i64 = 3;
pub const KID: i64 = 4;
pub const CWT_CLAIMS: i64 = 15;
pub const X5CHAIN: i64 = 33;
/// Certificate thumbprint: `[hash-alg, digest]`.
pub const X5T: i64 = 34;

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
            // Hash algorithms from the same registry, used by `x5t`.
            -16 => "SHA-256".into(),
            -43 => "SHA-384".into(),
            -44 => "SHA-512".into(),
            other => format!("alg({other})"),
        }
    }
}
