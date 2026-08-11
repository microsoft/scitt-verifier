//! COSE and CWT header labels used by SCITT and CCF.

/// COSE protected header labels (RFC 9052 / IANA).
pub const ALG: i64 = 1;
pub const CONTENT_TYPE: i64 = 3;
pub const KID: i64 = 4;
pub const CWT_CLAIMS: i64 = 15;
pub const X5CHAIN: i64 = 33;

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
pub const CWT_IAT: i64 = 6;

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
            other => format!("alg({other})"),
        }
    }
}
