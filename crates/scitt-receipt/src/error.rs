//! Errors.
//!
//! Note what is deliberately absent: severity, exit codes, and verdict words.
//! This crate reports *what happened*; deciding whether it is fatal belongs to
//! the relying party. A browser renders an unbound receipt in red; a deployment
//! gate exits 1. Neither opinion belongs here.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input is not a parseable COSE_Sign1.
    Malformed(String),
    /// CBOR present but not the shape SCITT/CCF requires.
    Structure(String),
    /// A verifiable data structure this release does not implement.
    /// Not evidence that the receipt is bad.
    UnsupportedVds(i64),
    /// An algorithm this release does not implement.
    UnsupportedAlgorithm(i64),
    /// Trust material could not be loaded or used.
    TrustMaterial(String),
    /// The requested key is not in the key set.
    UnknownKid(String),
    /// A cryptographic operation failed to run (not: returned invalid).
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed COSE_Sign1: {m}"),
            Self::Structure(m) => write!(f, "unexpected structure: {m}"),
            Self::UnsupportedVds(v) => write!(
                f,
                "verifiable data structure {v} is not implemented; this release verifies only {} (CCF_LEDGER_SHA256)",
                crate::labels::CCF_LEDGER_SHA256
            ),
            Self::UnsupportedAlgorithm(a) => {
                write!(f, "algorithm {} is not supported", crate::labels::alg::name(*a))
            }
            Self::TrustMaterial(m) => write!(f, "trust material unusable: {m}"),
            Self::UnknownKid(k) => write!(
                f,
                "no key with kid '{k}' in the key set; transparency services rotate signing keys"
            ),
            Self::Crypto(m) => write!(f, "cryptographic operation failed: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::Structure(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
