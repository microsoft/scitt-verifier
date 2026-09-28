//! Offline certificate commitment to the exact bytes of an accepted HBOM claim.

use crate::PathSegment;
use serde::{Deserialize, Serialize};

/// This profile is synthetic. No vendor device certificate format is implied.
pub const SYNTHETIC_OID: &str = "1.3.6.1.4.1.55555.1.1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HbomPolicy {
    pub source: HbomSource,
    pub root_sha256: String,
    pub leaf_eku: String,
    pub profile: CommitmentProfile,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HbomSource {
    StatementPayload,
    EncodedClaim {
        path: Vec<PathSegment>,
        encoding: ClaimEncoding,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimEncoding {
    Base64,
    Base64url,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommitmentProfile {
    pub oid: String,
    pub digest: Digest,
    pub encoding: DigestEncoding,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Digest {
    Sha384,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestEncoding {
    Raw,
    DerOctetString,
}

impl HbomPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if let HbomSource::EncodedClaim { path, .. } = &self.source {
            if path.is_empty() {
                return Err("source.path must name an encoded HBOM claim".into());
            }
        }
        if self.root_sha256.len() != 64 || !self.root_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("rootSha256 must be a 64-character hex SHA-256 fingerprint".into());
        }
        if self.leaf_eku.split('.').count() < 2
            || !self
                .leaf_eku
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("leafEku must be a dotted OID".into());
        }
        if self.profile.oid != SYNTHETIC_OID {
            return Err(format!(
                "unsupported certificate commitment profile OID {}; only synthetic {} is implemented",
                self.profile.oid, SYNTHETIC_OID
            ));
        }
        Ok(())
    }
}
