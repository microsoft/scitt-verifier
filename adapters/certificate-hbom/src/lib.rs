//! Offline association of an accepted HBOM claim with an authenticated certificate.
//!
//! Callers supply a previously accepted statement, DER certificate evidence,
//! independently selected roots, typed requirements, and a verification time.
//! This crate neither accepts the statement nor decides a deployment verdict.
//! Only the explicit synthetic commitment profile is supported; this is not
//! proof of device possession, workload state, or certificate revocation status.

pub use scitt_policy::adapters::hbom::HbomPolicy;
use scitt_policy::adapters::hbom::{ClaimEncoding, DigestEncoding, HbomSource};
use scitt_receipt::base64::Alphabet;
use scitt_receipt::chain::{self, Options, Outcome};
use scitt_receipt::{der, Sign1};
use sha2::{Digest, Sha384};

/// In-memory DER certificates, with roots selected independently of the evidence.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// Leaf first, followed by its issuing chain; no competing certificates.
    pub certificates: &'a [Vec<u8>],
    /// Candidate trust anchors; exactly one must match the policy's root pin.
    pub trusted_roots: &'a [Vec<u8>],
}

/// Domain check states, independent of any consumer's verdict vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Pass,
    Fail,
    CannotEvaluate,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub state: CheckState,
    pub detail: String,
}

/// Both findings are required; neither may stand in for the other.
#[derive(Debug, Clone)]
pub struct Appraisal {
    pub certificate_trust: Check,
    pub hbom_commitment: Check,
}

pub const CHECK_NAMES: [(&str, &str); 2] = [
    ("certificate-trust", "Certificate path, role and trust"),
    ("hbom-commitment", "Exact HBOM byte commitment"),
];

impl Appraisal {
    pub fn unevaluated(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        assessment(
            CheckState::CannotEvaluate,
            reason.clone(),
            CheckState::CannotEvaluate,
            reason,
        )
    }

    /// Stable report order shared by consumers.
    pub fn checks(&self) -> [(&'static str, &'static str, &Check); 2] {
        [
            (CHECK_NAMES[0].0, CHECK_NAMES[0].1, &self.certificate_trust),
            (CHECK_NAMES[1].0, CHECK_NAMES[1].1, &self.hbom_commitment),
        ]
    }
}

fn assessment(
    trust: CheckState,
    trust_detail: String,
    binding: CheckState,
    binding_detail: String,
) -> Appraisal {
    Appraisal {
        certificate_trust: Check {
            state: trust,
            detail: trust_detail,
        },
        hbom_commitment: Check {
            state: binding,
            detail: binding_detail,
        },
    }
}

fn blocked(state: CheckState, why: impl Into<String>) -> Appraisal {
    assessment(
        state,
        why.into(),
        CheckState::CannotEvaluate,
        "certificate trust did not pass; commitment cannot be attributed to an approved issuer"
            .into(),
    )
}

/// Appraise at `now` (Unix seconds), without obtaining evidence or reading a clock.
///
/// `statement` must be the same in-memory statement the caller already accepted.
/// Its HBOM source is decoded according to `policy`, never canonicalized.
pub fn appraise(
    statement: &Sign1,
    policy: &HbomPolicy,
    evidence: Evidence<'_>,
    now: i64,
) -> Appraisal {
    // Library callers can construct requirements without parsing a policy file.
    if let Err(e) = policy.validate() {
        return Appraisal::unevaluated(e);
    }
    let certs = evidence.certificates;
    let approved_roots: Vec<_> = evidence
        .trusted_roots
        .iter()
        .filter(|root| scitt_receipt::sha256_hex(root).eq_ignore_ascii_case(&policy.root_sha256))
        .cloned()
        .collect();
    if approved_roots.len() != 1 {
        return blocked(
            CheckState::Fail,
            format!(
                "independent root file must contain exactly one certificate matching policy rootSha256 {}; found {}",
                policy.root_sha256,
                approved_roots.len()
            ),
        );
    }
    let options = Options {
        trusted_roots: approved_roots,
        require_valid_at: Some(now),
    };
    // The chain's first certificate is the leaf; never search for a convenient
    // matching extension in an untrusted intermediate or alternative leaf.
    match chain::validate(certs, &options) {
        Ok(Outcome::Valid(details)) if details.anchored_externally => {
            if details.path_len != certs.len() && details.path_len != certs.len() + 1 {
                return blocked(
                    CheckState::Fail,
                    "certificate evidence includes certificates outside the validated path",
                );
            }

            let actual = details
                .root_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if !actual.eq_ignore_ascii_case(&policy.root_sha256) {
                return blocked(
                    CheckState::Fail,
                    format!("validated anchor SHA-256 {actual} does not match the policy pin"),
                );
            }
        }
        Ok(Outcome::Valid(_)) => {
            return blocked(
                CheckState::CannotEvaluate,
                "no independently supplied root anchored the certificate",
            )
        }
        Ok(Outcome::Invalid(e)) => return blocked(CheckState::Fail, e),
        Ok(Outcome::Unsupported(e) | Outcome::Insufficient(e))
        | Err(scitt_receipt::Error::TrustMaterial(e)) => {
            return blocked(CheckState::CannotEvaluate, e)
        }
        Err(e) => return blocked(CheckState::CannotEvaluate, e.to_string()),
    }

    let leaf = &certs[0];
    let eku = match der::unique_extension(leaf, "2.5.29.37") {
        Ok(Some(value)) => value,
        Ok(None) => return blocked(CheckState::Fail, "leaf certificate has no extendedKeyUsage"),
        Err(e) => return blocked(CheckState::Fail, e.to_string()),
    };
    match der::parse_eku_oids_strict(&eku) {
        Ok(oids) if oids.iter().any(|oid| oid == &policy.leaf_eku) => {}
        Ok(_) => {
            return blocked(
                CheckState::Fail,
                format!("leaf certificate lacks required EKU {}", policy.leaf_eku),
            )
        }
        Err(e) => return blocked(CheckState::Fail, e.to_string()),
    }

    let value = match der::unique_extension(leaf, &policy.profile.oid) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return assessment(
                CheckState::Pass,
                "certificate path, time, root pin and leaf EKU authenticated".into(),
                CheckState::Fail,
                "leaf certificate has no HBOM commitment extension".into(),
            )
        }
        Err(e) => {
            return assessment(
                CheckState::Pass,
                "certificate path, time, root pin and leaf EKU authenticated".into(),
                CheckState::Fail,
                e.to_string(),
            )
        }
    };
    let commitment =
        match policy.profile.encoding {
            DigestEncoding::Raw if value.len() == 48 => value.as_slice(),
            DigestEncoding::DerOctetString if value.len() == 50 && value[..2] == [0x04, 0x30] => {
                &value[2..]
            }
            _ => return assessment(
                CheckState::Pass,
                "certificate path, time, root pin and leaf EKU authenticated".into(),
                CheckState::Fail,
                "extension does not contain one SHA-384 digest in the policy's specified encoding"
                    .into(),
            ),
        };
    let hbom = match &policy.source {
        HbomSource::StatementPayload => match &statement.payload {
            Some(bytes) => bytes.clone(),
            None => {
                return assessment(
                    CheckState::Pass,
                    "certificate path, time, root pin and leaf EKU authenticated".into(),
                    CheckState::CannotEvaluate,
                    "accepted statement has no attached payload".into(),
                )
            }
        },
        HbomSource::EncodedClaim { path, encoding } => {
            let alphabet = match encoding {
                ClaimEncoding::Base64 => Alphabet::Standard,
                ClaimEncoding::Base64url => Alphabet::UrlSafe,
            };
            match scitt_policy::claim::encoded_claim_bytes(statement, path, alphabet) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return assessment(
                        CheckState::Pass,
                        "certificate path, time, root pin and leaf EKU authenticated".into(),
                        CheckState::CannotEvaluate,
                        format!(
                            "accepted statement's HBOM claim cannot be decoded: {}",
                            e.describe()
                        ),
                    )
                }
            }
        }
    };
    let digest = Sha384::digest(&hbom);
    let state = if &digest[..] == commitment {
        CheckState::Pass
    } else {
        CheckState::Fail
    };
    assessment(
        CheckState::Pass,
        format!(
            "certificate path, verification time, root {} and leaf EKU authenticated",
            policy.root_sha256
        ),
        state,
        format!(
            "SHA-384 commitment over {} exact decoded HBOM bytes {}",
            hbom.len(),
            if state == CheckState::Pass {
                "matches"
            } else {
                "does not match"
            }
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_synthetic_hbom_bytes_not_json_canonicalization() {
        let roots = chain::parse_pem_certificates(include_str!(
            "../../../corpus/fixtures/synthetic-hbom/root.pem"
        ))
        .unwrap();
        let policy_json = json!({
            "source": {"kind": "statement-payload"},
            "rootSha256": scitt_receipt::sha256_hex(&roots[0]),
            "leafEku": "1.3.6.1.4.1.55555.1.2",
            "profile": {"oid":"1.3.6.1.4.1.55555.1.1", "digest":"sha384", "encoding":"raw"}
        });
        let mut policy: HbomPolicy = serde_json::from_value(policy_json).unwrap();
        let mut statement =
            Sign1::parse(include_bytes!("../../../corpus/fixtures/cbor-header.cose")).unwrap();
        let hbom = include_bytes!("../../../corpus/fixtures/synthetic-hbom/hbom.json").to_vec();
        statement.payload = Some(hbom.clone());
        let certs = chain::parse_pem_certificates(include_str!(
            "../../../corpus/fixtures/synthetic-hbom/hbom.pem"
        ))
        .unwrap();
        let evidence = Evidence {
            certificates: &certs,
            trusted_roots: &roots,
        };
        let result = appraise(&statement, &policy, evidence, 1785197841);
        assert_eq!(result.certificate_trust.state, CheckState::Pass);
        assert_eq!(result.hbom_commitment.state, CheckState::Pass);

        let mut changed = hbom.clone();
        changed.insert(1, b' ');
        statement.payload = Some(changed);
        let result = appraise(&statement, &policy, evidence, 1785197841);
        assert_eq!(result.certificate_trust.state, CheckState::Pass);
        assert_eq!(result.hbom_commitment.state, CheckState::Fail);

        policy.source = HbomSource::EncodedClaim {
            path: vec![scitt_policy::PathSegment::Text("hbom".into())],
            encoding: ClaimEncoding::Base64,
        };
        // The CLI invokes the adapter only after accepting the real statement.
        statement.payload = Some(
            serde_json::to_vec(&json!({
                "hbom": "eyJkb2N1bWVudFR5cGUiOiJzeW50aGV0aWMtaGJvbSIsImNvbXBvbmVudHMiOlt7ImlkIjoiVEVTVC1PTkxZLVBBUlQifV19Cg=="
            }))
            .unwrap(),
        );
        let result = appraise(&statement, &policy, evidence, 1785197841);
        assert_eq!(result.certificate_trust.state, CheckState::Pass);
        assert_eq!(result.hbom_commitment.state, CheckState::Pass);
    }
}
