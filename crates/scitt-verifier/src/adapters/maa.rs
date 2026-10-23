//! Azure Attestation acquisition and comparison against the accepted payload.

use super::{AdapterAssessment, EvidenceSource};
use crate::outcome::{AdapterCheck, CheckState};
use crate::progress::{Event, Sink, Stage, State};
use scitt_policy::adapters::maa::MaaPolicy;
use scitt_receipt::Sign1;

pub const SCOPE: &str = "AMD-authenticated SNP reports in supplied MAA certificate evidence contain HOST_DATA matching SHA-256 of the accepted statement execution policy; this does not authenticate service/signing-key/serving-node identity, guest enforcement or freshness";

#[cfg(any(feature = "adapter-azure-attestation", test))]
fn target_host<'a>(policy: &'a MaaPolicy, endpoint: Option<&'a str>) -> Result<&'a str, String> {
    match endpoint {
        Some(endpoint) => scitt_network::maa::endpoint_host(endpoint).map_err(|e| e.to_string()),
        None => policy
            .target
            .as_ref()
            .map(|target| target.host.as_str())
            .ok_or_else(|| {
                "MAA acquisition requires --maa-endpoint or policy target.host; saved evidence requires policy target.host"
                    .into()
            }),
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn explicit_endpoint_overrides_policy_and_is_used_as_saved_target() {
        let mut policy: MaaPolicy = serde_json::from_value(serde_json::json!({
            "target": {"host": "policy.attest.azure.net"},
            "binding": {"path": ["security-policy-base64"], "encoding": "base64"}
        }))
        .unwrap();
        assert_eq!(
            target_host(&policy, None).unwrap(),
            "policy.attest.azure.net"
        );
        let host = target_host(&policy, Some("https://cli.attest.azure.net/")).unwrap();
        assert_eq!(host, "cli.attest.azure.net");
        let evidence = bundle::Bundle {
            schema_version: 1,
            target_host: host.into(),
            service_version: None,
            certs: serde_json::json!({"keys": []}),
        };
        evidence.validate(host).unwrap();
        assert!(evidence.validate("policy.attest.azure.net").is_err());
        policy.target = None;
        assert_eq!(
            target_host(&policy, Some("https://cli.attest.azure.net")).unwrap(),
            "cli.attest.azure.net"
        );
        assert!(target_host(&policy, None).is_err());
        assert!(target_host(&policy, Some("http://cli.attest.azure.net")).is_err());
    }
}

#[cfg(feature = "adapter-azure-attestation")]
fn check_names() -> &'static [(&'static str, &'static str)] {
    maa::CHECK_NAMES
}

#[cfg(not(feature = "adapter-azure-attestation"))]
fn check_names() -> &'static [(&'static str, &'static str)] {
    &[
        ("snp-validation", "SNP report authentication"),
        ("cce-policy-host-data", "CCE policy HOST_DATA"),
        (
            "maa-certificate-coverage",
            "MAA evidence certificate coverage",
        ),
    ]
}

pub fn not_attempted(reason: impl Into<String>) -> AdapterAssessment {
    let reason = reason.into();
    AdapterAssessment {
        checks: check_names()
            .iter()
            .map(|(name, label)| AdapterCheck {
                name: (*name).into(),
                label: (*label).into(),
                state: CheckState::CannotEvaluate,
                detail: reason.clone(),
            })
            .collect(),
        findings: Vec::new(),
        required_checks: check_names()
            .iter()
            .map(|(name, _)| (*name).into())
            .collect(),
        scope: SCOPE.into(),
        notes: vec![
            reason,
            "Requested comparison only: AMD-authenticated SNP HOST_DATA against the accepted statement execution policy; service identity, guest enforcement and freshness are not established.".into(),
        ],
    }
}

#[cfg(not(feature = "adapter-azure-attestation"))]
pub fn appraise_evidence(
    _source: EvidenceSource<'_>,
    _statement: &Sign1,
    _policy: &MaaPolicy,
    progress: &mut dyn Sink,
) -> AdapterAssessment {
    progress.emit(Event::stage(
        Stage::Adapter,
        State::NotRun,
        "Rebuild with --features adapter-azure-attestation",
    ));
    not_attempted(
        "this build was compiled without the Azure Attestation adapter; rebuild with --features adapter-azure-attestation",
    )
}

#[cfg(feature = "adapter-azure-attestation")]
pub fn appraise_evidence(
    source: EvidenceSource<'_>,
    statement: &Sign1,
    policy: &MaaPolicy,
    progress: &mut dyn Sink,
) -> AdapterAssessment {
    let endpoint = match &source {
        EvidenceSource::Live { maa_endpoint, .. } => *maa_endpoint,
        EvidenceSource::Saved(_) => None,
    };
    let host = match target_host(policy, endpoint) {
        Ok(host) => host,
        Err(reason) => return not_attempted(reason),
    };
    let extracted: Result<_, String> = (|| {
        policy.validate()?;
        let alphabet = match policy.binding.encoding {
            scitt_policy::adapters::maa::Encoding::Base64 => {
                scitt_receipt::base64::Alphabet::Standard
            }
            scitt_policy::adapters::maa::Encoding::Base64url => {
                scitt_receipt::base64::Alphabet::UrlSafe
            }
        };
        let bytes =
            scitt_policy::claim::encoded_claim_bytes(statement, &policy.binding.path, alphabet)
                .map_err(|e| e.describe())?;
        if policy
            .binding
            .max_decoded_bytes
            .is_some_and(|max| bytes.len() > max)
        {
            return Err("the decoded CCE policy exceeds binding.maxDecodedBytes".into());
        }
        Ok(scitt_receipt::sha256(&bytes))
    })();
    let digest = match extracted {
        Ok(value) => value,
        Err(reason) => return not_attempted(reason),
    };

    progress.emit(Event::stage(
        Stage::Evidence,
        State::Started,
        "Reading Azure Attestation certificate evidence",
    ));
    let saved = matches!(source, EvidenceSource::Saved(_));
    let acquired = (|| {
        let bundle = match source {
            EvidenceSource::Saved(dir) => bundle::load(dir)?,
            EvidenceSource::Live { save_to, .. } => {
                let acquired = scitt_network::maa::collect(host)
                    .map_err(|e| format!("Azure Attestation evidence acquisition failed: {e}"))?;
                let certs = scitt_policy::parse_payload_json(&acquired.certs_json)?;
                let evidence = bundle::Bundle {
                    schema_version: 1,
                    target_host: host.into(),
                    service_version: acquired.service_version,
                    certs,
                };
                evidence.validate(host)?;
                if let Some(dir) = save_to {
                    bundle::save(dir, &evidence)
                        .map_err(|e| format!("collected evidence could not be preserved: {e}"))?;
                }
                evidence
            }
        };
        bundle.validate(host)?;
        Ok::<_, String>(bundle)
    })();
    let bundle = match acquired {
        Ok(bundle) => bundle,
        Err(reason) => {
            progress.emit(Event::stage(
                Stage::Evidence,
                State::CannotEvaluate,
                reason.clone(),
            ));
            return not_attempted(reason);
        }
    };
    progress.emit(Event::stage(
        Stage::Evidence,
        State::Done,
        "Azure Attestation evidence loaded",
    ));
    let certs = match serde_json::to_vec(&bundle.certs) {
        Ok(certs) => certs,
        Err(e) => return not_attempted(format!("certificate evidence could not be read: {e}")),
    };
    let appraisal = maa::appraise(&certs, &digest);
    let mut notes = appraisal.notes;
    notes.push(format!(
        "MAA certificate evidence target: {host}; {}. The target is acquisition metadata, not authenticated report identity.",
        if endpoint.is_some() {
            "--maa-endpoint takes precedence over the policy target"
        } else {
            "selected from policy target.host"
        }
    ));
    notes.push(match &bundle.service_version {
        Some(version) => format!("The /certs service-version metadata observation was {version:?}; it was not compared with the statement and does not affect acceptance."),
        None => "No /certs service-version metadata was recorded; version metadata does not affect acceptance.".into(),
    });
    if saved {
        notes.push("Saved maa-evidence.json metadata is unsigned and collector-asserted; targetHost and serviceVersion do not authenticate bundle origin or freshness.".into());
    }
    AdapterAssessment {
        checks: appraisal
            .checks
            .into_iter()
            .map(|check| AdapterCheck {
                name: check.name.into(),
                label: check.label.into(),
                state: map_state(check.state),
                detail: check.detail,
            })
            .collect(),
        findings: appraisal
            .findings
            .into_iter()
            .map(|finding| crate::outcome::AdapterFinding {
                check: finding.check.into(),
                subject: finding.subject,
                state: map_state(finding.state),
                detail: finding.detail,
                expected: finding.expected,
                observed: finding.observed,
            })
            .collect(),
        required_checks: check_names()
            .iter()
            .map(|(name, _)| (*name).into())
            .collect(),
        scope: SCOPE.into(),
        notes,
    }
}

#[cfg(feature = "adapter-azure-attestation")]
fn map_state(state: maa::CheckState) -> CheckState {
    match state {
        maa::CheckState::Pass => CheckState::Pass,
        maa::CheckState::Fail => CheckState::Fail,
        maa::CheckState::CannotEvaluate => CheckState::CannotEvaluate,
    }
}

#[cfg(any(feature = "adapter-azure-attestation", test))]
mod bundle {
    use serde::{Deserialize, Serialize};
    use std::io::{Read, Write};
    use std::path::Path;

    pub const FILE: &str = "maa-evidence.json";
    pub const MAX_BYTES: u64 = 4 << 20;

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    pub struct Bundle {
        pub schema_version: u32,
        pub target_host: String,
        pub service_version: Option<String>,
        pub certs: serde_json::Value,
    }

    impl Bundle {
        pub fn validate(&self, target: &str) -> Result<(), String> {
            if self.schema_version != 1 {
                return Err("unsupported maa-evidence.json schemaVersion; expected 1".into());
            }
            if self.target_host != target || target.trim().is_empty() {
                return Err(
                    "maa-evidence.json targetHost does not exactly match policy target.host".into(),
                );
            }
            if !self.certs.is_object() {
                return Err(
                    "maa-evidence.json certs must be the JSON object returned by /certs".into(),
                );
            }
            Ok(())
        }
    }

    pub fn load(dir: &Path) -> Result<Bundle, String> {
        let root = std::fs::canonicalize(dir).map_err(|e| format!("evidence directory: {e}"))?;
        let path = std::fs::canonicalize(root.join(FILE)).map_err(|e| format!("{FILE}: {e}"))?;
        if !path.starts_with(&root) {
            return Err(format!("{FILE} escapes the evidence directory"));
        }
        let file = std::fs::File::open(&path).map_err(|e| format!("{FILE}: {e}"))?;
        let metadata = file.metadata().map_err(|e| format!("{FILE}: {e}"))?;
        if !metadata.is_file() || metadata.len() > MAX_BYTES {
            return Err(format!(
                "{FILE} must be a regular file at most {MAX_BYTES} bytes"
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("{FILE}: {e}"))?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(format!("{FILE} exceeds {MAX_BYTES} bytes"));
        }
        let value = scitt_policy::parse_payload_json(&bytes)?;
        serde_json::from_value(value).map_err(|e| format!("{FILE}: {e}"))
    }

    pub fn save(dir: &Path, bundle: &Bundle) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(bundle).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(format!("saved evidence exceeds {MAX_BYTES} bytes"));
        }
        std::fs::create_dir_all(dir).map_err(|e| format!("evidence directory: {e}"))?;
        let path = dir.join(FILE);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("{FILE}: {e}"))?;
        let result = file
            .write_all(&bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = result {
            // A partial recording must not look like the requested preserved evidence.
            if let Err(cleanup) = std::fs::remove_file(&path) {
                return Err(format!(
                    "saving {FILE}: {e}; could not remove the partial evidence file: {cleanup}"
                ));
            }
            return Err(format!("saving {FILE}: {e}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn evidence() -> bundle::Bundle {
        bundle::Bundle {
            schema_version: 1,
            target_host: "attestation.example".into(),
            service_version: Some("example-build".into()),
            certs: json!({"keys": []}),
        }
    }

    fn test_dir(name: &str) -> std::path::PathBuf {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("maa-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn metadata_must_match_exact_host_schema_and_certs_object() {
        let mut evidence = evidence();
        assert!(evidence.validate("attestation.example").is_ok());
        assert!(evidence.validate("ATTESTATION.example").is_err());
        evidence.schema_version = 2;
        assert!(evidence.validate("attestation.example").is_err());
        evidence.schema_version = 1;
        evidence.certs = json!([]);
        assert!(evidence.validate("attestation.example").is_err());
        evidence.certs = json!({});
        evidence.service_version = Some(String::new());
        assert!(evidence.validate("attestation.example").is_ok());
        evidence.service_version = None;
        assert!(evidence.validate("attestation.example").is_ok());
    }

    #[test]
    fn saved_evidence_is_bounded_and_never_overwritten() {
        let dir = test_dir("save");
        bundle::save(&dir, &evidence()).unwrap();
        let bytes = std::fs::read(dir.join(bundle::FILE)).unwrap();
        assert!(bundle::save(&dir, &evidence()).is_err());
        assert_eq!(std::fs::read(dir.join(bundle::FILE)).unwrap(), bytes);
        assert!(bundle::load(&dir)
            .unwrap()
            .validate("attestation.example")
            .is_ok());
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join(bundle::FILE))
            .unwrap();
        file.set_len(bundle::MAX_BYTES + 1).unwrap();
        assert!(bundle::load(&dir).is_err());
        drop(file);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn serialized_metadata_cannot_push_a_saved_bundle_over_the_replay_limit() {
        let dir = test_dir("serialized-limit");
        let mut evidence = evidence();
        evidence.certs = json!({"padding": "x".repeat(bundle::MAX_BYTES as usize - 32)});
        assert!(serde_json::to_vec(&evidence.certs).unwrap().len() as u64 <= bundle::MAX_BYTES);
        let error = bundle::save(&dir, &evidence).unwrap_err();
        assert!(error.contains("saved evidence exceeds"), "{error}");
        assert!(!dir.join(bundle::FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_duplicate_and_unknown_metadata_cannot_be_loaded() {
        let dir = test_dir("metadata");
        for bytes in [
            br#"{"schemaVersion":1,"schemaVersion":1}"#.as_slice(),
            br#"{"schemaVersion":1,"targetHost":"attestation.example","certs":{},"unknown":true}"#
                .as_slice(),
            b"not-json".as_slice(),
        ] {
            std::fs::write(dir.join(bundle::FILE), bytes).unwrap();
            assert!(bundle::load(&dir).is_err());
        }

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_bundle_symlink_cannot_escape_its_directory() {
        let dir = test_dir("symlink");
        let outside = test_dir("outside");
        bundle::save(&outside, &evidence()).unwrap();
        std::os::unix::fs::symlink(outside.join(bundle::FILE), dir.join(bundle::FILE)).unwrap();
        assert!(bundle::load(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn exactly_the_three_scoped_comparison_checks_are_required() {
        let mut result = not_attempted("not available");
        assert!(!result.scoped_pass());
        assert_eq!(
            result.required_checks,
            [
                "snp-validation",
                "cce-policy-host-data",
                "maa-certificate-coverage"
            ]
        );
        assert!(result
            .checks
            .iter()
            .all(|c| c.state == CheckState::CannotEvaluate));
        for check in &mut result.checks {
            check.state = CheckState::Pass;
        }
        assert!(result.scoped_pass());
        for index in 0..result.checks.len() {
            result.checks[index].state = CheckState::CannotEvaluate;
            assert!(!result.scoped_pass());
            result.checks[index].state = CheckState::Pass;
        }
    }
}
