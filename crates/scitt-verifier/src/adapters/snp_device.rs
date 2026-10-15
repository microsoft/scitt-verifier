//! Running the AMD SEV-SNP device adapter.
//!
//! This module owns what the pure crate must not: reading the evidence
//! directory, and taking the payload from the statement that passed
//! acceptance. The payload comes from that in-memory statement, never from a
//! second read of the file, so the device claim appraised is provably the one
//! that was verified.

use std::path::Path;

use scitt_policy::adapters::amd_snp_device::AmdSnpDevicePolicy;
use scitt_receipt::Sign1;

use super::{AdapterAssessment, EvidenceSource};
use crate::outcome::{AdapterCheck, CheckState};
use crate::progress::Sink;
#[cfg(feature = "adapter-amd-snp-device")]
use crate::progress::State;
use crate::progress::{Event, Stage};

/// File names inside the `--evidence` directory. Fixed, so a bundle cannot
/// point the reader somewhere else.
pub const REPORT: &str = "report.bin";
pub const VCEK: &str = "vcek.der";
pub const CERT_CHAIN: &str = "cert_chain.pem";
pub const NONCE: &str = "nonce.hex";

/// Published as the run's scope so it survives being quoted.
#[cfg_attr(not(feature = "adapter-amd-snp-device"), allow(dead_code))]
const SCOPE: &str = "the chip that signed the supplied SNP report is the device whose serial \
     this statement records, its firmware meets the configured TCB floor, and the report \
     carries the supplied nonce. The guest's software is not appraised, the serial and the \
     chip's hardware ID are assumed to be the same identifier, and AMD revocation is not \
     consulted";

pub fn check_event(check: &AdapterCheck, detail: String) -> Event {
    Event::finding(
        Stage::Adapter,
        &check.name,
        None,
        crate::progress_state(check.state),
        detail,
    )
}

pub fn not_attempted(reason: impl Into<String>) -> AdapterAssessment {
    let reason = reason.into();
    AdapterAssessment {
        checks: check_names()
            .into_iter()
            .map(|(name, label)| AdapterCheck {
                name: name.to_string(),
                label: label.to_string(),
                state: CheckState::CannotEvaluate,
                detail: reason.clone(),
            })
            .collect(),
        findings: Vec::new(),
        required_checks: required_checks(),
        scope: "no evidence was appraised".to_string(),
        notes: vec![reason],
    }
}

/// Every check is required. Freshness in particular: without it a report
/// captured once, anywhere, would pass for as long as it was kept.
fn required_checks() -> Vec<String> {
    check_names()
        .into_iter()
        .map(|(name, _)| name.to_string())
        .collect()
}

/// The check names an appraisal reports, whether or not one ran.
#[cfg(feature = "adapter-amd-snp-device")]
fn check_names() -> Vec<(&'static str, &'static str)> {
    snpdev::CHECK_NAMES.to_vec()
}

/// What a build without the adapter reports. It still names the checks it
/// did not perform: a run that omitted them would be indistinguishable from
/// one where they were never relevant.
#[cfg_attr(feature = "adapter-amd-snp-device", allow(dead_code))]
const FALLBACK_CHECK_NAMES: [(&str, &str); 5] = [
    ("device-claim", "Statement device claim"),
    ("snp-report", "SNP report and AMD chain"),
    ("tcb-floor", "Minimum TCB"),
    ("freshness", "Report freshness"),
    ("device-binding", "Device binding"),
];

#[cfg(not(feature = "adapter-amd-snp-device"))]
fn check_names() -> Vec<(&'static str, &'static str)> {
    FALLBACK_CHECK_NAMES.to_vec()
}

#[cfg(not(feature = "adapter-amd-snp-device"))]
pub fn appraise_evidence(
    _source: EvidenceSource<'_>,
    _statement: &Sign1,
    _policy: &AmdSnpDevicePolicy,
    progress: &mut dyn Sink,
) -> AdapterAssessment {
    // Reported as cannot-evaluate so it exits 3: a build that silently skipped
    // the appraisal would let a gate pass on a check that never ran.
    progress.emit(Event::stage(
        Stage::Evidence,
        crate::progress::State::NotRun,
        "This build has no AMD SEV-SNP device adapter",
    ));
    progress.emit(Event::stage(
        Stage::Adapter,
        crate::progress::State::NotRun,
        "Rebuild with --features adapter-amd-snp-device",
    ));
    not_attempted(
        "this build was compiled without the AMD SEV-SNP device adapter, so no attestation \
         report can be appraised. Rebuild with --features adapter-amd-snp-device.",
    )
}

#[cfg(feature = "adapter-amd-snp-device")]
pub fn appraise_evidence(
    source: EvidenceSource<'_>,
    statement: &Sign1,
    policy: &AmdSnpDevicePolicy,
    progress: &mut dyn Sink,
) -> AdapterAssessment {
    use snpdev::{Evidence, Payload, Requirements, TcbFloor};

    let dir =
        match source {
            EvidenceSource::Saved(dir) => dir,
            EvidenceSource::Live { .. } => return not_attempted(
                "the amd-snp-device adapter appraises supplied evidence only; collect it on the \
                 device and pass --binding-mode saved-evidence --evidence <DIR>",
            ),
        };

    progress.emit(Event::stage(
        Stage::Evidence,
        State::Started,
        "Reading the SNP report, VCEK, AMD certificate chain and nonce...",
    ));
    let files = match read_all(dir) {
        Ok(files) => files,
        Err(why) => {
            progress.emit(Event::stage(Stage::Evidence, State::Fail, why.clone()));
            return not_attempted(why);
        }
    };
    progress.emit(Event::stage(
        Stage::Evidence,
        State::Done,
        [
            (REPORT, &files[0]),
            (VCEK, &files[1]),
            (CERT_CHAIN, &files[2]),
            (NONCE, &files[3]),
        ]
        .iter()
        .map(|(name, bytes)| format!("{name} {}", presence(bytes)))
        .collect::<Vec<_>>()
        .join(", "),
    ));

    let payload = match (&statement.payload, statement.content_type()) {
        (None, _) => Payload::Unavailable(
            "the statement's payload is detached, so its device claim cannot be read".into(),
        ),
        (Some(_), None) => Payload::NotJson("(no content type)".into()),
        (Some(bytes), Some(ct)) if scitt_policy::declares_json(&ct) => Payload::Json(bytes),
        (Some(_), Some(ct)) => Payload::NotJson(ct),
    };

    // Validation already parsed every floor; a failure here would mean the
    // policy changed under us, and is reported rather than defaulted.
    let mut floors = Vec::new();
    for entry in &policy.minimum_tcb {
        match entry.value() {
            Ok(value) => floors.push(TcbFloor {
                generation: &entry.generation,
                reported_tcb: value,
            }),
            Err(e) => return not_attempted(format!("adapters.amd-snp-device.minimumTcb: {e}")),
        }
    }

    progress.emit(Event::stage(
        Stage::Adapter,
        State::Started,
        "Binding the SNP report to the device the statement describes...",
    ));
    let appraisal = snpdev::appraise(
        payload,
        Evidence {
            report: files[0].as_deref(),
            vcek: files[1].as_deref(),
            cert_chain: files[2].as_deref(),
            nonce: files[3].as_deref(),
        },
        &Requirements {
            profile: &policy.profile,
            category: &policy.category,
            minimum_tcb: &floors,
        },
    );

    for finding in &appraisal.findings {
        progress.emit(Event::finding_with_values(
            Stage::Adapter,
            finding.check,
            Some(finding.subject.clone()),
            crate::progress_state(map_state(finding.state)),
            finding.detail.clone(),
            finding.expected.clone(),
            finding.observed.clone(),
        ));
    }

    AdapterAssessment {
        checks: appraisal
            .checks()
            .iter()
            .map(|(name, label, check)| AdapterCheck {
                name: (*name).to_string(),
                label: (*label).to_string(),
                state: map_state(check.state),
                detail: check.detail.clone(),
            })
            .collect(),
        findings: appraisal
            .findings
            .iter()
            .map(|f| crate::outcome::AdapterFinding {
                check: f.check.to_string(),
                subject: f.subject.clone(),
                state: map_state(f.state),
                detail: f.detail.clone(),
                expected: f.expected.clone(),
                observed: f.observed.clone(),
            })
            .collect(),
        required_checks: required_checks(),
        scope: SCOPE.to_string(),
        notes: appraisal.informational,
    }
}

/// The four evidence files, in [`REPORT`], [`VCEK`], [`CERT_CHAIN`],
/// [`NONCE`] order. Absent files are `None` and become cannot-evaluate;
/// present but unusable ones are an error.
#[cfg_attr(not(feature = "adapter-amd-snp-device"), allow(dead_code))]
fn read_all(dir: &Path) -> Result<[Option<Vec<u8>>; 4], String> {
    use super::reproduction::read_bounded_limit as read;
    Ok([
        // A report is 1184 bytes in every version so far.
        read(dir, REPORT, 4 * 1024, "an SNP report is about 1 KiB")?,
        read(dir, VCEK, 16 * 1024, "a VCEK is one certificate")?,
        read(
            dir,
            CERT_CHAIN,
            32 * 1024,
            "AMD's chain is two certificates",
        )?,
        read(dir, NONCE, 1024, "a nonce is at most 64 bytes of hex")?,
    ])
}

#[cfg(feature = "adapter-amd-snp-device")]
fn presence(bytes: &Option<Vec<u8>>) -> String {
    match bytes {
        Some(b) => format!("{} bytes", b.len()),
        None => "absent".into(),
    }
}

#[cfg(feature = "adapter-amd-snp-device")]
fn map_state(state: snpdev::CheckState) -> CheckState {
    match state {
        snpdev::CheckState::Pass => CheckState::Pass,
        snpdev::CheckState::Fail => CheckState::Fail,
        snpdev::CheckState::CannotEvaluate => CheckState::CannotEvaluate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_appraisal_that_did_not_run_names_every_check_and_passes_none() {
        let a = not_attempted("why");
        assert_eq!(a.checks.len(), 5);
        assert!(a
            .checks
            .iter()
            .all(|c| c.state == CheckState::CannotEvaluate));
        assert!(!a.scoped_pass());
    }

    #[test]
    fn an_oversized_report_is_refused_rather_than_read() {
        let dir = std::env::temp_dir().join(format!("scitt-snpdev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_all(&dir).unwrap().iter().all(Option::is_none));
        std::fs::write(dir.join(REPORT), vec![0u8; 4 * 1024 + 1]).unwrap();
        assert!(read_all(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two builds must agree about which checks a run skipped.
    #[cfg(feature = "adapter-amd-snp-device")]
    #[test]
    fn the_fallback_check_names_are_the_adapters() {
        assert_eq!(FALLBACK_CHECK_NAMES, snpdev::CHECK_NAMES);
    }
}
