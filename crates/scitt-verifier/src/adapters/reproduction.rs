//! Running the image-reproduction adapter.
//!
//! This module owns what the pure crate must not: reading the evidence
//! directory, and extracting the payload from the statement that passed
//! acceptance. The payload is taken from that in-memory statement, never from
//! a second read of the file, so the claim appraised is provably the claim
//! that was verified.

use std::io::Read;
use std::path::{Path, PathBuf};

use repro::{Evidence, Payload, Requirements};
use scitt_policy::adapters::image_reproduction::ImageReproductionPolicy;
use scitt_receipt::Sign1;

use super::{AdapterAssessment, EvidenceSource};
use crate::outcome::{AdapterCheck, AdapterFinding, CheckState};
use crate::progress::{Event, Sink, Stage, State};

/// File names inside the `--evidence` directory. Fixed, so a bundle cannot
/// point the reader somewhere else.
pub const PUBLISHED_RECORD: &str = "published-reproduce.json";
pub const REBUILT_RECORD: &str = "rebuilt-reproduce.json";

/// Far above any real record (the 0.20.1 one is about 1 KiB). A bound, because
/// the directory is operator-supplied and read before anything is known about
/// it.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Published as the run's scope so it survives being quoted. The rebuild is
/// operator-supplied, and a copy of the published record passes.
const SCOPE: &str = "a supplied rebuild record matches the reproduction record this statement \
     commits to: the same recorded inputs and the same ordered filesystem layers. The rebuild \
     is operator-asserted; this does not establish that it was performed independently, that \
     any published image has these layers, or that any deployment runs them";

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
        checks: repro::CHECK_NAMES
            .iter()
            .map(|(name, label)| AdapterCheck {
                name: (*name).to_string(),
                label: (*label).to_string(),
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

/// Every check is required. None of them bounds the claim the way freshness
/// bounds the ledger adapter's; each is a link the claim depends on.
fn required_checks() -> Vec<String> {
    repro::CHECK_NAMES
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect()
}

pub fn appraise_evidence(
    source: EvidenceSource<'_>,
    statement: &Sign1,
    policy: &ImageReproductionPolicy,
    progress: &mut dyn Sink,
) -> AdapterAssessment {
    let dir = match source {
        EvidenceSource::Saved(dir) => dir,
        EvidenceSource::Live { .. } => {
            return not_attempted(
                "the image-reproduction adapter appraises supplied records only; it has no \
                 live evidence to collect",
            )
        }
    };

    progress.emit(Event::stage(
        Stage::Evidence,
        State::Started,
        "Reading the published and rebuilt reproduction records...",
    ));
    let (published, rebuilt) = match (
        read_bounded(dir, PUBLISHED_RECORD),
        read_bounded(dir, REBUILT_RECORD),
    ) {
        (Ok(p), Ok(r)) => (p, r),
        (Err(why), _) | (_, Err(why)) => {
            progress.emit(Event::stage(Stage::Evidence, State::Fail, why.clone()));
            return not_attempted(why);
        }
    };
    progress.emit(Event::stage(
        Stage::Evidence,
        State::Done,
        format!(
            "Published record {}, rebuilt record {}",
            presence(&published),
            presence(&rebuilt)
        ),
    ));

    let payload = match (&statement.payload, statement.content_type()) {
        (None, _) => Payload::Unavailable(
            "the statement's payload is detached, so its reproduction claim cannot be read".into(),
        ),
        (Some(_), None) => Payload::NotJson("(no content type)".into()),
        (Some(bytes), Some(ct)) if scitt_policy::declares_json(&ct) => Payload::Json(bytes),
        (Some(_), Some(ct)) => Payload::NotJson(ct),
    };

    progress.emit(Event::stage(
        Stage::Adapter,
        State::Started,
        "Comparing the rebuild with the committed reproduction record...",
    ));
    let appraisal = repro::appraise(
        payload,
        Evidence {
            published_record: published.as_deref(),
            rebuilt_record: rebuilt.as_deref(),
        },
        &Requirements {
            profile: &policy.profile,
            source_repository: &policy.source_repository,
            app: &policy.component.app,
            variant: &policy.component.variant,
        },
    );

    // Each compared value that differed, with both sides, so a reader sees
    // what drifted rather than only that something did.
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
            .map(|f| AdapterFinding {
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

fn presence(bytes: &Option<Vec<u8>>) -> String {
    match bytes {
        Some(b) => format!("{} bytes", b.len()),
        None => "absent".into(),
    }
}

fn map_state(state: repro::CheckState) -> CheckState {
    match state {
        repro::CheckState::Pass => CheckState::Pass,
        repro::CheckState::Fail => CheckState::Fail,
        repro::CheckState::CannotEvaluate => CheckState::CannotEvaluate,
    }
}

/// Read one named record from the evidence directory.
///
/// Absent is `Ok(None)`, which the adapter reports as cannot-evaluate. Present
/// but unusable — a directory, a link leading out of the bundle, or oversized —
/// is an error, because silently treating it as absent would hide that the
/// bundle is not what the operator thinks it is.
fn read_bounded(dir: &Path, name: &str) -> Result<Option<Vec<u8>>, String> {
    let root = dir
        .canonicalize()
        .map_err(|e| format!("could not open evidence directory {}: {e}", dir.display()))?;
    if !root.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let path: PathBuf = root.join(name);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
        Ok(_) => {}
    }
    let resolved = path
        .canonicalize()
        .map_err(|e| format!("could not resolve {}: {e}", path.display()))?;
    if !resolved.starts_with(&root) {
        return Err(format!(
            "{name} resolves outside the evidence directory; refusing to read it"
        ));
    }
    if !resolved.is_file() {
        return Err(format!("{name} in the evidence directory is not a file"));
    }
    let file = std::fs::File::open(&resolved)
        .map_err(|e| format!("could not read {}: {e}", resolved.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {}: {e}", resolved.display()))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(format!(
            "{name} is larger than {MAX_RECORD_BYTES} bytes; a reproduction record is a small \
             JSON document, so this is not one"
        ));
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("scitt-repro-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_absent_record_is_none_and_an_oversized_one_is_refused() {
        let dir = temp_dir("bounds");
        assert_eq!(read_bounded(&dir, PUBLISHED_RECORD).unwrap(), None);
        std::fs::write(
            dir.join(PUBLISHED_RECORD),
            vec![b' '; MAX_RECORD_BYTES as usize + 1],
        )
        .unwrap();
        assert!(read_bounded(&dir, PUBLISHED_RECORD).is_err());
        std::fs::write(dir.join(PUBLISHED_RECORD), b"{}").unwrap();
        assert_eq!(
            read_bounded(&dir, PUBLISHED_RECORD).unwrap(),
            Some(b"{}".to_vec())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_in_place_of_a_record_is_refused_not_ignored() {
        let dir = temp_dir("dir");
        std::fs::create_dir_all(dir.join(REBUILT_RECORD)).unwrap();
        assert!(read_bounded(&dir, REBUILT_RECORD).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_evidence_directory_is_an_error() {
        let dir = std::env::temp_dir().join("scitt-repro-does-not-exist-7f3a");
        assert!(read_bounded(&dir, PUBLISHED_RECORD).is_err());
    }

    #[test]
    fn an_appraisal_that_did_not_run_names_every_check_and_passes_none() {
        let a = not_attempted("why");
        assert_eq!(a.checks.len(), repro::CHECK_NAMES.len());
        assert!(a
            .checks
            .iter()
            .all(|c| c.state == CheckState::CannotEvaluate));
        assert!(!a.scoped_pass());
    }
}
