//! Bounded certificate loading and mapping of pure HBOM appraisal findings.

use super::AdapterAssessment;
use crate::outcome::{AdapterCheck, CheckState};
use hbom::{Appraisal, Evidence, HbomPolicy};
use scitt_receipt::{chain, Sign1};
use std::io::Read;
use std::path::Path;

fn assessment(appraisal: Appraisal) -> AdapterAssessment {
    AdapterAssessment {
        checks: appraisal
            .checks()
            .into_iter()
            .map(|(name, label, check)| AdapterCheck {
                name: name.into(),
                label: label.into(),
                state: match check.state {
                    hbom::CheckState::Pass => CheckState::Pass,
                    hbom::CheckState::Fail => CheckState::Fail,
                    hbom::CheckState::CannotEvaluate => CheckState::CannotEvaluate,
                },
                detail: check.detail.clone(),
            })
            .collect(),
        findings: Vec::new(),
        required_checks: hbom::CHECK_NAMES
            .iter()
            .map(|(name, _)| (*name).into())
            .collect(),
        scope: "offline certificate association to exact bytes of an accepted statement claim; no device possession or workload state verified".into(),
        notes: Vec::new(),
    }
}

pub fn not_attempted(reason: impl Into<String>) -> AdapterAssessment {
    assessment(Appraisal::unevaluated(reason))
}

fn read_pem(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("could not open {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    if bytes.len() > 1024 * 1024 {
        return Err(format!(
            "{} exceeds the 1 MiB certificate input limit",
            path.display()
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| format!("{} is not UTF-8 PEM: {e}", path.display()))?;
    let certs = chain::parse_pem_certificates(text)
        .map_err(|e| format!("{} is not a PEM certificate bundle: {e}", path.display()))?;
    if certs.is_empty() || certs.len() > 16 {
        return Err("certificate input must contain 1 to 16 certificates".into());
    }
    Ok(certs)
}

pub fn appraise(
    statement: &Sign1,
    policy: &HbomPolicy,
    evidence: &Path,
    roots_file: &Path,
    now: i64,
) -> AdapterAssessment {
    let certs = match read_pem(evidence) {
        Ok(certs) => certs,
        Err(e) => return not_attempted(e),
    };
    let roots = match read_pem(roots_file) {
        Ok(roots) => roots,
        Err(e) => return not_attempted(e),
    };
    assessment(hbom::appraise(
        statement,
        policy,
        Evidence {
            certificates: &certs,
            trusted_roots: &roots,
        },
        now,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_bytes(name: &str, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let path = std::env::temp_dir().join(format!(
            "scitt-hbom-loader-{}-{name}.pem",
            std::process::id()
        ));
        std::fs::write(&path, bytes).unwrap();
        let result = read_pem(&path);
        std::fs::remove_file(&path).unwrap();
        result
    }

    #[test]
    fn pem_loading_preserves_size_and_certificate_count_bounds() {
        let pem = include_str!("../../../../corpus/fixtures/synthetic-hbom/root.pem");
        assert_eq!(load_bytes("one", pem.as_bytes()).unwrap().len(), 1);
        assert_eq!(
            load_bytes("sixteen", pem.repeat(16).as_bytes())
                .unwrap()
                .len(),
            16
        );
        assert!(load_bytes("seventeen", pem.repeat(17).as_bytes())
            .unwrap_err()
            .contains("1 to 16 certificates"));

        let mut bytes = pem.as_bytes().to_vec();
        bytes.resize(1024 * 1024, b'\n');
        assert_eq!(load_bytes("limit", &bytes).unwrap().len(), 1);
        bytes.push(b'\n');
        assert!(load_bytes("over-limit", &bytes)
            .unwrap_err()
            .contains("exceeds the 1 MiB certificate input limit"));
    }

    #[test]
    fn invalid_pem_inputs_are_reported_not_ignored() {
        for (name, bytes, expected) in [
            ("empty", b"".as_slice(), "not a PEM certificate bundle"),
            (
                "non-pem",
                b"not PEM".as_slice(),
                "not a PEM certificate bundle",
            ),
            ("non-utf8", &[0xff], "not UTF-8 PEM"),
        ] {
            assert!(load_bytes(name, bytes).unwrap_err().contains(expected));
        }
        let result = not_attempted("unreadable certificate evidence");
        assert!(!result.scoped_pass());
        assert_eq!(result.checks.len(), 2);
        assert!(result.checks.iter().all(|check| {
            check.state == CheckState::CannotEvaluate
                && check.detail == "unreadable certificate evidence"
        }));
    }
}
