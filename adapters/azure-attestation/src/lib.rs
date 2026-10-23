//! Offline SNP authenticity and policy HOST_DATA appraisal, not a resource verdict.
//!
//! A successful appraisal establishes only that AMD-authenticated reports
//! contain the caller's policy digest. It does not authenticate an MAA signing
//! key, endpoint or connection, or establish guest execution or enforcement.
//! Callers must escape untrusted finding text before rendering it.

#[cfg(feature = "azure-attestation")]
mod evidence;
#[cfg(feature = "azure-attestation")]
mod snp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Pass,
    Fail,
    CannotEvaluate,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub label: &'static str,
    pub state: CheckState,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub check: &'static str,
    pub subject: String,
    pub state: CheckState,
    pub detail: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Appraisal {
    pub checks: Vec<Check>,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

pub const CHECK_NAMES: &[(&str, &str)] = &[
    ("snp-validation", "SNP report authentication"),
    ("cce-policy-host-data", "CCE policy HOST_DATA"),
    (
        "maa-certificate-coverage",
        "MAA evidence certificate coverage",
    ),
];

pub fn unevaluated(reason: &str) -> Appraisal {
    Appraisal {
        checks: CHECK_NAMES
            .iter()
            .map(|&(name, label)| Check {
                name,
                label,
                state: CheckState::CannotEvaluate,
                detail: reason.into(),
            })
            .collect(),
        findings: Vec::new(),
        notes: vec![
            "MAA service signing-key, endpoint and connection identity are not established; KID and public-key binding are not checked".into(),
            "Evidence freshness is not checked".into(),
            "UVM endorsements are not interpreted or checked; guest execution and security-policy enforcement are not validated".into(),
            "No relying-party platform acceptance policy, minimum TCB floor, debug restriction or guest SVN minimum is evaluated; SNP authenticity and VCEK/report TCB consistency do not establish such a policy".into(),
            "Certificate validity time and revocation are not checked".into(),
            "Certificates without MAA evidence extensions are excluded from the report-evidence scope, not treated as attested signing keys".into(),
            "The certificate response, evidence-container association and service/build metadata have unsigned scope; reports can be copied between containers, and no binding to a live MAA service is established".into(),
        ],
    }
}

/// Compare authenticated HOST_DATA to SHA256 of the exact decoded
/// security-policy-base64 bytes from a statement the caller already verified.
pub fn appraise(certs_json: &[u8], policy_digest: &[u8; 32]) -> Appraisal {
    #[cfg(feature = "azure-attestation")]
    {
        evidence::appraise(certs_json, policy_digest)
    }
    #[cfg(not(feature = "azure-attestation"))]
    {
        let _ = (certs_json, policy_digest);
        unevaluated("this build does not enable the azure-attestation feature")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unevaluated_never_reports_success_and_explains_limitations() {
        let appraisal = unevaluated("evidence unavailable");
        assert_eq!(appraisal.checks.len(), CHECK_NAMES.len());
        assert!(appraisal
            .checks
            .iter()
            .all(|c| c.state == CheckState::CannotEvaluate));
        assert!(appraisal.notes.iter().any(|n| n.contains("endpoint")));
        assert!(appraisal.notes.iter().any(|n| n.contains("freshness")));
        assert!(appraisal.notes.iter().any(|n| n.contains("unsigned")));
    }

    #[cfg(not(feature = "azure-attestation"))]
    #[test]
    fn feature_off_never_passes() {
        let appraisal = appraise(b"{}", &[0; 32]);
        assert!(appraisal
            .checks
            .iter()
            .all(|c| c.state == CheckState::CannotEvaluate));
    }
}
