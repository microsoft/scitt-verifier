//! Optional domain workflows. Statement verification remains in the CLI/core.

mod acl;
#[cfg(feature = "adapter-azure-confidential-ledger")]
mod live;
#[cfg(feature = "adapter-azure-confidential-ledger")]
mod load;

use scitt_policy::Policy;
use scitt_receipt::Sign1;
use std::path::Path;

use crate::cli::Adapter;
use crate::outcome::{AdapterCheck, AdapterFinding, CheckState};

#[cfg_attr(not(feature = "adapter-azure-confidential-ledger"), allow(dead_code))]
pub enum EvidenceSource<'a> {
    Saved(&'a Path),
    Live { save_to: Option<&'a Path> },
}

/// Findings and their explicit acceptance contract, independent of domain.
pub struct AdapterAssessment {
    pub checks: Vec<AdapterCheck>,
    pub findings: Vec<AdapterFinding>,
    pub required_checks: Vec<String>,
    pub scope: String,
    pub notes: Vec<String>,
}

impl AdapterAssessment {
    pub fn scoped_pass(&self) -> bool {
        crate::outcome::required_checks_pass(&self.checks, &self.required_checks)
    }

    pub fn blocking(&self) -> Vec<String> {
        if self.required_checks.is_empty() {
            return vec!["adapter declared no required checks".into()];
        }
        self.required_checks
            .iter()
            .filter_map(|name| {
                let mut matches = self.checks.iter().filter(|check| check.name == *name);
                match (matches.next(), matches.next()) {
                    (Some(check), None) if check.state == CheckState::Pass => None,
                    (Some(check), None) => Some(check.label.clone()),
                    _ => Some(format!("{name} (missing or duplicate check)")),
                }
            })
            .collect()
    }
}

/// A policy requirement cannot disappear just because its CLI selector was omitted.
pub fn validate_request(adapter: Option<Adapter>, policy: &Policy) -> Result<(), String> {
    match (adapter, policy.adapters.acl.as_ref()) {
        (None, None) | (Some(Adapter::AzureConfidentialLedger), Some(_)) => Ok(()),
        (None, Some(_)) => Err(
            "policy requires adapters.azure-confidential-ledger; select --adapter azure-confidential-ledger and an \
             evidence binding mode so its requirements are evaluated"
                .into(),
        ),
        (Some(Adapter::AzureConfidentialLedger), None) => {
            Err("--adapter azure-confidential-ledger requires policy.adapters.azure-confidential-ledger".into())
        }
    }
}

pub fn not_attempted(adapter: Adapter, reason: impl Into<String>) -> AdapterAssessment {
    match adapter {
        Adapter::AzureConfidentialLedger => acl::not_attempted(reason),
    }
}

pub fn check_event(
    adapter: Adapter,
    check: &AdapterCheck,
    detail: String,
    findings: &[AdapterFinding],
) -> crate::progress::Event {
    match adapter {
        Adapter::AzureConfidentialLedger => acl::check_event(check, detail, findings),
    }
}

pub fn compact_limitation(
    adapter: Adapter,
    check: &AdapterCheck,
    findings: &[AdapterFinding],
) -> Option<&'static str> {
    match adapter {
        Adapter::AzureConfidentialLedger => acl::compact_limitation(check, findings),
    }
}

pub fn appraise(
    adapter: Adapter,
    source: EvidenceSource<'_>,
    statement: &Sign1,
    policy: &Policy,
    progress: &mut dyn crate::progress::Sink,
) -> AdapterAssessment {
    match adapter {
        Adapter::AzureConfidentialLedger => match &policy.adapters.acl {
            Some(config) => acl::appraise_evidence(source, statement, config, progress),
            None => not_attempted(
                adapter,
                "policy.adapters.azure-confidential-ledger is missing",
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assessment(state: CheckState) -> AdapterAssessment {
        AdapterAssessment {
            checks: vec![AdapterCheck {
                name: "binding".into(),
                label: "Binding".into(),
                state,
                detail: "detail".into(),
            }],
            findings: Vec::new(),
            required_checks: vec!["binding".into()],
            scope: "test".into(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn all_required_checks_must_run_and_pass() {
        assert!(assessment(CheckState::Pass).scoped_pass());
        for state in [
            CheckState::Fail,
            CheckState::CannotEvaluate,
            CheckState::NotChecked,
        ] {
            assert!(!assessment(state).scoped_pass());
        }
        let mut result = assessment(CheckState::Pass);
        result.required_checks.push("missing".into());
        assert!(!result.scoped_pass());
    }

    #[test]
    fn empty_contract_and_duplicate_results_cannot_pass() {
        let mut result = assessment(CheckState::Pass);
        result.checks.push(result.checks[0].clone());
        assert!(!result.scoped_pass());
        result.required_checks.clear();
        assert!(!result.scoped_pass());
    }

    #[test]
    fn excluded_checks_do_not_replace_required_checks() {
        let mut result = assessment(CheckState::Pass);
        result.checks.push(AdapterCheck {
            name: "excluded".into(),
            label: "Excluded".into(),
            state: CheckState::CannotEvaluate,
            detail: "outside this claim".into(),
        });
        assert!(result.scoped_pass());
        result.checks[0].state = CheckState::CannotEvaluate;
        assert!(!result.scoped_pass());
    }
}
