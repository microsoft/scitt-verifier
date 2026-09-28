//! Optional domain workflows. Statement verification remains in the CLI/core.

mod acl;
#[cfg(feature = "adapter-azure-confidential-ledger")]
mod live;
#[cfg(feature = "adapter-azure-confidential-ledger")]
mod load;
mod reproduction;

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

/// The adapters a policy configures, in a fixed order.
fn configured(policy: &Policy) -> Vec<Adapter> {
    let mut out = Vec::new();
    if policy.adapters.acl.is_some() {
        out.push(Adapter::AzureConfidentialLedger);
    }
    if policy.adapters.image_reproduction.is_some() {
        out.push(Adapter::ImageReproduction);
    }
    out
}

/// A policy requirement cannot disappear just because its CLI selector was omitted.
pub fn validate_request(adapter: Option<Adapter>, policy: &Policy) -> Result<(), String> {
    let configured = configured(policy);
    match adapter {
        None => match configured.first() {
            None => Ok(()),
            Some(required) => Err(format!(
                "policy requires adapters.{0}; select --adapter {0} and an evidence binding \
                 mode so its requirements are evaluated",
                required.as_str()
            )),
        },
        Some(selected) if !configured.contains(&selected) => Err(format!(
            "--adapter {0} requires policy.adapters.{0}",
            selected.as_str()
        )),
        // A run appraises one adapter. Accepting a policy that configures two
        // would evaluate one and leave the other's requirements unexamined
        // while the run reported the policy satisfied.
        Some(_) if configured.len() > 1 => Err(format!(
            "policy configures {} adapters ({}), but a run appraises one; split it into one \
             policy per adapter so no requirement goes unevaluated",
            configured.len(),
            configured
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Some(_) => Ok(()),
    }
}

pub fn not_attempted(adapter: Adapter, reason: impl Into<String>) -> AdapterAssessment {
    match adapter {
        Adapter::AzureConfidentialLedger => acl::not_attempted(reason),
        Adapter::ImageReproduction => reproduction::not_attempted(reason),
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
        Adapter::ImageReproduction => reproduction::check_event(check, detail),
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
        Adapter::ImageReproduction => match &policy.adapters.image_reproduction {
            Some(config) => reproduction::appraise_evidence(source, statement, config, progress),
            None => not_attempted(adapter, "policy.adapters.image-reproduction is missing"),
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
