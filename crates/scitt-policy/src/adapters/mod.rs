//! Optional relying-party requirements that need adapter-specific evidence.

pub mod acl;
pub mod hbom;

use crate::{result, AssertionResult, Outcome};
use acl::AzureConfidentialLedgerPolicy;
use hbom::HbomPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Adapters {
    #[serde(rename = "azure-confidential-ledger")]
    pub acl: Option<AzureConfidentialLedgerPolicy>,
    #[serde(rename = "certificate-hbom", skip_serializing_if = "Option::is_none")]
    pub hbom: Option<HbomPolicy>,
}

impl Adapters {
    pub fn is_empty(&self) -> bool {
        self.acl.is_none() && self.hbom.is_none()
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if let Some(policy) = &self.acl {
            policy
                .validate()
                .map_err(|e| format!("adapters.azure-confidential-ledger: {e}"))?;
        }
        if let Some(policy) = &self.hbom {
            policy
                .validate()
                .map_err(|e| format!("adapters.certificate-hbom: {e}"))?;
        }
        Ok(())
    }

    pub(crate) fn unavailable_results(&self) -> Vec<AssertionResult> {
        let mut results = Vec::new();
        if self.acl.is_some() {
            results.push(result(
                "adapters.azure-confidential-ledger",
                Outcome::CannotEvaluate,
                "MST ledger appraisal requires adapter evidence unavailable through this API",
            ));
        }
        if self.hbom.is_some() {
            results.push(result(
                "adapters.certificate-hbom",
                Outcome::CannotEvaluate,
                "certificate-HBOM binding requires independently supplied certificate evidence",
            ));
        }
        results
    }
}
