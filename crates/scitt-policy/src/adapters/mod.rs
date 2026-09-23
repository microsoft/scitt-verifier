//! Optional relying-party requirements that need adapter-specific evidence.

pub mod acl;

use crate::{result, AssertionResult, Outcome};
use acl::AzureConfidentialLedgerPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Adapters {
    #[serde(rename = "azure-confidential-ledger")]
    pub acl: Option<AzureConfidentialLedgerPolicy>,
}

impl Adapters {
    pub fn is_empty(&self) -> bool {
        self.acl.is_none()
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if let Some(policy) = &self.acl {
            policy
                .validate()
                .map_err(|e| format!("adapters.azure-confidential-ledger: {e}"))?;
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
        results
    }
}
