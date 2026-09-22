//! Optional relying-party requirements that need adapter-specific evidence.

pub mod mst_ledger;

use crate::{result, AssertionResult, Outcome};
use mst_ledger::MstLedgerPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Adapters {
    #[serde(rename = "mst-ledger")]
    pub mst_ledger: Option<MstLedgerPolicy>,
}

impl Adapters {
    pub fn is_empty(&self) -> bool {
        self.mst_ledger.is_none()
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if let Some(policy) = &self.mst_ledger {
            policy
                .validate()
                .map_err(|e| format!("adapters.mst-ledger: {e}"))?;
        }
        Ok(())
    }

    pub(crate) fn unavailable_results(&self) -> Vec<AssertionResult> {
        let mut results = Vec::new();
        if self.mst_ledger.is_some() {
            results.push(result(
                "adapters.mst-ledger",
                Outcome::CannotEvaluate,
                "MST ledger appraisal requires adapter evidence unavailable through this API",
            ));
        }
        results
    }
}
