//! Optional relying-party requirements that need adapter-specific evidence.

pub mod acl;
pub mod amd_snp_device;
pub mod image_reproduction;
pub mod maa;

use crate::{result, AssertionResult, Outcome};
use acl::AzureConfidentialLedgerPolicy;
use amd_snp_device::AmdSnpDevicePolicy;
use image_reproduction::ImageReproductionPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Adapters {
    #[serde(
        rename = "azure-attestation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub maa: Option<maa::MaaPolicy>,
    #[serde(rename = "azure-confidential-ledger")]
    pub acl: Option<AzureConfidentialLedgerPolicy>,
    #[serde(
        rename = "image-reproduction",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub image_reproduction: Option<ImageReproductionPolicy>,
    #[serde(
        rename = "amd-snp-device",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub amd_snp_device: Option<AmdSnpDevicePolicy>,
}

impl Adapters {
    pub fn is_empty(&self) -> bool {
        self.acl.is_none()
            && self.image_reproduction.is_none()
            && self.maa.is_none()
            && self.amd_snp_device.is_none()
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if let Some(policy) = &self.maa {
            policy
                .validate()
                .map_err(|e| format!("adapters.azure-attestation: {e}"))?;
        }
        if let Some(policy) = &self.acl {
            policy
                .validate()
                .map_err(|e| format!("adapters.azure-confidential-ledger: {e}"))?;
        }
        if let Some(policy) = &self.image_reproduction {
            policy
                .validate()
                .map_err(|e| format!("adapters.image-reproduction: {e}"))?;
        }
        if let Some(policy) = &self.amd_snp_device {
            policy
                .validate()
                .map_err(|e| format!("adapters.amd-snp-device: {e}"))?;
        }
        Ok(())
    }

    pub(crate) fn unavailable_results(&self) -> Vec<AssertionResult> {
        let mut results = Vec::new();
        if self.maa.is_some() {
            results.push(result(
                "adapters.azure-attestation",
                Outcome::CannotEvaluate,
                "Azure Attestation appraisal requires adapter evidence unavailable through this API",
            ));
        }
        if self.acl.is_some() {
            results.push(result(
                "adapters.azure-confidential-ledger",
                Outcome::CannotEvaluate,
                "MST ledger appraisal requires adapter evidence unavailable through this API",
            ));
        }
        if self.image_reproduction.is_some() {
            results.push(result(
                "adapters.image-reproduction",
                Outcome::CannotEvaluate,
                "image reproduction appraisal requires rebuild evidence unavailable through this API",
            ));
        }
        if self.amd_snp_device.is_some() {
            results.push(result(
                "adapters.amd-snp-device",
                Outcome::CannotEvaluate,
                "SNP device appraisal requires attestation evidence unavailable through this API",
            ));
        }
        results
    }
}
