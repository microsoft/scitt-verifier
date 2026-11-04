//! The policy section that configures the AMD SEV-SNP device adapter.
//!
//! Parsed and validated in every build, like the other adapter sections, so a
//! policy is understood identically everywhere. Which profiles exist is
//! decided by the adapter: a policy naming one this build does not implement
//! parses, and the run reports it cannot evaluate.

use super::acl::TcbFloorEntry;
use serde::{Deserialize, Serialize};

/// Requirements for binding a statement's device claim to a live SNP report.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AmdSnpDevicePolicy {
    /// Which rules read the device claim from the statement's payload.
    ///
    /// Required rather than defaulted, so a policy written today does not
    /// change meaning when a later build adds a profile.
    pub profile: String,
    /// The hardware category whose serial number names the processor.
    ///
    /// Required because a hardware BOM can describe several parts, each with
    /// a serial. Naming the category picks the one the processor's identity
    /// is compared with, and a statement with zero or several such parts
    /// fails rather than having one chosen for it.
    pub category: String,
    /// Minimum reported TCB, per processor generation.
    ///
    /// Required and non-empty. A report whose generation has no floor here
    /// cannot be evaluated, so an empty list would never pass and one naming
    /// only other generations would never pass on this hardware.
    pub minimum_tcb: Vec<TcbFloorEntry>,
}

const GENERATIONS: [&str; 3] = ["milan", "genoa", "turin"];

impl AmdSnpDevicePolicy {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [("profile", &self.profile), ("category", &self.category)] {
            if value.trim().is_empty() {
                return Err(format!("{name} is empty"));
            }
            if value.trim() != value {
                return Err(format!(
                    "{name} has surrounding whitespace; it is compared exactly, so it would \
                     never match"
                ));
            }
        }
        if self.minimum_tcb.is_empty() {
            return Err(
                "minimumTcb is empty; name a floor for each processor generation the \
                 device may be"
                    .into(),
            );
        }
        let mut seen = Vec::new();
        for (index, entry) in self.minimum_tcb.iter().enumerate() {
            let generation = entry.generation.to_ascii_lowercase();
            if !GENERATIONS.contains(&generation.as_str()) {
                return Err(format!(
                    "minimumTcb[{index}].generation {:?} is not one of milan, genoa, turin",
                    entry.generation
                ));
            }
            if seen.contains(&generation) {
                return Err(format!(
                    "minimumTcb[{index}] repeats generation {:?}; two floors for one \
                     generation leave which applies ambiguous",
                    entry.generation
                ));
            }
            seen.push(generation);
            entry
                .value()
                .map_err(|e| format!("minimumTcb[{index}]: {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Policy;

    fn policy(section: &str) -> Result<Policy, String> {
        Policy::from_json(
            format!(
                r#"{{"policyId":"t","policyVersion":"1",
                    "assertions":{{"issuer":["example.invalid"]}},
                    "adapters":{{"amd-snp-device":{section}}}}}"#
            )
            .as_bytes(),
        )
    }

    const FLOOR: &str = r#"[{"generation":"turin","reportedTcb":"0x5100000004010101"}]"#;

    #[test]
    fn a_complete_section_parses() {
        let p = policy(&format!(
            r#"{{"profile":"spdx3-hbom","category":"packaged soc","minimumTcb":{FLOOR}}}"#
        ))
        .unwrap();
        let section = p.adapters.amd_snp_device.unwrap();
        assert_eq!(section.profile, "spdx3-hbom");
        assert_eq!(section.category, "packaged soc");
        assert_eq!(
            section.minimum_tcb[0].value().unwrap(),
            0x5100_0000_0401_0101
        );
    }

    #[test]
    fn every_field_is_required_and_none_may_be_empty_or_ambiguous() {
        for section in [
            format!(r#"{{"category":"c","minimumTcb":{FLOOR}}}"#),
            format!(r#"{{"profile":"p","minimumTcb":{FLOOR}}}"#),
            r#"{"profile":"p","category":"c"}"#.to_string(),
            format!(r#"{{"profile":"","category":"c","minimumTcb":{FLOOR}}}"#),
            format!(r#"{{"profile":"p","category":" c","minimumTcb":{FLOOR}}}"#),
            r#"{"profile":"p","category":"c","minimumTcb":[]}"#.to_string(),
            r#"{"profile":"p","category":"c","minimumTcb":[
                {"generation":"bergamo","reportedTcb":"0x1"}]}"#
                .to_string(),
            r#"{"profile":"p","category":"c","minimumTcb":[
                {"generation":"turin","reportedTcb":"0x1"},
                {"generation":"Turin","reportedTcb":"0x2"}]}"#
                .to_string(),
            r#"{"profile":"p","category":"c","minimumTcb":[
                {"generation":"turin","reportedTcb":"5100000004010101"}]}"#
                .to_string(),
        ] {
            assert!(policy(&section).is_err(), "{section} was accepted");
        }
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let err = policy(&format!(
            r#"{{"profile":"p","category":"c","minimumTcb":{FLOOR},"checkUvm":true}}"#
        ))
        .unwrap_err();
        assert!(err.contains("checkUvm"), "{err}");
    }

    #[test]
    fn a_policy_with_only_this_section_is_not_empty() {
        let p = policy(&format!(
            r#"{{"profile":"p","category":"c","minimumTcb":{FLOOR}}}"#
        ))
        .unwrap();
        assert!(!p.adapters.is_empty());
    }
}
