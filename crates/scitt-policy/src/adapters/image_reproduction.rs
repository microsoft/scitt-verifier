//! The policy section that configures the image-reproduction adapter.
//!
//! Parsed and validated in every build, like the ledger section, so a policy
//! is understood identically everywhere. Which profiles exist is decided by
//! the adapter, not here: a policy naming one this build does not implement
//! parses, and the run reports it cannot evaluate rather than reporting a
//! malformed policy for what is really a missing capability.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ImageReproductionPolicy {
    /// Which rules read the statement's claim and the reproduction record.
    ///
    /// Required rather than defaulted. A default would make a policy written
    /// today silently change meaning when a later build adds a profile.
    pub profile: String,
    /// The one source repository the statement may name, compared exactly.
    ///
    /// Required because a signature authenticates who published the build,
    /// not what they built it from. Without it a publisher's reproducible
    /// build of a fork would satisfy a policy written for the upstream.
    pub source_repository: String,
    /// The one component the statement may be about.
    ///
    /// Required because one signing identity issues statements for every
    /// component and variant it builds. Without it a debug image's statement
    /// would satisfy a policy written for the production image.
    pub component: Component,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Component {
    /// The statement's `component.app`, compared exactly.
    pub app: String,
    /// The statement's `component.variant`, compared exactly.
    pub variant: String,
}

impl ImageReproductionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.profile.trim().is_empty() {
            return Err("profile is empty; name the reproduction profile to apply".into());
        }
        if self.source_repository.trim().is_empty() {
            return Err(
                "sourceRepository is empty; without it any repository the publisher builds \
                 would satisfy this policy"
                    .into(),
            );
        }
        if self.source_repository.trim() != self.source_repository {
            return Err(
                "sourceRepository has surrounding whitespace; it is compared exactly, so it \
                 would never match"
                    .into(),
            );
        }
        for (name, value) in [
            ("component.app", &self.component.app),
            ("component.variant", &self.component.variant),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "{name} is empty; without it a statement for any component would satisfy \
                     this policy"
                ));
            }
            if value.trim() != value {
                return Err(format!(
                    "{name} has surrounding whitespace; it is compared exactly, so it would \
                     never match"
                ));
            }
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
                    "adapters":{{"image-reproduction":{section}}}}}"#
            )
            .as_bytes(),
        )
    }

    #[test]
    fn a_complete_section_parses() {
        let p = policy(
            r#"{"profile":"p/v1","sourceRepository":"https://example.invalid/r",
                "component":{"app":"a","variant":"v"}}"#,
        )
        .unwrap();
        let section = p.adapters.image_reproduction.unwrap();
        assert_eq!(section.profile, "p/v1");
        assert_eq!(section.source_repository, "https://example.invalid/r");
        assert_eq!(section.component.app, "a");
        assert_eq!(section.component.variant, "v");
    }

    #[test]
    fn every_field_is_required_and_none_may_be_empty() {
        const C: &str = r#""component":{"app":"a","variant":"v"}"#;
        for section in [
            format!(r#"{{"profile":"p/v1",{C}}}"#),
            format!(r#"{{"sourceRepository":"https://example.invalid/r",{C}}}"#),
            r#"{"profile":"p/v1","sourceRepository":"https://example.invalid/r"}"#.to_string(),
            format!(r#"{{"profile":"","sourceRepository":"https://example.invalid/r",{C}}}"#),
            format!(r#"{{"profile":"p/v1","sourceRepository":" ",{C}}}"#),
            format!(r#"{{"profile":"p/v1","sourceRepository":"https://example.invalid/r ",{C}}}"#),
            r#"{"profile":"p/v1","sourceRepository":"r","component":{"app":"a"}}"#.to_string(),
            r#"{"profile":"p/v1","sourceRepository":"r","component":{"app":"","variant":"v"}}"#
                .to_string(),
            r#"{"profile":"p/v1","sourceRepository":"r","component":{"app":"a","variant":"v "}}"#
                .to_string(),
            r#"{"profile":"p/v1","sourceRepository":"r","component":{"app":"a","variant":"v","x":1}}"#
                .to_string(),
        ] {
            assert!(policy(&section).is_err(), "{section} was accepted");
        }
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let err = policy(
            r#"{"profile":"p/v1","sourceRepository":"https://example.invalid/r",
                "component":{"app":"a","variant":"v"},"requireIndependentRebuild":true}"#,
        )
        .unwrap_err();
        assert!(err.contains("requireIndependentRebuild"), "{err}");
    }

    #[test]
    fn a_policy_with_only_this_section_is_not_empty() {
        let adapters = crate::Adapters {
            acl: None,
            image_reproduction: Some(super::ImageReproductionPolicy {
                profile: "p/v1".into(),
                source_repository: "r".into(),
                component: super::Component {
                    app: "a".into(),
                    variant: "v".into(),
                },
            }),
        };
        assert!(!adapters.is_empty());
    }
}
