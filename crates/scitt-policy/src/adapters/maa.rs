//! Requirements for comparing Azure Attestation reports with an accepted statement.

use crate::PathSegment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaaPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<MaaTarget>,
    pub binding: MaaBinding,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaaTarget {
    pub host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Base64,
    Base64url,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaaBinding {
    pub path: Vec<PathSegment>,
    pub encoding: Encoding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_decoded_bytes: Option<usize>,
}

impl MaaPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self
            .target
            .as_ref()
            .is_some_and(|target| target.host.trim().is_empty())
        {
            return Err("target.host is empty".into());
        }
        if self.binding.path.is_empty()
            || self
                .binding
                .path
                .iter()
                .any(|segment| matches!(segment, PathSegment::Text(key) if key.trim().is_empty()))
        {
            return Err("binding.path must be a nonempty claim path".into());
        }
        if self.binding.max_decoded_bytes == Some(0) {
            return Err("binding.maxDecodedBytes must be greater than zero".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Outcome, Policy};
    use serde_json::{json, Value};

    pub(crate) fn document() -> Value {
        json!({
            "policyId": "example", "policyVersion": "1",
            "assertions": {"receiptCount": 1},
            "adapters": {"azure-attestation": {
                "target": {"host": "attestation.example"},
                "binding": {
                    "path": ["security-policy-base64"], "encoding": "base64"
                }
            }}
        })
    }

    #[test]
    fn committed_azure_attestation_policy_parses_with_the_minimal_contract() {
        let policy = Policy::from_json(include_bytes!(
            "../../../../corpus/policies/azure-attestation.json"
        ))
        .expect("committed Azure Attestation example policy");
        let adapter = policy.adapters.maa.expect("azure-attestation requirements");
        assert_eq!(
            adapter.target.unwrap().host,
            "example.region.attest.azure.net"
        );
        assert_eq!(adapter.binding.encoding, super::Encoding::Base64);
        assert_eq!(
            serde_json::to_value(&adapter.binding.path).unwrap(),
            json!(["security-policy-base64"])
        );
        assert_eq!(adapter.binding.max_decoded_bytes, Some(1_048_576));
    }

    #[test]
    fn complete_policy_round_trips_and_is_not_empty() {
        let mut value = document();
        let policy = Policy::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!policy.adapters.is_empty());
        assert_eq!(
            serde_json::to_value(&policy).unwrap()["adapters"]["azure-attestation"],
            value["adapters"]["azure-attestation"]
        );
        value["assertions"] = json!({});
        assert!(Policy::from_json(&serde_json::to_vec(&value).unwrap()).is_ok());
    }

    #[test]
    fn standalone_evaluation_never_skips_adapter_requirements() {
        let policy = Policy::from_json(&serde_json::to_vec(&document()).unwrap()).unwrap();
        let facts = scitt_receipt::StatementFacts {
            receipts_present: 1,
            ..Default::default()
        };
        let decision = policy.evaluate(&facts, 0);
        assert!(decision.results.iter().any(
            |r| r.name == "adapters.azure-attestation" && r.outcome == Outcome::CannotEvaluate
        ));
        assert!(!decision.satisfied());
    }

    #[test]
    fn target_can_be_supplied_by_the_live_cli_without_dropping_binding_requirements() {
        let mut value = document();
        value["adapters"]["azure-attestation"]
            .as_object_mut()
            .unwrap()
            .remove("target");
        let policy = Policy::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(policy.adapters.maa.as_ref().unwrap().target.is_none());
        assert!(!policy.adapters.is_empty());
        value["adapters"]["azure-attestation"]
            .as_object_mut()
            .unwrap()
            .remove("binding");
        assert!(Policy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn absent_empty_unknown_and_removed_requirements_are_refused() {
        for (path, replacement) in [
            ("/target/host", json!("")),
            ("/binding/path", json!([])),
            ("/binding/maxDecodedBytes", json!(0)),
        ] {
            let mut value = document();
            let adapter = &mut value["adapters"]["azure-attestation"];
            if path == "/binding/maxDecodedBytes" {
                adapter["binding"]["maxDecodedBytes"] = replacement;
            } else {
                *adapter.pointer_mut(path).unwrap() = replacement;
            }
            assert!(
                Policy::from_json(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{path}"
            );
        }
        for path in ["target", "binding"] {
            let mut value = document();
            value["adapters"]["azure-attestation"][path]["unknown"] = json!(true);
            assert!(Policy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = document();
        value["adapters"]["azure-attestation"]["binding"]
            .as_object_mut()
            .unwrap()
            .remove("path");
        assert!(Policy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
        for (field, removed) in [
            ("trust", json!({"uvmIssuer": "example", "uvmEku": "1.2.3"})),
            ("buildVersionPath", json!(["build", "number"])),
            ("uvmFeed", json!("example")),
            ("minUvmSvn", json!(1)),
            (
                "minimumTcb",
                json!([{"generation": "genoa", "reportedTcb": "0x1"}]),
            ),
        ] {
            let mut value = document();
            if field == "trust" {
                value["adapters"]["azure-attestation"][field] = removed;
            } else {
                value["adapters"]["azure-attestation"]["binding"][field] = removed;
            }
            let error = Policy::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
            assert!(error.contains(field), "{error}");
        }
    }
}
