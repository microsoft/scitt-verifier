//! The policy section that configures appraisal of a ledger's enforced policy.
//!
//! Three things about the shape here are deliberate.
//!
//! **The target ledger lives in the policy, not on the command line.** The
//! policy is the artifact that gets reviewed and committed; a flag can be
//! edited in a pipeline definition to point at an attacker-controlled ledger,
//! which would happily attest to its own policy. A command-line resource may
//! only ever *agree* with what is written here.
//!
//! **Every field here changes what is enforced.** Nothing is accepted merely
//! because a design document mentioned it. A policy field that is parsed and
//! then ignored is worse than an absent one, because a reviewer reads it as a
//! control that is in force. Two fields were left out for exactly this reason:
//! an AMD root pin, because the attestation library pins AMD's roots itself
//! and will not accept an override, so naming one would imply a choice the
//! operator does not have; and a debug-disabled requirement, because the same
//! library always enforces it and a policy saying `false` could not be obeyed.
//!
//! **This module parses and validates; it never appraises.** It is compiled
//! into every build, including those without an adapter, so that a policy is
//! understood identically everywhere. A build that cannot act on this section
//! says so at the point of use — it does not fail to parse the document, which
//! would report a malformed policy for what is really a missing feature.

use crate::PathSegment;
use serde::{Deserialize, Serialize};

/// The ledger whose enforced policy is being appraised.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LedgerTarget {
    /// The ledger's hostname.
    ///
    /// The service whose enforced policy is being appraised — normally *not*
    /// the transparency service that issued the receipt, which notarises
    /// builds for many deployments.
    ///
    /// Enforced, not merely recorded: an evidence bundle collected from any
    /// other host is refused. That comparison is against the collector's own
    /// unsigned manifest, so it catches the wrong bundle rather than a forged
    /// one; pinning the bundle's service certificate to the one published for
    /// this host would be the adversarial form, and needs a network request
    /// this build does not make.
    pub host: String,
}

impl LedgerTarget {
    pub fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err("ledger.host is empty; the policy must name the ledger it is about".into());
        }
        Ok(())
    }
}

/// Trust inputs the consumer supplies, independent of the evidence.
///
/// Separate from the evidence bundle on purpose: material that travelled with
/// the thing it is meant to authenticate proves only internal consistency.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustInputs {
    /// The `did:x509` the UVM endorsement's certificate chain must anchor to.
    ///
    /// The bare DID, with no `::` policy components. Components are rejected
    /// rather than ignored: the attestation library's own parser keeps only
    /// the text before the first `::` and silently discards the rest, so a
    /// policy that wrote its EKU there would read as though it constrained the
    /// signer while constraining nothing. The EKU is a separate field below so
    /// that it cannot be lost that way.
    pub uvm_issuer: String,
    /// The extended key usage the UVM endorsement's signer must carry.
    ///
    /// Required, not optional. A root pin alone does not distinguish signing
    /// roles, and on the ledger this was built against the UVM endorsement and
    /// the statement share a root — so without an EKU a statement-signing
    /// certificate would satisfy the UVM requirement.
    pub uvm_eku: String,
}

impl TrustInputs {
    pub fn validate(&self) -> Result<(), String> {
        if !self.uvm_issuer.starts_with("did:x509:") {
            return Err(format!(
                "trust.uvmIssuer must be a did:x509, got {:?}",
                self.uvm_issuer
            ));
        }
        if self.uvm_issuer.contains("::") {
            return Err(
                "trust.uvmIssuer must be the bare did:x509 with no '::' policy components; \
                 put the EKU in trust.uvmEku, where it is enforced. Components written here \
                 would be discarded, leaving the signer unconstrained."
                    .into(),
            );
        }
        if self.uvm_eku.trim().is_empty() {
            return Err(
                "trust.uvmEku is empty; without it the UVM signer is unconstrained \
                        beyond its root"
                    .into(),
            );
        }
        if !self.uvm_eku.chars().all(|c| c.is_ascii_digit() || c == '.')
            || !self.uvm_eku.starts_with(|c: char| c.is_ascii_digit())
        {
            return Err(format!(
                "trust.uvmEku must be a dotted OID, got {:?}",
                self.uvm_eku
            ));
        }
        Ok(())
    }
}

/// How the claim's text is encoded.
///
/// Named by the policy rather than guessed from the value: a per-value guess
/// would decode two different claims two different ways, and the digest of the
/// result is what a deployment gate compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Base64,
    Base64url,
}

/// Which nodes the coverage requirement is over.
///
/// One variant today, spelled out rather than implied, because the alternative
/// this leaves room for — a quorum, or a named set — changes what a pass
/// means, and a policy written before that existed must not silently acquire
/// the new meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeCoverage {
    /// Every node the evidence enumerates must produce usable evidence.
    ///
    /// Note what this cannot see: a node omitted from the evidence entirely is
    /// not in the enumeration, so it cannot fail this. `expectNodeCount` is
    /// the only field that turns an omission into a failure.
    AllEnumerated,
}

/// A minimum reported TCB for one CPU generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TcbFloorEntry {
    /// CPU generation, e.g. `genoa`.
    pub generation: String,
    /// The raw 64-bit reported-TCB floor, hex, `0x`-prefixed.
    ///
    /// Written as hex text rather than a JSON number because JSON numbers are
    /// doubles in most tooling, and this value does not survive that intact.
    pub reported_tcb: String,
}

impl TcbFloorEntry {
    /// The floor as the raw 64-bit value the report carries.
    pub fn value(&self) -> Result<u64, String> {
        let text = self
            .reported_tcb
            .strip_prefix("0x")
            .or_else(|| self.reported_tcb.strip_prefix("0X"))
            .ok_or_else(|| {
                format!(
                    "reportedTcb must be 0x-prefixed hex, got {:?}",
                    self.reported_tcb
                )
            })?;
        u64::from_str_radix(text, 16)
            .map_err(|e| format!("reportedTcb {:?} is not 64-bit hex: {e}", self.reported_tcb))
    }
}

/// Bind the statement's embedded execution policy to what nodes enforce.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BindLedgerPolicy {
    /// Where the encoded execution policy lives in the payload.
    ///
    /// The same `PathSegment` array `payloadJson` uses, so a path printed by
    /// `inspect --decode` pastes straight in.
    pub path: Vec<PathSegment>,
    pub encoding: Encoding,
    /// Refuse a decoded policy larger than this.
    ///
    /// A sanity bound on the claim, not a security boundary: the statement is
    /// already in memory by the time this is checked. It catches a path that
    /// resolved to something enormous and unintended before its digest is
    /// reported as though it meant something.
    #[serde(default)]
    pub max_decoded_bytes: Option<usize>,
    pub node_coverage: NodeCoverage,
    /// How many nodes the evidence must enumerate.
    ///
    /// The only field that makes an *omitted* node a failure. Coverage alone
    /// is over the nodes the evidence names, so evidence that quietly leaves
    /// one out is indistinguishable from a smaller ledger.
    #[serde(default)]
    pub expect_node_count: Option<usize>,
    /// The UVM feed the endorsement must name, e.g. `ContainerPlat-AMD-UVM`.
    pub uvm_feed: String,
    /// Minimum acceptable UVM guest SVN.
    ///
    /// Deliberately not `minSvn`. That field reads the *statement's* declared
    /// security version for artifact anti-rollback; this is a property of the
    /// platform the ledger runs on. Sharing one field would let an artifact
    /// rollback floor silently gate platform firmware.
    pub min_uvm_svn: u64,
    /// Minimum reported TCB, per CPU generation.
    ///
    /// Required and non-empty. The attestation library skips the TCB check
    /// entirely when the floor is empty, and only compares entries whose
    /// generation matches the node's — so both an empty list and a list naming
    /// only other generations accept any firmware at all.
    pub minimum_tcb: Vec<TcbFloorEntry>,
    /// Optionally pin the execution policy to one exact build.
    ///
    /// Not needed for the comparison — the reference digest comes from the
    /// statement. It defends against a different question: a correctly signed,
    /// correctly witnessed statement for the *wrong* build.
    #[serde(default)]
    pub expect_policy_sha256: Option<String>,
}

impl BindLedgerPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.path.is_empty() {
            return Err(
                "bindLedgerPolicy.path is empty; it would address the whole payload \
                        rather than the policy claim"
                    .into(),
            );
        }
        if let Some(max) = self.max_decoded_bytes {
            if max == 0 {
                return Err(
                    "bindLedgerPolicy.maxDecodedBytes is 0, which no policy can satisfy".into(),
                );
            }
        }
        if let Some(count) = self.expect_node_count {
            if count == 0 {
                return Err(
                    "bindLedgerPolicy.expectNodeCount is 0; zero nodes agreeing establishes \
                     nothing, so this would be satisfied by evidence about no ledger at all"
                        .into(),
                );
            }
        }
        if self.uvm_feed.trim().is_empty() {
            return Err("bindLedgerPolicy.uvmFeed is empty".into());
        }
        if self.minimum_tcb.is_empty() {
            return Err(
                "bindLedgerPolicy.minimumTcb is empty; an empty floor is not a floor — the \
                 attestation library skips the check entirely, accepting any reported TCB"
                    .into(),
            );
        }
        for (index, entry) in self.minimum_tcb.iter().enumerate() {
            if entry.generation.trim().is_empty() {
                return Err(format!(
                    "bindLedgerPolicy.minimumTcb[{index}].generation is empty"
                ));
            }
            entry
                .value()
                .map_err(|e| format!("bindLedgerPolicy.minimumTcb[{index}]: {e}"))?;
        }
        if let Some(pin) = &self.expect_policy_sha256 {
            if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "bindLedgerPolicy.expectPolicySha256 must be 64 hex characters, got {:?}",
                    pin
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Policy;

    fn policy_json(extra: &str) -> Vec<u8> {
        format!(
            r#"{{
              "policyId": "p", "policyVersion": "1",
              "ledger": {{ "host": "l.example" }},
              "trust": {{
                "uvmIssuer": "did:x509:0:sha256:abc",
                "uvmEku": "1.3.6.1.4.1.311.76.59.1.2"
              }},
              "assertions": {{
                "receiptCount": 1,
                "bindLedgerPolicy": {{
                  "path": ["security-policy-base64"],
                  "encoding": "base64",
                  "nodeCoverage": "all-enumerated",
                  "uvmFeed": "ContainerPlat-AMD-UVM",
                  "minUvmSvn": 104,
                  "minimumTcb": [
                    {{ "generation": "genoa", "reportedTcb": "0x541700000000000a" }}
                  ]{extra}
                }}
              }}
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_complete_section_parses_and_validates() {
        let p = Policy::from_json(&policy_json("")).expect("policy");
        let ledger = p.ledger.expect("ledger");
        assert_eq!(ledger.host, "l.example");
        let bind = p.assertions.bind_ledger_policy.expect("bind");
        assert_eq!(bind.encoding, Encoding::Base64);
        assert_eq!(bind.node_coverage, NodeCoverage::AllEnumerated);
        assert_eq!(bind.min_uvm_svn, 104);
        assert_eq!(bind.minimum_tcb[0].value().unwrap(), 0x5417_0000_0000_000a);
    }

    /// The section must parse in builds that cannot act on it.
    ///
    /// Reporting a malformed policy for a missing build feature would send an
    /// operator to edit a document that is perfectly correct. The refusal
    /// belongs at the point of use, where it can say what it actually is.
    #[test]
    fn the_section_parses_regardless_of_build_features() {
        let p = Policy::from_json(&policy_json("")).expect("policy");
        assert!(p.assertions.bind_ledger_policy.is_some());
    }

    /// An EKU written into the DID would be silently discarded downstream, so
    /// it is refused here rather than accepted and lost.
    #[test]
    fn an_eku_hidden_in_the_did_is_refused_rather_than_ignored() {
        let json = String::from_utf8(policy_json("")).unwrap().replace(
            r#""uvmIssuer": "did:x509:0:sha256:abc""#,
            r#""uvmIssuer": "did:x509:0:sha256:abc::eku:1.2.3""#,
        );
        let err = Policy::from_json(json.as_bytes()).unwrap_err();
        assert!(err.contains("uvmEku"), "{err}");
    }

    #[test]
    fn an_empty_tcb_floor_is_refused_because_it_would_be_skipped() {
        let json = String::from_utf8(policy_json("")).unwrap().replace(
            r#"[
                    { "generation": "genoa", "reportedTcb": "0x541700000000000a" }
                  ]"#,
            "[]",
        );
        // The replacement above is whitespace-sensitive; do it robustly.
        let json = if json.contains("\"minimumTcb\": []") {
            json
        } else {
            let start = json.find("\"minimumTcb\"").unwrap();
            let end = json[start..].find(']').unwrap() + start + 1;
            format!("{}\"minimumTcb\": []{}", &json[..start], &json[end..])
        };
        let err = Policy::from_json(json.as_bytes()).unwrap_err();
        assert!(err.contains("minimumTcb"), "{err}");
        assert!(err.contains("not a floor"), "{err}");
    }

    #[test]
    fn a_zero_node_expectation_is_refused() {
        let err = Policy::from_json(&policy_json(r#", "expectNodeCount": 0"#)).unwrap_err();
        assert!(err.contains("expectNodeCount"), "{err}");
    }

    #[test]
    fn a_malformed_tcb_value_is_refused_rather_than_defaulted() {
        let json = String::from_utf8(policy_json("")).unwrap().replace(
            r#""reportedTcb": "0x541700000000000a""#,
            r#""reportedTcb": "541700000000000a""#,
        );
        let err = Policy::from_json(json.as_bytes()).unwrap_err();
        assert!(err.contains("0x-prefixed"), "{err}");
    }

    #[test]
    fn a_short_policy_pin_is_refused() {
        let err =
            Policy::from_json(&policy_json(r#", "expectPolicySha256": "228bcb4e""#)).unwrap_err();
        assert!(err.contains("64 hex"), "{err}");
    }

    /// An unrecognised member must be refused, not ignored.
    ///
    /// This is the same rule the rest of the policy document follows: a
    /// forward-dated field that this build skips is a rule nobody enforced.
    #[test]
    fn an_unknown_member_is_refused() {
        let err = Policy::from_json(&policy_json(r#", "requireDebugDisabled": true"#)).unwrap_err();
        assert!(err.contains("requireDebugDisabled"), "{err}");
    }

    #[test]
    fn an_empty_path_is_refused() {
        let json = String::from_utf8(policy_json(""))
            .unwrap()
            .replace(r#""path": ["security-policy-base64"]"#, r#""path": []"#);
        let err = Policy::from_json(json.as_bytes()).unwrap_err();
        assert!(err.contains("path"), "{err}");
    }

    /// The trust section is only meaningful alongside the assertion that uses
    /// it, and vice versa. Half a configuration must not look like a whole one.
    #[test]
    fn the_assertion_and_its_trust_inputs_must_arrive_together() {
        let json = String::from_utf8(policy_json("")).unwrap().replace(
            r#""trust": {
                "uvmIssuer": "did:x509:0:sha256:abc",
                "uvmEku": "1.3.6.1.4.1.311.76.59.1.2"
              },"#,
            "",
        );
        let err = Policy::from_json(json.as_bytes()).unwrap_err();
        assert!(err.contains("trust"), "{err}");
    }
}
