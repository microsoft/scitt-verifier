//! # scitt-policy
//!
//! Relying-party policy: the part that turns *facts* into a *decision*.
//!
//! `scitt-receipt` can tell you that a statement was registered on a ledger by
//! an issuer calling itself `https://example.transparency`. It cannot tell you
//! whether that is an issuer you accept. That question has no universal answer,
//! so it is asked here, against a policy document the relying party owns.
//!
//! Three properties are load-bearing:
//!
//! * **A policy is always required.** There is no default policy, because a
//!   default would be a trust decision made by this tool on someone else's
//!   behalf.
//! * **An assertion that cannot be evaluated is not a pass.** If a policy asks
//!   for a minimum SVN and the statement carries no SVN, the answer is
//!   `CannotEvaluate` — never `Pass`.
//! * **Unknown assertions are refused.** A policy naming an assertion this
//!   build does not implement is rejected outright, so a policy written for a
//!   newer version cannot appear to pass on an older binary.
//!
//! The crate takes no clock. `now` is passed in, so evaluation is reproducible
//! and testable.

use scitt_receipt::StatementFacts;
use serde::{Deserialize, Serialize};

/// A relying-party policy document.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Policy {
    /// Stable identifier, echoed into the evidence so a decision can be traced
    /// back to the rules that produced it.
    pub policy_id: String,
    pub policy_version: String,
    #[serde(default)]
    pub description: Option<String>,
    pub assertions: Assertions,
}

/// The assertions this build understands.
///
/// `deny_unknown_fields` is the mechanism that refuses forward-dated policies.
/// Silently ignoring an unrecognised assertion would report a pass for a rule
/// that was never checked.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Assertions {
    /// Accepted transparency service issuers.
    #[serde(default)]
    pub issuer: Option<Vec<String>>,
    /// Substring that must appear in the signing certificate's subject.
    #[serde(default)]
    pub signer_subject_contains: Option<String>,
    /// Substring that must appear in the signing certificate's issuer.
    #[serde(default)]
    pub signer_issuer_contains: Option<String>,
    /// Minimum number of receipts that must fully verify.
    #[serde(default)]
    pub min_receipts: Option<usize>,
    /// Registration must be no earlier than this Unix timestamp.
    #[serde(default)]
    pub registered_after: Option<i64>,
    /// Registration must be no later than this Unix timestamp.
    #[serde(default)]
    pub registered_before: Option<i64>,
    /// Registration must be within this many days of `now`.
    #[serde(default)]
    pub max_age_days: Option<i64>,
    /// Minimum security version number, for anti-rollback.
    #[serde(default)]
    pub min_svn: Option<i64>,
    /// Require that each receipt's kid was derived from its key material.
    #[serde(default)]
    pub require_kid_bound_to_key: Option<bool>,
}

/// The outcome of one assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Pass,
    Fail,
    /// The input needed to answer this assertion was absent.
    ///
    /// Distinct from `Fail` on purpose: "the statement does not claim an SVN"
    /// and "the statement claims an SVN that is too low" call for different
    /// responses from the person reading the report.
    CannotEvaluate,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResult {
    pub name: String,
    pub outcome: Outcome,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub policy_id: String,
    pub policy_version: String,
    pub results: Vec<AssertionResult>,
}

impl PolicyDecision {
    pub fn failed(&self) -> bool {
        self.results.iter().any(|r| r.outcome == Outcome::Fail)
    }

    pub fn unevaluable(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.outcome == Outcome::CannotEvaluate)
    }

    /// True only if every assertion actually ran and passed.
    pub fn satisfied(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.outcome == Outcome::Pass)
    }
}

impl Policy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let policy: Policy = serde_json::from_slice(bytes)
            .map_err(|e| format!("policy document is not valid: {e}"))?;
        if policy.is_empty() {
            return Err(
                "policy declares no assertions; an empty policy would accept anything".into(),
            );
        }
        Ok(policy)
    }

    fn is_empty(&self) -> bool {
        let a = &self.assertions;
        a.issuer.is_none()
            && a.signer_subject_contains.is_none()
            && a.signer_issuer_contains.is_none()
            && a.min_receipts.is_none()
            && a.registered_after.is_none()
            && a.registered_before.is_none()
            && a.max_age_days.is_none()
            && a.min_svn.is_none()
            && a.require_kid_bound_to_key.is_none()
    }

    /// Evaluate the policy against verified facts.
    ///
    /// `now` is a Unix timestamp supplied by the caller. Passing it in rather
    /// than reading the clock keeps the same inputs producing the same decision
    /// on every machine, which matters when a build agent and a human are
    /// arguing about why a gate failed.
    pub fn evaluate(&self, facts: &StatementFacts, now: i64) -> PolicyDecision {
        let mut results = Vec::new();
        let a = &self.assertions;

        // Registration time is taken from the receipt, not the statement's own
        // `iat`. The issuer controls the latter; the ledger controls the former.
        let registered_at = facts
            .receipts
            .iter()
            .filter(|r| r.fully_verified())
            .filter_map(|r| r.registered_at)
            .min();

        if let Some(accepted) = &a.issuer {
            // Only fully verified receipts, for the same reason `registered_at`
            // filters above: receipts travel in the statement's *unprotected*
            // bucket, so anyone handling the file can append one. An appended
            // receipt's self-declared `iss` is an attacker-chosen string, and
            // accepting it here would let a statement registered on a ledger
            // this policy rejects satisfy the issuer rule anyway.
            let issuers: Vec<String> = facts
                .receipts
                .iter()
                .filter(|r| r.fully_verified())
                .filter_map(|r| r.issuer.clone())
                .collect();
            results.push(if issuers.is_empty() {
                result(
                    "issuer",
                    Outcome::CannotEvaluate,
                    "no fully verified receipt declares an issuer",
                )
            } else if issuers.iter().any(|i| accepted.contains(i)) {
                result(
                    "issuer",
                    Outcome::Pass,
                    format!("receipt issuer {issuers:?} is accepted"),
                )
            } else {
                result(
                    "issuer",
                    Outcome::Fail,
                    format!("receipt issuer {issuers:?} is not in the accepted list {accepted:?}"),
                )
            });
        }

        if let Some(needle) = &a.signer_subject_contains {
            results.push(match &facts.leaf_subject {
                None => result(
                    "signerSubjectContains",
                    Outcome::CannotEvaluate,
                    "statement carries no signing certificate",
                ),
                Some(subject) if subject.contains(needle) => result(
                    "signerSubjectContains",
                    Outcome::Pass,
                    format!("subject '{subject}' contains '{needle}'"),
                ),
                Some(subject) => result(
                    "signerSubjectContains",
                    Outcome::Fail,
                    format!("subject '{subject}' does not contain '{needle}'"),
                ),
            });
        }

        if let Some(needle) = &a.signer_issuer_contains {
            results.push(match &facts.leaf_issuer {
                None => result(
                    "signerIssuerContains",
                    Outcome::CannotEvaluate,
                    "statement carries no signing certificate",
                ),
                Some(issuer) if issuer.contains(needle) => result(
                    "signerIssuerContains",
                    Outcome::Pass,
                    format!("certificate issuer '{issuer}' contains '{needle}'"),
                ),
                Some(issuer) => result(
                    "signerIssuerContains",
                    Outcome::Fail,
                    format!("certificate issuer '{issuer}' does not contain '{needle}'"),
                ),
            });
        }

        if let Some(minimum) = a.min_receipts {
            let verified = facts.receipts.iter().filter(|r| r.fully_verified()).count();
            results.push(if verified >= minimum {
                result(
                    "minReceipts",
                    Outcome::Pass,
                    format!("{verified} receipt(s) fully verified, {minimum} required"),
                )
            } else {
                result(
                    "minReceipts",
                    Outcome::Fail,
                    format!("only {verified} receipt(s) fully verified, {minimum} required"),
                )
            });
        }

        if let Some(bound) = a.registered_after {
            results.push(compare_time(
                "registeredAfter",
                registered_at,
                |t| t >= bound,
                format!("registration must be at or after {bound}"),
            ));
        }

        if let Some(bound) = a.registered_before {
            results.push(compare_time(
                "registeredBefore",
                registered_at,
                |t| t <= bound,
                format!("registration must be at or before {bound}"),
            ));
        }

        if let Some(days) = a.max_age_days {
            let cutoff = now - days * 86_400;
            results.push(compare_time(
                "maxAgeDays",
                registered_at,
                |t| t >= cutoff,
                format!("registration must be within {days} day(s) of {now}"),
            ));
        }

        if let Some(minimum) = a.min_svn {
            results.push(match facts.cwt.svn {
                None => result(
                    "minSvn",
                    Outcome::CannotEvaluate,
                    "statement declares no security version number",
                ),
                Some(svn) if svn >= minimum => result(
                    "minSvn",
                    Outcome::Pass,
                    format!("svn {svn} meets the minimum of {minimum}"),
                ),
                Some(svn) => result(
                    "minSvn",
                    Outcome::Fail,
                    format!("svn {svn} is below the minimum of {minimum}"),
                ),
            });
        }

        if a.require_kid_bound_to_key == Some(true) {
            let flags: Vec<Option<bool>> =
                facts.receipts.iter().map(|r| r.kid_bound_to_key).collect();
            results.push(if flags.is_empty() || flags.iter().any(Option::is_none) {
                result(
                    "requireKidBoundToKey",
                    Outcome::CannotEvaluate,
                    "at least one receipt's signing key was never resolved",
                )
            } else if flags.iter().all(|f| *f == Some(true)) {
                result(
                    "requireKidBoundToKey",
                    Outcome::Pass,
                    "every receipt's kid is the digest of its signing key",
                )
            } else {
                result(
                    "requireKidBoundToKey",
                    Outcome::Fail,
                    "a receipt's kid is not the digest of its signing key",
                )
            });
        }

        PolicyDecision {
            policy_id: self.policy_id.clone(),
            policy_version: self.policy_version.clone(),
            results,
        }
    }
}

fn result(name: &str, outcome: Outcome, detail: impl Into<String>) -> AssertionResult {
    AssertionResult {
        name: name.to_string(),
        outcome,
        detail: detail.into(),
    }
}

fn compare_time(
    name: &str,
    registered_at: Option<i64>,
    predicate: impl Fn(i64) -> bool,
    requirement: String,
) -> AssertionResult {
    match registered_at {
        // No verified receipt means no trustworthy registration time. Falling
        // back to the statement's own `iat` here would let the issuer choose
        // the answer to a time-based policy question.
        None => result(
            name,
            Outcome::CannotEvaluate,
            format!("{requirement}, but no verified receipt supplied a registration time"),
        ),
        Some(t) if predicate(t) => result(
            name,
            Outcome::Pass,
            format!("registered at {t}; {requirement}"),
        ),
        Some(t) => result(
            name,
            Outcome::Fail,
            format!("registered at {t}; {requirement}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scitt_receipt::keys::KeyLookup;
    use scitt_receipt::receipt::ReceiptFacts;

    #[test]
    fn unknown_assertions_are_refused() {
        let json = br#"{"policyId":"p","policyVersion":"1","assertions":{"quantumProof":true}}"#;
        let err = Policy::from_json(json).unwrap_err();
        assert!(err.contains("not valid"), "{err}");
    }

    #[test]
    fn an_empty_policy_is_refused() {
        let json = br#"{"policyId":"p","policyVersion":"1","assertions":{}}"#;
        assert!(Policy::from_json(json).is_err());
    }

    #[test]
    fn a_decision_with_no_results_is_not_satisfied() {
        let decision = PolicyDecision {
            policy_id: "p".into(),
            policy_version: "1".into(),
            results: vec![],
        };
        assert!(!decision.satisfied());
    }

    #[test]
    fn cannot_evaluate_is_not_a_pass() {
        let decision = PolicyDecision {
            policy_id: "p".into(),
            policy_version: "1".into(),
            results: vec![result("minSvn", Outcome::CannotEvaluate, "no svn")],
        };
        assert!(!decision.satisfied());
        assert!(!decision.failed());
        assert!(decision.unevaluable());
    }

    fn policy_accepting(issuer: &str) -> Policy {
        let json = format!(
            r#"{{"policyId":"p","policyVersion":"1","assertions":{{"issuer":["{issuer}"]}}}}"#
        );
        Policy::from_json(json.as_bytes()).unwrap()
    }

    fn verified_receipt(issuer: &str) -> ReceiptFacts {
        ReceiptFacts {
            issuer: Some(issuer.into()),
            root_signature_valid: Some(true),
            bound_to_statement: Some(true),
            key_lookup: Some(KeyLookup::Found),
            ..Default::default()
        }
    }

    fn unverified_receipt(issuer: &str) -> ReceiptFacts {
        ReceiptFacts {
            issuer: Some(issuer.into()),
            ..Default::default()
        }
    }

    fn facts_with(receipts: Vec<ReceiptFacts>) -> StatementFacts {
        StatementFacts {
            receipts,
            ..Default::default()
        }
    }

    #[test]
    fn an_unverified_receipt_cannot_satisfy_the_issuer_assertion() {
        // Receipts ride in the statement's unprotected bucket, so anyone can
        // append one that declares whatever issuer the policy wants to see.
        let facts = facts_with(vec![unverified_receipt("trusted.example")]);
        let decision = policy_accepting("trusted.example").evaluate(&facts, 0);
        assert!(!decision.satisfied(), "{decision:?}");
        assert!(decision.unevaluable(), "{decision:?}");
    }

    #[test]
    fn a_forged_receipt_cannot_launder_a_genuine_one_from_another_ledger() {
        // A genuine receipt from a ledger the policy rejects, plus a forged
        // receipt naming the ledger it accepts, must not add up to a pass.
        let facts = facts_with(vec![
            verified_receipt("other.example"),
            unverified_receipt("trusted.example"),
        ]);
        let decision = policy_accepting("trusted.example").evaluate(&facts, 0);
        assert!(decision.failed(), "{decision:?}");
    }

    #[test]
    fn a_verified_receipt_satisfies_the_issuer_assertion() {
        let facts = facts_with(vec![verified_receipt("trusted.example")]);
        assert!(policy_accepting("trusted.example")
            .evaluate(&facts, 0)
            .satisfied());
    }
}
