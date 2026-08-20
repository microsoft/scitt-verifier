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
    /// Exactly how many receipts the statement must carry. Must be 1.
    ///
    /// Counts receipts *present*, not receipts that verified, because the
    /// thing it detects is insertion. Receipts ride in the unprotected header
    /// bucket that no signature covers, so anyone who handled the file can add
    /// one; a service this tool verifies against issues exactly one per
    /// registration. A second receipt therefore means the file is not the file
    /// the service returned, whether or not the extra one verifies.
    ///
    /// A value above 1 is refused rather than supported. Receipts are not
    /// signed as a set, so `2` would be satisfied by attaching a copy of the
    /// one that exists — counting twice while proving once. Verifying genuinely
    /// independent registrations needs explicit support, not a larger number.
    ///
    /// Deliberately an exact count rather than a lower bound. A minimum of 1
    /// could only restate what the verdict already guarantees — no run passes
    /// without a verified receipt — so it would never reject anything.
    #[serde(default)]
    pub receipt_count: Option<usize>,
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
    /// The subject the statement must claim, from the protected CWT claims.
    ///
    /// Unlike `signerSubjectContains`, which reads a certificate the statement
    /// carries, this reads a claim inside the signed payload — so it is covered
    /// by the issuer's signature and, through the claim digest, by the receipt
    /// the ledger issued. Pinning it answers "is this statement about the thing
    /// I am holding?" for artifacts that cannot be hashed, such as a physical
    /// part identified by serial number.
    #[serde(default)]
    pub statement_subject: Option<StringMatch>,
}

/// How a policy matches a string-valued claim.
///
/// Exactly one mode must be set, and it must be capable of rejecting something.
/// Both an empty object and a criterion every value satisfies are refused when
/// the policy is parsed, because either would appear in the report as a rule
/// that ran and passed while having examined nothing.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StringMatch {
    /// The claim must be exactly this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    /// The claim must begin with this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_with: Option<String>,
    /// The claim must be exactly one of these values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<String>>,
}

impl StringMatch {
    fn validate(&self, field: &str) -> Result<(), String> {
        let declared = [
            self.equals.is_some(),
            self.starts_with.is_some(),
            self.one_of.is_some(),
        ]
        .iter()
        .filter(|set| **set)
        .count();

        if declared == 0 {
            return Err(format!(
                "{field} declares no match criteria; it would accept any value"
            ));
        }
        if declared > 1 {
            return Err(format!(
                "{field} declares more than one of equals, startsWith, oneOf; use exactly one"
            ));
        }
        // A criterion that cannot reject anything is worse than no criterion at
        // all, because the report shows it passing.
        if self.starts_with.as_deref() == Some("") {
            return Err(format!(
                "{field}.startsWith is empty; every value starts with the empty string"
            ));
        }
        if self.one_of.as_deref().is_some_and(<[String]>::is_empty) {
            return Err(format!(
                "{field}.oneOf is empty; no value could ever satisfy it"
            ));
        }
        Ok(())
    }

    fn matches(&self, value: &str) -> bool {
        if let Some(expected) = &self.equals {
            return value == expected;
        }
        if let Some(prefix) = &self.starts_with {
            return value.starts_with(prefix);
        }
        if let Some(accepted) = &self.one_of {
            return accepted.iter().any(|c| c == value);
        }
        false
    }

    fn describe(&self) -> String {
        if let Some(expected) = &self.equals {
            return format!("must equal '{expected}'");
        }
        if let Some(prefix) = &self.starts_with {
            return format!("must start with '{prefix}'");
        }
        if let Some(accepted) = &self.one_of {
            return format!("must be one of {accepted:?}");
        }
        "has no criteria".into()
    }
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
        if let Some(subject) = &policy.assertions.statement_subject {
            subject.validate("statementSubject")?;
        }
        if let Some(expected) = policy.assertions.receipt_count {
            // Refused at parse time rather than evaluated to a failure, so the
            // operator learns the policy asks for something unobtainable
            // instead of watching every artifact fail and hunting for why.
            if expected != 1 {
                return Err(format!(
                    "receiptCount is {expected}, but the only supported value is 1. Receipts are \
                     not signed as a set, so a count above 1 can be met by attaching a copy of a \
                     single receipt — counting twice while proving once — and no transparency \
                     service this build verifies against issues more than one per registration. \
                     A count of 0 would accept a statement with no proof at all."
                ));
            }
        }
        Ok(policy)
    }

    /// Whether the policy declares no assertion at all.
    ///
    /// Derived from the serialised form rather than a hand-written chain of
    /// `is_none` checks. The chain had to be extended every time an assertion
    /// was added, and forgetting to do so would reject a policy that used only
    /// the new assertion as though it were empty.
    fn is_empty(&self) -> bool {
        match serde_json::to_value(&self.assertions) {
            Ok(serde_json::Value::Object(fields)) => {
                fields.values().all(serde_json::Value::is_null)
            }
            _ => false,
        }
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
            .verified_receipts()
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
                .verified_receipts()
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

        if let Some(expected) = &a.statement_subject {
            // The claim is absent rather than wrong, which is a different
            // message to the reader and must never read as a pass.
            results.push(match &facts.cwt.sub {
                None => result(
                    "statementSubject",
                    Outcome::CannotEvaluate,
                    "statement declares no CWT subject claim",
                ),
                Some(subject) if expected.matches(subject) => result(
                    "statementSubject",
                    Outcome::Pass,
                    format!("subject '{subject}' {}", expected.describe()),
                ),
                Some(subject) => result(
                    "statementSubject",
                    Outcome::Fail,
                    format!(
                        "subject '{subject}' does not match: it {}",
                        expected.describe()
                    ),
                ),
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

        if let Some(expected) = a.receipt_count {
            // `receipts_present`, not `verified_receipts()`: this assertion
            // exists to notice that the file grew a receipt after the service
            // returned it, and an inserted receipt is unlikely to verify. That
            // an inserted receipt is disregarded by the verdict is exactly why
            // counting only the verified ones would never see it.
            let present = facts.receipts_present;
            results.push(if present == expected {
                result(
                    "receiptCount",
                    Outcome::Pass,
                    format!("statement carries {present} receipt(s), {expected} required"),
                )
            } else {
                result(
                    "receiptCount",
                    Outcome::Fail,
                    format!(
                        "statement carries {present} receipt(s), {expected} required; \
                         receipts are attached to a header no signature covers, so an \
                         unexpected count means the file is not the one the service returned"
                    ),
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
            // Only fully verified receipts. Reading every receipt here made
            // this assertion an attacker-triggerable denial of gate: appending
            // one junk receipt, whose key never resolves, left a `None` in the
            // list and forced `cannotEvaluate` on a statement that was
            // otherwise fine. Nobody needs a signing key to append a receipt.
            //
            // Filtering does not weaken the assertion. `fully_verified()`
            // requires the key to have been *found*, not that its kid was
            // derived from it, so the case this rule exists to catch — a
            // genuine, verifying receipt whose kid is not its key's digest —
            // still reaches the check below.
            let flags: Vec<Option<bool>> = facts
                .verified_receipts()
                .map(|r| r.kid_bound_to_key)
                .collect();
            results.push(if flags.is_empty() {
                result(
                    "requireKidBoundToKey",
                    Outcome::CannotEvaluate,
                    "no receipt fully verified, so no signing key was resolved to compare",
                )
            } else if flags.iter().any(Option::is_none) {
                result(
                    "requireKidBoundToKey",
                    Outcome::CannotEvaluate,
                    "a verified receipt's kid could not be compared to its signing key",
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

    fn subject_policy(criteria: &str) -> Result<Policy, String> {
        let json = format!(
            r#"{{"policyId":"p","policyVersion":"1","assertions":{{"statementSubject":{criteria}}}}}"#
        );
        Policy::from_json(json.as_bytes())
    }

    fn receipt_count_policy(value: &str) -> Result<Policy, String> {
        let json = format!(
            r#"{{"policyId":"p","policyVersion":"1","assertions":{{"receiptCount":{value}}}}}"#
        );
        Policy::from_json(json.as_bytes())
    }

    #[test]
    fn one_receipt_is_the_only_accepted_count() {
        assert!(receipt_count_policy("1").is_ok());
    }

    #[test]
    fn asking_for_two_receipts_is_refused_at_parse_time() {
        // The count is unobtainable rather than merely strict: no service this
        // tool verifies against issues two receipts, and the only way to reach
        // two is to attach a copy of the one that exists. Refusing the policy
        // tells the operator that; failing every artifact would not.
        let err = receipt_count_policy("2").unwrap_err();
        assert!(err.contains("only supported value is 1"), "{err}");
    }

    #[test]
    fn a_large_receipt_count_is_refused_too() {
        assert!(receipt_count_policy("99").is_err());
    }

    #[test]
    fn a_zero_receipt_count_is_refused() {
        // Zero would accept a statement carrying no proof of registration at
        // all, which is the one thing this tool exists to require.
        assert!(receipt_count_policy("0").is_err());
    }

    #[test]
    fn an_extra_receipt_fails_the_count_even_though_it_is_disregarded() {
        // The whole point of the assertion. An inserted receipt does not
        // verify, so `verified_receipts()` cannot see it and the verdict
        // rightly ignores it — but the file still is not the one the service
        // returned, and an operator who asked for exactly one is told so.
        let policy = receipt_count_policy("1").unwrap();
        let facts = StatementFacts {
            receipts_present: 2,
            ..Default::default()
        };
        assert!(policy.evaluate(&facts, 0).failed());
    }

    #[test]
    fn a_single_receipt_satisfies_the_count() {
        let policy = receipt_count_policy("1").unwrap();
        let facts = StatementFacts {
            receipts_present: 1,
            ..Default::default()
        };
        assert!(!policy.evaluate(&facts, 0).failed());
    }

    #[test]
    fn a_policy_of_only_a_new_assertion_is_not_empty() {
        // Guards the reflective `is_empty`. The hand-written chain it replaced
        // had to be extended for every assertion, and forgetting to do so
        // rejected a valid policy as though it declared nothing.
        subject_policy(r#"{"startsWith":"amd-hbom-"}"#).unwrap();
    }

    #[test]
    fn a_subject_match_with_no_criteria_is_refused() {
        let err = subject_policy("{}").unwrap_err();
        assert!(err.contains("no match criteria"), "{err}");
    }

    #[test]
    fn a_subject_match_that_cannot_reject_anything_is_refused() {
        // `startsWith: ""` is satisfied by every string. Accepting it would put
        // a rule in the report that passed without examining anything — the
        // same class of failure as an assertion nobody ran.
        let err = subject_policy(r#"{"startsWith":""}"#).unwrap_err();
        assert!(err.contains("empty string"), "{err}");
    }

    #[test]
    fn a_subject_match_nothing_can_satisfy_is_refused() {
        let err = subject_policy(r#"{"oneOf":[]}"#).unwrap_err();
        assert!(err.contains("oneOf is empty"), "{err}");
    }

    #[test]
    fn a_subject_match_with_two_modes_is_refused() {
        let err = subject_policy(r#"{"equals":"a","startsWith":"b"}"#).unwrap_err();
        assert!(err.contains("exactly one"), "{err}");
    }

    #[test]
    fn an_unknown_subject_match_mode_is_refused() {
        // `contains` is deliberately absent: `signerSubjectContains` reads a
        // certificate, and a substring match on an identity claim invites a
        // policy for 'amd-hbom-1' to accept 'not-amd-hbom-12'.
        assert!(subject_policy(r#"{"contains":"amd"}"#).is_err());
    }

    #[test]
    fn an_absent_subject_claim_cannot_evaluate_rather_than_fail() {
        // "the statement claims no subject" and "the statement claims the wrong
        // subject" call for different responses from whoever reads the report.
        let policy = subject_policy(r#"{"equals":"amd-hbom-1"}"#).unwrap();
        let facts = StatementFacts::default();
        assert_eq!(facts.cwt.sub, None);
        let decision = policy.evaluate(&facts, 0);
        assert!(decision.unevaluable(), "{decision:?}");
        assert!(!decision.failed(), "{decision:?}");
        assert!(!decision.satisfied(), "{decision:?}");
    }

    #[test]
    fn a_subject_prefix_does_not_match_in_the_middle() {
        let policy = subject_policy(r#"{"startsWith":"amd-hbom-"}"#).unwrap();
        let facts = StatementFacts {
            cwt: scitt_receipt::statement::CwtClaims {
                sub: Some("evil-amd-hbom-1".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(policy.evaluate(&facts, 0).failed());
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

    fn kid_policy() -> Policy {
        let json =
            br#"{"policyId":"p","policyVersion":"1","assertions":{"requireKidBoundToKey":true}}"#;
        Policy::from_json(json).unwrap()
    }

    #[test]
    fn an_appended_junk_receipt_cannot_deny_the_gate() {
        // Anyone handling the file can append a receipt whose key never
        // resolves. If that alone forced cannotEvaluate, appending junk would
        // be enough to stop a good build from shipping.
        let mut good = verified_receipt("trusted.example");
        good.kid_bound_to_key = Some(true);
        let facts = facts_with(vec![good, unverified_receipt("whatever")]);
        assert!(kid_policy().evaluate(&facts, 0).satisfied());
    }

    #[test]
    fn a_verified_receipt_with_an_unbound_kid_still_fails() {
        // The filter above must not swallow the case this assertion exists for.
        let mut bad = verified_receipt("trusted.example");
        bad.kid_bound_to_key = Some(false);
        assert!(kid_policy().evaluate(&facts_with(vec![bad]), 0).failed());
    }

    #[test]
    fn nothing_verified_means_the_kid_rule_cannot_be_evaluated() {
        let facts = facts_with(vec![unverified_receipt("trusted.example")]);
        assert!(kid_policy().evaluate(&facts, 0).unevaluable());
    }
}
