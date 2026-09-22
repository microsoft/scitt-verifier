//! Online mode: which ledgers to ask, and how their keys stay apart.
//!
//! Two jobs, both of which exist because receipts arrive in the statement's
//! *unprotected* header bucket. Nothing signs that bucket, so anyone who
//! handles the file can append a receipt naming any ledger they like.
//!
//! The first job is selection: deciding which ledgers may be contacted, using
//! the relying party's allowlist and never the statement. The second is
//! scoping: making sure a key acquired from one ledger can never verify a
//! receipt attributed to another, even when both name the same `kid`.

use scitt_acquire::{limits, route_for, validate_host, Acquired, Failed, Outcome};
use scitt_policy::Policy;
use scitt_receipt::{
    describe_receipt, verify_statement, verify_statement_with, KeyLookup, LedgerKeySet,
    ReceiptFacts, Sign1, StatementFacts, VerifyOptions,
};

/// What selection concluded, before anything touched the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Contact exactly these issuers, in this order.
    Ready(Vec<String>),
    /// The run is misconfigured. Exit 4, and no request is made.
    Refused(String),
    /// Nothing to ask. Not an error about the operator, and not a finding about
    /// the artifact: no ledger this policy accepts is named by any receipt, so
    /// transparency simply cannot be established here.
    Nothing(String),
}

/// The issuer each receipt claims, by position, without verifying anything.
///
/// These are discovery hints and nothing more. A value here has not been
/// authenticated, is not evidence, and is only ever used to *narrow* a set the
/// policy already authorised.
pub fn candidate_issuers(statement_bytes: &[u8]) -> Vec<Option<String>> {
    let Ok(statement) = Sign1::parse(statement_bytes) else {
        return Vec::new();
    };
    statement
        .receipts()
        .iter()
        .map(|bytes| describe_receipt(bytes).ok().and_then(|s| s.issuer))
        .collect()
}

/// Decide which ledgers may be contacted.
///
/// The allowlist is the only source of authority. `explicit` can pick one entry
/// out of it and can never add to it; candidate issuers can narrow it and can
/// never extend it. Both restrictions are what keep an appended receipt from
/// choosing where this process connects.
pub fn select(policy: &Policy, candidates: &[Option<String>], explicit: Option<&str>) -> Selection {
    let allowlist = match policy.assertions.issuer.as_ref() {
        Some(list) if !list.is_empty() => list,
        _ => {
            return Selection::Refused(
                "--online needs the policy to say which transparency services it accepts, \
                 and this policy sets no assertions.issuer allowlist. Without one, the \
                 statement being checked would be choosing where to fetch keys from."
                    .into(),
            )
        }
    };

    // Deduplicate and sort so the same inputs always produce the same requests
    // in the same order. A record that changes between identical runs is harder
    // to compare, and comparison is most of what a record is for.
    let mut accepted: Vec<String> = allowlist.clone();
    accepted.sort();
    accepted.dedup();

    let selected: Vec<String> = if let Some(named) = explicit {
        if !accepted.iter().any(|a| a == named) {
            return Selection::Refused(format!(
                "--ledger {named} is not in the policy's assertions.issuer allowlist. \
                 --ledger narrows what the policy already accepts; it cannot add to it. \
                 Allowlisted: {}",
                accepted.join(", ")
            ));
        }
        vec![named.to_string()]
    } else if accepted.len() == 1 {
        // One accepted service and no ambiguity about which it is, so there is
        // nothing for a candidate to disambiguate. This is what lets the common
        // single-ledger case work without the operator naming it twice.
        accepted.clone()
    } else {
        let mut named: Vec<String> = candidates
            .iter()
            .flatten()
            .filter(|c| accepted.iter().any(|a| &a == c))
            .cloned()
            .collect();
        named.sort();
        named.dedup();

        if named.is_empty() {
            return Selection::Nothing(format!(
                "no receipt names a transparency service this policy accepts ({}), \
                 so no keys were fetched",
                accepted.join(", ")
            ));
        }
        named
    };

    // Refuse rather than truncate. Silently dropping the tail would mean the
    // run checked less than the operator asked for while still being able to
    // report a pass.
    if selected.len() > limits::MAX_LEDGERS {
        return Selection::Refused(format!(
            "{} ledgers were selected, above the limit of {}. Narrow the policy's \
             assertions.issuer allowlist, or pass --ledger to choose one.",
            selected.len(),
            limits::MAX_LEDGERS
        ));
    }

    // Every selected destination is validated and routable before a single
    // packet leaves. A typo in an allowlist should read as a typo, not as a
    // ledger that failed to answer.
    for issuer in &selected {
        if let Err(e) = validate_host(issuer) {
            return Selection::Refused(format!("policy allowlist entry is unusable: {e}"));
        }
        if let Err(e) = route_for(issuer) {
            return Selection::Refused(format!(
                "{e}. This build cannot bootstrap trust for that service, and will not \
                 guess an endpoint for it."
            ));
        }
    }

    Selection::Ready(selected)
}

/// A key set holding nothing.
///
/// Built directly rather than parsed because a COSE_KeySet with no usable keys
/// is rightly rejected as trust material. This is not trust material: it is the
/// absence of it, used to obtain the parse-level facts about a statement — leaf
/// hashes, proof shape, what each receipt commits to — that hold regardless of
/// whether any key was ever found.
fn no_keys() -> LedgerKeySet {
    LedgerKeySet {
        keys: Vec::new(),
        revoked_kids: Vec::new(),
        skipped: Vec::new(),
    }
}

/// Verify every receipt against the keys of the ledger it names, and no others.
///
/// The isolation is structural. Each acquired key set is handed to its own
/// verification pass, and a receipt's result is only ever taken from the pass
/// belonging to the issuer that receipt claims. Two ledgers publishing the same
/// `kid` therefore cannot stand in for one another: the receipt naming ledger A
/// is never shown ledger B's keys at all, so there is no lookup to confuse.
///
/// A receipt whose issuer was not selected is reported as exactly that. It is
/// not an unknown key — nobody looked — and saying otherwise would describe a
/// deliberate scoping decision as a gap in the trust material.
pub fn verify_scoped(
    statement_bytes: &[u8],
    acquired: &[Acquired],
    options: &VerifyOptions,
) -> Result<StatementFacts, scitt_receipt::Error> {
    let mut merged = verify_statement_with(statement_bytes, &no_keys(), options)?;

    let per_ledger: Vec<(&str, StatementFacts)> = acquired
        .iter()
        .filter_map(|a| {
            verify_statement(statement_bytes, &a.keys)
                .ok()
                .map(|f| (a.issuer.as_str(), f))
        })
        .collect();

    for receipt in merged.receipts.iter_mut() {
        let claimed = receipt.issuer.clone();
        let index = receipt.index;
        let scoped: Vec<(&str, &[ReceiptFacts])> = per_ledger
            .iter()
            .map(|(l, f)| (*l, f.receipts.as_slice()))
            .collect();

        match pick(&scoped, claimed.as_deref(), index) {
            Pick::Scoped(found) => {
                // Cheap tripwires. If either ever fires, the identity used by
                // `pick` has stopped identifying, and silently verifying the
                // wrong receipt is the one failure worth aborting a debug
                // build over.
                debug_assert_eq!(found.issuer, claimed);
                debug_assert_eq!(found.index, index);
                *receipt = found.clone();
            }
            Pick::Unevaluable => mark_unevaluable(receipt, claimed.as_deref()),
            Pick::NotSelected => mark_not_selected(receipt, claimed.as_deref()),
        }
    }

    Ok(merged)
}

/// Where a receipt's verified facts should come from.
enum Pick<'a> {
    /// The ledger this receipt names was selected, and it judged this receipt.
    Scoped(&'a ReceiptFacts),
    /// The ledger was selected and its keys were held, but evaluating this
    /// receipt under them failed outright.
    Unevaluable,
    /// No key set was ever consulted for this receipt.
    NotSelected,
}

/// Choose the scoped result for one receipt.
///
/// Matched on the receipt's own issuer *and* its own envelope index. Neither
/// position within a pass's `receipts` nor order of iteration can be used: a
/// receipt that cannot be evaluated is recorded as a problem rather than as
/// facts, and which receipts that removes depends on the key set in play. A
/// pass holding the right key reaches checks the base pass never does — an
/// unsupported algorithm, or a key that will not import — and drops the receipt
/// there, leaving the two sequences different lengths. Matching by position
/// would then hand one receipt's verdict to another, which is the single
/// outcome this module exists to rule out.
fn pick<'a>(
    per_ledger: &[(&str, &'a [ReceiptFacts])],
    claimed: Option<&str>,
    index: usize,
) -> Pick<'a> {
    let Some(issuer) = claimed else {
        return Pick::NotSelected;
    };
    let Some((_, receipts)) = per_ledger.iter().find(|(l, _)| *l == issuer) else {
        return Pick::NotSelected;
    };
    match receipts.iter().find(|r| r.index == index) {
        Some(found) => Pick::Scoped(found),
        None => Pick::Unevaluable,
    }
}

/// Record that a receipt could not be evaluated under its own ledger's keys.
///
/// Reached when the scoped pass resolved the signing key and then failed on
/// something further in — an algorithm this build does not implement, or key
/// material it cannot import. The receipt is left unverified, which is what it
/// is, rather than being reported as a key that was never sought.
fn mark_unevaluable(receipt: &mut ReceiptFacts, claimed: Option<&str>) {
    receipt.root_signature_valid = None;

    receipt.problems.push(match claimed {
        Some(issuer) => format!(
            "receipt could not be evaluated against the keys acquired from '{issuer}'; \
             it is not verified"
        ),
        None => "receipt could not be evaluated; it is not verified".into(),
    });
}

/// Record that a receipt was never looked up, and why.
fn mark_not_selected(receipt: &mut ReceiptFacts, claimed: Option<&str>) {
    // The empty-key-set pass reaches the key lookup, finds nothing, records
    // "this kid is not in the key set", and returns immediately. That note is
    // true of that pass and false of this run: no key set was ever consulted
    // for this receipt. Leaving it would make a deliberate scoping decision
    // read as a rotation this build failed to follow, which is the one reading
    // that would send an operator looking for a problem that does not exist.
    //
    // It is always the last entry, because the lookup returns as soon as it
    // pushes it. Dropping it by position rather than by matching its text keeps
    // this from silently doing nothing if the wording upstream is reworded.
    if receipt.key_lookup == Some(KeyLookup::UnknownKid) {
        let note = receipt.problems.pop();
        debug_assert!(
            note.as_deref()
                .is_some_and(|n| receipt.kid.as_deref().is_some_and(|k| n.contains(k))),
            "expected the trailing problem to be the unknown-kid note for this receipt, \
             got {note:?}"
        );
    }

    // "No key matched" and "no key was sought" have to stay distinguishable.
    receipt.key_lookup = None;
    receipt.root_signature_valid = None;
    receipt.kid_bound_to_key = None;

    receipt.problems.push(match claimed {
        Some(issuer) => format!(
            "receipt names transparency service '{issuer}', which the policy does not \
             accept or which could not be acquired; its signing key was not looked up"
        ),
        None => "receipt names no transparency service, so no signing key could be \
                 selected for it"
            .into(),
    });
}

/// Split acquisition outcomes into what succeeded and what did not.
pub fn partition(outcomes: Vec<Outcome>) -> (Vec<Acquired>, Vec<Failed>) {
    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(a) => ok.push(a),
            Err(f) => failed.push(*f),
        }
    }
    (ok, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(issuers: Option<Vec<&str>>) -> Policy {
        let mut p = Policy {
            policy_id: "test".into(),
            policy_version: "1".into(),
            description: None,
            ledger: None,
            trust: None,
            assertions: Default::default(),
        };
        p.assertions.issuer = issuers.map(|v| v.into_iter().map(String::from).collect());
        p
    }

    const A: &str = "a.confidential-ledger.azure.com";
    const B: &str = "b.confidential-ledger.azure.com";

    #[test]
    fn no_allowlist_is_a_configuration_error() {
        assert!(matches!(
            select(&policy_with(None), &[], None),
            Selection::Refused(_)
        ));
    }

    #[test]
    fn empty_allowlist_is_a_configuration_error() {
        assert!(matches!(
            select(&policy_with(Some(vec![])), &[], None),
            Selection::Refused(_)
        ));
    }

    /// The single-ledger case must not require a receipt to name it, or a
    /// first-time user has to know the answer before asking the question.
    #[test]
    fn one_allowlisted_issuer_is_selected_without_any_candidate() {
        assert_eq!(
            select(&policy_with(Some(vec![A])), &[], None),
            Selection::Ready(vec![A.to_string()])
        );
    }

    #[test]
    fn multiple_allowlisted_issuers_narrow_to_those_receipts_name() {
        let got = select(&policy_with(Some(vec![A, B])), &[Some(B.to_string())], None);
        assert_eq!(got, Selection::Ready(vec![B.to_string()]));
    }

    #[test]
    fn a_receipt_naming_an_unlisted_ledger_selects_nothing() {
        let got = select(
            &policy_with(Some(vec![A, B])),
            &[Some("evil.confidential-ledger.azure.com".into())],
            None,
        );
        assert!(matches!(got, Selection::Nothing(_)), "{got:?}");
    }

    /// The whole point of the feature: a statement cannot introduce a ledger.
    #[test]
    fn an_appended_receipt_cannot_add_a_destination() {
        let attacker = "attacker.confidential-ledger.azure.com".to_string();
        let got = select(
            &policy_with(Some(vec![A, B])),
            &[Some(attacker.clone()), Some(A.to_string())],
            None,
        );
        match got {
            Selection::Ready(list) => assert!(!list.contains(&attacker), "{list:?}"),
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn explicit_ledger_outside_the_allowlist_is_refused() {
        assert!(matches!(
            select(&policy_with(Some(vec![A])), &[], Some(B)),
            Selection::Refused(_)
        ));
    }

    #[test]
    fn explicit_ledger_inside_the_allowlist_selects_only_it() {
        assert_eq!(
            select(&policy_with(Some(vec![A, B])), &[], Some(A)),
            Selection::Ready(vec![A.to_string()])
        );
    }

    #[test]
    fn an_unroutable_allowlist_entry_is_refused_before_networking() {
        assert!(matches!(
            select(&policy_with(Some(vec!["ledger.example.test"])), &[], None),
            Selection::Refused(_)
        ));
    }

    #[test]
    fn an_allowlist_entry_that_is_not_a_hostname_is_refused() {
        assert!(matches!(
            select(
                &policy_with(Some(vec!["https://a.confidential-ledger.azure.com"])),
                &[],
                None
            ),
            Selection::Refused(_)
        ));
    }

    #[test]
    fn a_selection_above_the_limit_is_refused_rather_than_truncated() {
        let hosts: Vec<String> = (0..=limits::MAX_LEDGERS)
            .map(|i| format!("l{i}.confidential-ledger.azure.com"))
            .collect();
        let refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let candidates: Vec<Option<String>> = hosts.iter().cloned().map(Some).collect();
        assert!(matches!(
            select(&policy_with(Some(refs)), &candidates, None),
            Selection::Refused(_)
        ));
    }

    #[test]
    fn selection_is_deterministic_regardless_of_allowlist_order() {
        let one = select(&policy_with(Some(vec![B, A])), &[], Some(A));
        let two = select(&policy_with(Some(vec![A, B])), &[], Some(A));
        assert_eq!(one, two);
    }

    fn facts_at(index: usize, issuer: &str) -> ReceiptFacts {
        ReceiptFacts {
            index,
            issuer: Some(issuer.into()),
            ..Default::default()
        }
    }

    /// The bug this guards against: a scoped pass returns *fewer* receipts than
    /// the base pass whenever it resolves a key and then fails further in, so
    /// the two sequences stop lining up. Selecting by position then takes a
    /// later receipt's result for an earlier one — reporting an unverifiable
    /// receipt as verified, and burying the genuinely verified one.
    #[test]
    fn a_dropped_receipt_never_shifts_another_receipts_result() {
        // The ledger judged receipt 1 only; receipt 0 failed under its keys.
        let scoped = vec![facts_at(1, A)];
        let per_ledger = vec![(A, scoped.as_slice())];

        // Receipt 0 must not inherit receipt 1's result.
        match pick(&per_ledger, Some(A), 0) {
            Pick::Unevaluable => {}
            Pick::Scoped(f) => panic!("receipt 0 took receipt {}'s result", f.index),
            Pick::NotSelected => panic!("the ledger was selected and did answer"),
        }

        // And receipt 1 must still get its own.
        match pick(&per_ledger, Some(A), 1) {
            Pick::Scoped(f) => assert_eq!(f.index, 1),
            _ => panic!("receipt 1 lost its own result"),
        }
    }

    #[test]
    fn a_receipt_is_never_judged_by_another_ledgers_pass() {
        let a_facts = vec![facts_at(0, A)];
        let per_ledger = vec![(A, a_facts.as_slice())];

        // Same index, different service: there is no result to take.
        assert!(matches!(pick(&per_ledger, Some(B), 0), Pick::NotSelected));
        // No claimed issuer at all is likewise never matched to a pass.
        assert!(matches!(pick(&per_ledger, None, 0), Pick::NotSelected));
    }

    /// `index` is the envelope position, not the position within `receipts`.
    /// If these were ever the same thing, `pick` would be matching on a value
    /// that carries no more information than the loop counter it replaced.
    #[test]
    fn receipt_index_is_the_envelope_position() {
        let statement =
            std::fs::read(crate::online::tests::fixture("transparent-statement.cose")).unwrap();
        let facts = verify_statement(&statement, &no_keys()).unwrap();
        for (position, receipt) in facts.receipts.iter().enumerate() {
            assert_eq!(
                receipt.index, position,
                "no receipt was dropped here, so the two must agree"
            );
        }
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/fixtures")
            .join(name)
    }
}
