use scitt_policy::{ExternalRootSource, ExternalRoots, Outcome, Policy};
use scitt_receipt::{chain, verify_statement_with, LedgerKeySet, StatementFacts, VerifyOptions};
use serde_json::{json, Value};

const URL: &str = "https://publisher.example/trust/root.crt";
const VALID: &[u8] = include_bytes!("../../scitt-verifier/tests/fixtures/critical-eku/valid.cose");

fn expected() -> Value {
    serde_json::from_str(include_str!(
        "../../scitt-verifier/tests/fixtures/critical-eku/expected.json"
    ))
    .unwrap()
}

fn policy(extra: Value) -> Policy {
    let mut assertions = json!({
        "requireChainToRootFromHttps": URL,
        "requireEku": expected()["leafEkuOids"],
        "certificateValidAtSigningTime": true,
    });
    assertions
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    Policy::from_json(
        &serde_json::to_vec(&json!({
            "policyId": "synthetic-publisher-roots",
            "policyVersion": "1",
            "assertions": assertions,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn facts(bytes: &[u8], policy: &Policy, trusted_roots: Vec<Vec<u8>>) -> StatementFacts {
    let keys = LedgerKeySet::from_cose_key_set(include_bytes!(
        "../../scitt-verifier/tests/fixtures/critical-eku/keys.cbor"
    ))
    .unwrap();
    verify_statement_with(
        bytes,
        &keys,
        &VerifyOptions {
            chain: Some(chain::Options {
                required_eku: policy.assertions.require_eku.clone().unwrap_or_default(),
                trusted_roots,
                ..Default::default()
            }),
        },
    )
    .unwrap()
}

fn source(roots: Vec<String>) -> ExternalRootSource {
    ExternalRootSource {
        url: URL.into(),
        outcome: Ok(ExternalRoots {
            acquired_at: 1792000000,
            response_sha256: "ab".repeat(32),
            encoding: "der".into(),
            root_sha256: roots,
        }),
    }
}

fn root() -> String {
    expected()["rootSha256"].as_str().unwrap().into()
}

#[test]
fn a_published_root_authorizes_a_short_lived_purpose_checked_statement_chain() {
    let policy = policy(json!({}));
    let facts = facts(VALID, &policy, vec![]);
    let decision = policy.evaluate_statement_with_external_roots(
        &facts,
        1792000000,
        &[source(vec![root().to_uppercase()])],
    );
    assert!(decision.satisfied(), "{decision:?}");
    assert_eq!(facts.signature_valid, Some(true));
    assert_eq!(facts.certificates_valid_at_signing_time, Some(true));
    let chain::Outcome::Valid(details) = facts.chain_outcome.as_ref().unwrap() else {
        panic!("expected a validated path")
    };
    assert!(!details.anchored_externally);
    assert_eq!(details.path_len, 3);
    assert!(details.path_not_after < 1792000000);
    let authorization = &decision.results[0];
    assert_eq!(authorization.name, "requireChainToRootFromHttps");
    assert_eq!(authorization.root_source_matched, Some(true));
    let evidence = authorization.root_source.as_ref().unwrap();
    assert_eq!(evidence.url, URL);
    assert_eq!(evidence.material.as_ref().unwrap().encoding, "der");
}

#[test]
fn a_different_root_fails_and_a_pin_remains_an_independent_constraint() {
    for (pin, roots, outcome) in [
        (root(), vec![root()], Outcome::Pass),
        (root(), vec!["00".repeat(32)], Outcome::Fail),
        ("00".repeat(32), vec![root()], Outcome::Fail),
    ] {
        let policy = policy(json!({ "requireChainToRootSha256": pin }));
        let decision = policy.evaluate_statement_with_external_roots(
            &facts(VALID, &policy, vec![]),
            0,
            &[source(roots)],
        );
        assert_eq!(
            decision.satisfied(),
            outcome == Outcome::Pass,
            "{decision:?}"
        );
        assert_eq!(decision.failed(), outcome == Outcome::Fail, "{decision:?}");
    }
    let policy = policy(json!({}));
    let decision = policy.evaluate_statement_with_external_roots(
        &facts(VALID, &policy, vec![]),
        0,
        &[source(vec!["00".repeat(32)])],
    );
    assert_eq!(decision.results[0].outcome, Outcome::Fail);
    assert_eq!(decision.results[0].root_source_matched, Some(false));
}

#[test]
fn offline_missing_failed_empty_duplicate_or_other_sources_never_authorize() {
    let policy = policy(json!({ "requireChainToRootSha256": root() }));
    let facts = facts(VALID, &policy, vec![]);
    let mut other = source(vec![root()]);
    other.url = "https://other.example/root.crt".into();
    for sources in [
        vec![],
        vec![other],
        vec![ExternalRootSource {
            url: URL.into(),
            outcome: Err("TLS failure".into()),
        }],
        vec![source(vec![])],
        vec![source(vec![root()]), source(vec![root()])],
    ] {
        let decision = policy.evaluate_statement_with_external_roots(&facts, 0, &sources);
        assert!(!decision.satisfied());
        let result = decision
            .results
            .iter()
            .find(|r| r.name == "requireChainToRootFromHttps")
            .unwrap();
        assert_eq!(result.outcome, Outcome::CannotEvaluate);
        assert_eq!(result.root_source_matched, None);
        assert!(result.root_source.as_ref().unwrap().failure.is_some());
    }
    assert!(!policy.evaluate(&facts, 0).satisfied());
    assert!(!policy.evaluate_statement(&facts, 0).satisfied());
    let mut unchecked = facts.clone();
    unchecked.chain_outcome = None;
    let decision =
        policy.evaluate_statement_with_external_roots(&unchecked, 0, &[source(vec![root()])]);
    assert!(decision
        .results
        .iter()
        .any(|r| r.name == "requireChainToRootFromHttps" && r.outcome == Outcome::CannotEvaluate));
    assert!(!decision.satisfied());
}

#[test]
fn root_publication_does_not_bypass_purpose_path_or_registration_time_checks() {
    let base = policy(json!({}));
    for (bytes, expected_outcome) in [
        (
            include_bytes!(
                "../../scitt-verifier/tests/fixtures/critical-eku/tampered-intermediate.cose"
            )
            .as_slice(),
            Outcome::Fail,
        ),
        (
            include_bytes!("../../scitt-verifier/tests/fixtures/critical-eku/leaf-only.cose")
                .as_slice(),
            Outcome::CannotEvaluate,
        ),
        (
            include_bytes!(
                "../../scitt-verifier/tests/fixtures/critical-eku/late-registration.cose"
            )
            .as_slice(),
            Outcome::Fail,
        ),
        (
            include_bytes!(
                "../../scitt-verifier/tests/fixtures/critical-eku/no-registration-time.cose"
            )
            .as_slice(),
            Outcome::CannotEvaluate,
        ),
    ] {
        let decision = base.evaluate_statement_with_external_roots(
            &facts(bytes, &base, vec![]),
            0,
            &[source(vec![root()])],
        );
        assert!(!decision.satisfied(), "{decision:?}");
        assert!(
            decision
                .results
                .iter()
                .any(|r| r.outcome == expected_outcome),
            "{decision:?}"
        );
    }
    for (policy, expected_outcome) in [
        (
            policy(json!({ "requireEku": ["1.3.6.1.4.1.55555.99"] })),
            Outcome::Fail,
        ),
        (
            policy(json!({ "requireEku": null })),
            Outcome::CannotEvaluate,
        ),
    ] {
        let decision = policy.evaluate_statement_with_external_roots(
            &facts(VALID, &policy, vec![]),
            0,
            &[source(vec![root()])],
        );
        assert_eq!(
            decision.results[0].outcome, expected_outcome,
            "{decision:?}"
        );
        assert_eq!(decision.results[0].root_source_matched, None);
        assert!(!decision.satisfied());
    }
    let wrong_local_roots = chain::parse_pem_certificates(include_str!(
        "../../scitt-verifier/tests/fixtures/external-chain/roots.pem"
    ))
    .unwrap();
    let decision = base.evaluate_statement_with_external_roots(
        &facts(VALID, &base, wrong_local_roots),
        0,
        &[source(vec![root()])],
    );
    assert!(decision.failed(), "{decision:?}");
}

#[test]
fn an_https_root_source_alone_is_an_assertion_and_invalid_urls_are_rejected() {
    for (url, valid) in [
        (URL, true),
        ("", false),
        ("http://publisher.example/root.crt", false),
        ("https://", false),
        ("https://publisher.example/root.crt\n", false),
    ] {
        let result = Policy::from_json(
            &serde_json::to_vec(&json!({
                "policyId": "only-root-source",
                "policyVersion": "1",
                "assertions": { "requireChainToRootFromHttps": url },
            }))
            .unwrap(),
        );
        assert_eq!(result.is_ok(), valid, "{url:?}");
    }
}
