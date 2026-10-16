use scitt_policy::{ExternalRootSource, ExternalRoots, Outcome, Policy};
use scitt_receipt::{verify_statement, LedgerKeySet, StatementFacts};
use serde_json::json;

const URL: &str = "https://supplier.example/trust/hbom-roots.pem";
const VALID: &[u8] =
    include_bytes!("../../scitt-verifier/tests/fixtures/external-chain/valid.cose");
const NESTED: &[u8] =
    include_bytes!("../../scitt-verifier/tests/fixtures/external-chain/nested.cose");

fn facts(bytes: &[u8]) -> StatementFacts {
    let keys = LedgerKeySet::from_cose_key_set(include_bytes!(
        "../../scitt-verifier/tests/fixtures/external-chain/keys.cbor"
    ))
    .unwrap();
    let facts = verify_statement(bytes, &keys).unwrap();
    assert_eq!(facts.signature_valid, Some(true));
    assert_eq!(facts.verified_receipts().count(), 1);
    facts
}

fn root() -> String {
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../scitt-verifier/tests/fixtures/external-chain/expected.json"
    ))
    .unwrap();
    expected["rootSha256"].as_str().unwrap().into()
}

fn policy(signed_over: &str, pin: Option<&str>) -> Policy {
    Policy::from_json(
        &serde_json::to_vec(&json!({
            "policyId": "synthetic-https-roots",
            "policyVersion": "1",
            "assertions": { "externalSignatures": [{
                "path": ["external-signature", 0],
                "signedOver": signed_over,
                "requireChainToRootFromHttps": URL,
                "requireChainToRootSha256": pin,
            }] },
        }))
        .unwrap(),
    )
    .unwrap()
}

fn source(roots: Vec<String>) -> ExternalRootSource {
    ExternalRootSource {
        url: URL.into(),
        outcome: Ok(ExternalRoots {
            acquired_at: 1792000000,
            response_sha256: "ab".repeat(32),
            encoding: "pem".into(),
            root_sha256: roots,
        }),
    }
}

#[test]
fn endpoint_authorizes_only_a_validated_root_for_both_conventions() {
    for (bytes, signed_over) in [(VALID, "payload"), (NESTED, "coseSign1")] {
        let decision = policy(signed_over, None).evaluate_statement_with_external_roots(
            &facts(bytes),
            0,
            &[source(vec!["00".repeat(32), root().to_uppercase()])],
        );
        assert!(decision.satisfied(), "{decision:?}");
        let evidence = decision.results[0].external_signature.as_ref().unwrap();
        assert_eq!(evidence.signature_verified, Some(true));
        assert_eq!(evidence.root_source_matched, Some(true));
        assert_eq!(evidence.root_pin_matched, None);
        assert_eq!(evidence.certificate_chain.as_ref().unwrap().path_length, 3);
        let source = evidence.root_source.as_ref().unwrap();
        assert_eq!(source.url, URL);
        assert_eq!(source.material.as_ref().unwrap().acquired_at, 1792000000);
        assert!(source.failure.is_none());
    }
}

#[test]
fn a_different_published_root_fails_and_keeps_validated_path_evidence() {
    let decision = policy("payload", None).evaluate_statement_with_external_roots(
        &facts(VALID),
        0,
        &[source(vec!["00".repeat(32)])],
    );
    assert!(decision.failed());
    let evidence = decision.results[0].external_signature.as_ref().unwrap();
    assert_eq!(evidence.root_source_matched, Some(false));
    assert_eq!(
        evidence.certificate_chain.as_ref().unwrap().root_sha256,
        root()
    );
}

#[test]
fn a_pin_and_an_https_source_are_both_required() {
    for (pin, roots, expected) in [
        (root(), vec![root()], Outcome::Pass),
        ("00".repeat(32), vec![root()], Outcome::Fail),
        (root(), vec!["00".repeat(32)], Outcome::Fail),
    ] {
        let decision = policy("payload", Some(&pin)).evaluate_statement_with_external_roots(
            &facts(VALID),
            0,
            &[source(roots)],
        );
        assert_eq!(decision.results[0].outcome, expected, "{decision:?}");
    }
}

#[test]
fn missing_failed_empty_duplicate_or_wrongly_scoped_acquisition_never_passes() {
    let mut wrong_url = source(vec![root()]);
    wrong_url.url = "https://other.example/roots.pem".into();
    let unavailable = ExternalRootSource {
        url: URL.into(),
        outcome: Err("TLS authentication failed".into()),
    };
    for sources in [
        vec![],
        vec![wrong_url],
        vec![unavailable],
        vec![source(vec![])],
        vec![source(vec![root()]), source(vec![root()])],
    ] {
        let policy = policy("payload", Some(&root()));
        let decision = policy.evaluate_statement_with_external_roots(&facts(VALID), 0, &sources);
        assert_eq!(
            decision.results[0].outcome,
            Outcome::CannotEvaluate,
            "{decision:?}"
        );
        let evidence = decision.results[0].external_signature.as_ref().unwrap();
        assert_eq!(evidence.root_pin_matched, Some(true));
        assert_eq!(evidence.root_source_matched, None);
        assert!(evidence.root_source.as_ref().unwrap().failure.is_some());
        assert!(!policy.evaluate(&facts(VALID), 0).satisfied());
        assert!(!policy.evaluate_statement(&facts(VALID), 0).satisfied());
    }
}

#[test]
fn supplied_roots_do_not_hide_bad_signatures_damaged_paths_or_unsupported_checks() {
    for (bytes, expected) in [
        (
            include_bytes!("../../scitt-verifier/tests/fixtures/external-chain/bad-signature.cose")
                .as_slice(),
            Outcome::Fail,
        ),
        (
            include_bytes!(
                "../../scitt-verifier/tests/fixtures/external-chain/tampered-intermediate.cose"
            )
            .as_slice(),
            Outcome::Fail,
        ),
        (
            include_bytes!("../../scitt-verifier/tests/fixtures/external-chain/missing-root.cose")
                .as_slice(),
            Outcome::Fail,
        ),
        (
            include_bytes!(
                "../../scitt-verifier/tests/fixtures/external-chain/malformed-first-entry.cose"
            )
            .as_slice(),
            Outcome::Fail,
        ),
        (
            include_bytes!(
                "../../scitt-verifier/tests/fixtures/external-chain/unsupported-pss.cose"
            )
            .as_slice(),
            Outcome::CannotEvaluate,
        ),
        (
            include_bytes!(
                "../../scitt-verifier/tests/fixtures/external-chain/unsupported-critical.cose"
            )
            .as_slice(),
            Outcome::CannotEvaluate,
        ),
    ] {
        let decision = policy("payload", None).evaluate_statement_with_external_roots(
            &facts(bytes),
            0,
            &[source(vec![root()])],
        );
        assert_eq!(decision.results[0].outcome, expected, "{decision:?}");
        assert_eq!(
            decision.results[0]
                .external_signature
                .as_ref()
                .unwrap()
                .root_source_matched,
            None,
        );
    }
}

#[test]
fn authorization_is_independent_for_each_rule() {
    let mut value = serde_json::to_value(policy("payload", None)).unwrap();
    let mut second = value["assertions"]["externalSignatures"][0].clone();
    second["requireChainToRootFromHttps"] = "https://other.example/roots.pem".into();
    value["assertions"]["externalSignatures"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let policy = Policy::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let decision =
        policy.evaluate_statement_with_external_roots(&facts(VALID), 0, &[source(vec![root()])]);
    assert_eq!(decision.results[0].outcome, Outcome::Pass);
    assert_eq!(decision.results[1].outcome, Outcome::CannotEvaluate);
    assert!(!decision.satisfied());
}

#[test]
fn plainly_invalid_https_sources_are_refused_when_reading_policy() {
    for url in [
        "",
        "http://supplier.example/roots.pem",
        "https://",
        "https://supplier.example/\n",
    ] {
        let mut value = serde_json::to_value(policy("payload", None)).unwrap();
        value["assertions"]["externalSignatures"][0]["requireChainToRootFromHttps"] = url.into();
        assert!(Policy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
