//! Exercise the reusable API without a CLI, filesystem, or implicit clock.

use scitt_adapter_certificate_hbom::{appraise, Appraisal, CheckState, Evidence, HbomPolicy};
use scitt_policy::adapters::hbom::{ClaimEncoding, DigestEncoding, HbomSource};
use scitt_receipt::{chain, Sign1};
use serde_json::json;

const NOW: i64 = 1785197841;
const ROOT: &str = include_str!("../../../corpus/fixtures/synthetic-hbom/root.pem");
const GOOD: &str = include_str!("../../../corpus/fixtures/synthetic-hbom/good.pem");

fn certificates(pem: &str) -> Vec<Vec<u8>> {
    chain::parse_pem_certificates(pem).unwrap()
}

fn statement() -> Sign1 {
    Sign1::parse(include_bytes!(
        "../../../corpus/fixtures/transparent-statement.cose"
    ))
    .unwrap()
}

fn policy() -> HbomPolicy {
    serde_json::from_value(json!({
        "source": {"kind": "statement-payload"},
        "rootSha256": scitt_receipt::sha256_hex(&certificates(ROOT)[0]),
        "leafEku": "1.3.6.1.4.1.55555.1.2",
        "profile": {
            "oid": "1.3.6.1.4.1.55555.1.1", "digest": "sha384", "encoding": "raw"
        }
    }))
    .unwrap()
}

fn evaluate(policy: &HbomPolicy, chain: &str, roots: &str, now: i64) -> Appraisal {
    appraise(
        &statement(),
        policy,
        Evidence {
            certificates: &certificates(chain),
            trusted_roots: &certificates(roots),
        },
        now,
    )
}

fn assert_states(result: &Appraisal, trust: CheckState, binding: CheckState) {
    assert_eq!(result.certificate_trust.state, trust, "{result:?}");
    assert_eq!(result.hbom_commitment.state, binding, "{result:?}");
    for (_, _, check) in result.checks() {
        assert!(!check.detail.is_empty(), "{result:?}");
    }
}

#[test]
fn certificate_and_commitment_failure_states_survive_extraction() {
    use CheckState::{CannotEvaluate, Fail, Pass};
    for (pem, trust, binding) in [
        (GOOD, Pass, Pass),
        (
            include_str!("../../../corpus/fixtures/synthetic-hbom/broken.pem"),
            Fail,
            CannotEvaluate,
        ),
        (
            include_str!("../../../corpus/fixtures/synthetic-hbom/expired.pem"),
            Fail,
            CannotEvaluate,
        ),
        (
            include_str!("../../../corpus/fixtures/synthetic-hbom/ambiguous.pem"),
            Fail,
            CannotEvaluate,
        ),
        (
            include_str!("../../../corpus/fixtures/synthetic-hbom/mismatch.pem"),
            Pass,
            Fail,
        ),
        (
            include_str!("../../../corpus/fixtures/synthetic-hbom/missing.pem"),
            Pass,
            Fail,
        ),
        (
            include_str!("../../../corpus/fixtures/synthetic-hbom/malformed.pem"),
            Pass,
            Fail,
        ),
    ] {
        assert_states(&evaluate(&policy(), pem, ROOT, NOW), trust, binding);
    }
}

#[test]
fn independent_roots_pin_role_and_explicit_time_are_required() {
    use CheckState::{CannotEvaluate, Fail, Pass};
    let unrelated = include_str!("../../../corpus/fixtures/synthetic-hbom/untrusted-root.pem");
    let mut policy = policy();
    assert_states(&evaluate(&policy, GOOD, ROOT, NOW), Pass, Pass);
    assert_states(&evaluate(&policy, GOOD, ROOT, 0), Fail, CannotEvaluate);
    assert_states(
        &evaluate(&policy, GOOD, unrelated, NOW),
        Fail,
        CannotEvaluate,
    );
    assert_states(
        &evaluate(&policy, GOOD, &ROOT.repeat(2), NOW),
        Fail,
        CannotEvaluate,
    );
    policy.leaf_eku = "1.2.3.4".into();
    assert_states(&evaluate(&policy, GOOD, ROOT, NOW), Fail, CannotEvaluate);
    policy.root_sha256 = scitt_receipt::sha256_hex(&certificates(unrelated)[0]);
    let result = evaluate(&policy, GOOD, unrelated, NOW);
    assert_states(&result, Fail, CannotEvaluate);
    assert!(result.certificate_trust.detail.contains("chain ends at"));
}

#[test]
fn synthetic_profile_is_explicit_even_for_direct_library_callers() {
    use CheckState::{CannotEvaluate, Fail, Pass};
    let der = include_str!("../../../corpus/fixtures/synthetic-hbom/der-octet.pem");
    let mut policy = policy();
    assert_states(&evaluate(&policy, der, ROOT, NOW), Pass, Fail);
    policy.profile.encoding = DigestEncoding::DerOctetString;
    assert_states(&evaluate(&policy, der, ROOT, NOW), Pass, Pass);
    policy.profile.oid = "1.3.6.1.4.1.3704.5.2".into();
    let result = evaluate(&policy, der, ROOT, NOW);
    assert_states(&result, CannotEvaluate, CannotEvaluate);
    assert!(result.certificate_trust.detail.contains("unsupported"));
}

#[test]
fn missing_or_malformed_in_memory_inputs_never_pass() {
    use CheckState::{CannotEvaluate, Fail, Pass};
    let certs = certificates(GOOD);
    let roots = certificates(ROOT);
    let mut statement = statement();
    let mut policy = policy();
    let evidence = Evidence {
        certificates: &certs,
        trusted_roots: &roots,
    };
    assert_states(
        &appraise(
            &statement,
            &policy,
            Evidence {
                certificates: &[],
                ..evidence
            },
            NOW,
        ),
        CannotEvaluate,
        CannotEvaluate,
    );
    assert_states(
        &appraise(
            &statement,
            &policy,
            Evidence {
                trusted_roots: &[],
                ..evidence
            },
            NOW,
        ),
        Fail,
        CannotEvaluate,
    );
    statement.payload = None;
    assert_states(
        &appraise(&statement, &policy, evidence, NOW),
        Pass,
        CannotEvaluate,
    );
    statement = Sign1::parse(include_bytes!("../../../corpus/fixtures/cbor-header.cose")).unwrap();
    policy.source = HbomSource::EncodedClaim {
        path: vec![scitt_policy::PathSegment::Text("hbom".into())],
        encoding: ClaimEncoding::Base64,
    };
    for payload in [
        br#"{"hbom":"%%%"}"#.as_slice(),
        br#"{"hbom":"eA==","hbom":"eA=="}"#.as_slice(),
        br#"{}"#.as_slice(),
    ] {
        statement.payload = Some(payload.to_vec());
        assert_states(
            &appraise(&statement, &policy, evidence, NOW),
            Pass,
            CannotEvaluate,
        );
    }
    assert_states(
        &Appraisal::unevaluated("statement not accepted"),
        CannotEvaluate,
        CannotEvaluate,
    );
}
