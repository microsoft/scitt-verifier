use super::*;
use serde_json::json;

/// The public scitt-ccf-ledger 0.20.1 release record, exact bytes.
const PUBLISHED: &[u8] =
    include_bytes!("../../../corpus/fixtures/image-reproduction/published-reproduce.json");
/// That release rebuilt on scitt-ccf-ledger's own CI runners.
const REBUILT: &[u8] =
    include_bytes!("../../../corpus/fixtures/image-reproduction/rebuilt-reproduce.json");

const REPOSITORY: &str = "https://github.com/microsoft/scitt-ccf-ledger";

fn record_value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn claim_for(record: &[u8]) -> Value {
    let r = record_value(record);
    json!({
        "scittReproduction": 1,
        "profile": PROFILE_SCITT_CCF_LEDGER,
        "sourceRepository": REPOSITORY,
        "sourceCommit": r["source_commit"],
        "version": r["scitt_version"],
        "contextSha256": r["context_sha256"],
        "reproductionRecordSha256": scitt_receipt::sha256_hex(record),
    })
}

fn requirements() -> Requirements<'static> {
    Requirements {
        profile: PROFILE_SCITT_CCF_LEDGER,
        source_repository: REPOSITORY,
    }
}

fn run(claim: &Value, published: Option<&[u8]>, rebuilt: Option<&[u8]>) -> Appraisal {
    let payload = serde_json::to_vec(claim).unwrap();
    appraise(
        Payload::Json(&payload),
        Evidence {
            published_record: published,
            rebuilt_record: rebuilt,
        },
        &requirements(),
    )
}

fn edited(bytes: &[u8], edit: impl FnOnce(&mut Map<String, Value>)) -> Vec<u8> {
    let Value::Object(mut map) = record_value(bytes) else {
        panic!("record is an object")
    };
    edit(&mut map);
    serde_json::to_vec_pretty(&Value::Object(map)).unwrap()
}

fn states(a: &Appraisal) -> Vec<CheckState> {
    a.checks().iter().map(|(_, _, c)| c.state).collect()
}

use CheckState::{CannotEvaluate as Ce, Fail, Pass};

#[test]
fn the_real_rebuild_matches_the_real_record() {
    let a = run(&claim_for(PUBLISHED), Some(PUBLISHED), Some(REBUILT));
    assert_eq!(states(&a), [Pass, Pass, Pass, Pass, Pass], "{a:#?}");
    assert!(a.findings.is_empty());
}

#[test]
fn a_record_other_than_the_committed_one_is_refused_before_it_is_read() {
    let mut claim = claim_for(PUBLISHED);
    claim["reproductionRecordSha256"] = json!("00".repeat(32));
    let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
    assert_eq!(states(&a), [Pass, Pass, Fail, Ce, Ce]);
    assert_eq!(a.findings[0].subject, "reproductionRecordSha256");
}

#[test]
fn a_committed_record_that_disagrees_with_the_statement_fails() {
    for (claim_field, value) in [
        ("sourceCommit", json!("1".repeat(40))),
        ("version", json!("9.9.9")),
        ("contextSha256", json!("2".repeat(64))),
    ] {
        let mut claim = claim_for(PUBLISHED);
        claim[claim_field] = value;
        let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
        assert_eq!(states(&a), [Pass, Pass, Fail, Ce, Ce], "{claim_field}");
    }
}

#[test]
fn input_drift_is_reported_apart_from_layer_mismatch() {
    let rebuilt = edited(REBUILT, |m| {
        m.insert("ccf_rpm_sha256".into(), json!("3".repeat(64)));
    });
    let a = run(&claim_for(PUBLISHED), Some(PUBLISHED), Some(&rebuilt));
    assert_eq!(states(&a), [Pass, Pass, Pass, Fail, Pass]);
    assert!(a.rebuild_inputs.detail.contains("ccf_rpm_sha256"));

    let rebuilt = edited(REBUILT, |m| {
        m.insert("context_sha256".into(), json!("4".repeat(64)));
    });
    let a = run(&claim_for(PUBLISHED), Some(PUBLISHED), Some(&rebuilt));
    assert_eq!(a.rebuild_inputs.state, Fail, "context drift is input drift");
}

#[test]
fn every_recorded_input_is_compared() {
    for field in INPUT_FIELDS {
        let rebuilt = edited(REBUILT, |m| {
            m.insert(field.into(), json!("changed"));
        });
        let a = run(&claim_for(PUBLISHED), Some(PUBLISHED), Some(&rebuilt));
        assert_eq!(a.rebuild_inputs.state, Fail, "{field} was not compared");
    }
}

#[test]
fn builder_details_are_reported_not_compared() {
    let rebuilt = edited(REBUILT, |m| {
        m.insert("docker_version".into(), json!("99.0.0"));
        m.insert(
            "image_id".into(),
            json!(format!("sha256:{}", "5".repeat(64))),
        );
    });
    let a = run(&claim_for(PUBLISHED), Some(PUBLISHED), Some(&rebuilt));
    assert_eq!(states(&a), [Pass, Pass, Pass, Pass, Pass]);
    assert_eq!(a.informational.len(), 2);
}

#[test]
fn layer_order_and_multiplicity_are_part_of_the_claim() {
    let layers = record_value(PUBLISHED)["layers"].clone();
    let original: Vec<Value> = layers.as_array().unwrap().clone();

    let mut reversed = original.clone();
    reversed.reverse();
    let mut dropped = original.clone();
    dropped.pop();
    let mut repeated = original.clone();
    repeated.push(original[original.len() - 1].clone());
    let mut replaced = original.clone();
    replaced[0] = json!(format!("sha256:{}", "6".repeat(64)));

    for (name, list) in [
        ("reordered", reversed),
        ("dropped", dropped),
        ("repeated", repeated),
        ("replaced", replaced),
        ("empty", Vec::new()),
    ] {
        let rebuilt = edited(REBUILT, |m| {
            m.insert("layers".into(), Value::Array(list));
        });
        let a = run(&claim_for(PUBLISHED), Some(PUBLISHED), Some(&rebuilt));
        assert_eq!(states(&a), [Pass, Pass, Pass, Pass, Fail], "{name}");
        assert!(!a.findings.is_empty(), "{name}");
    }
}

#[test]
fn a_record_with_no_layers_cannot_be_matched_vacuously() {
    let published = edited(PUBLISHED, |m| {
        m.insert("layers".into(), json!([]));
    });
    let rebuilt = edited(REBUILT, |m| {
        m.insert("layers".into(), json!([]));
    });
    let a = run(&claim_for(&published), Some(&published), Some(&rebuilt));
    assert_eq!(states(&a), [Pass, Pass, Fail, Ce, Ce]);
}

#[test]
fn a_registry_digest_is_not_a_layer_digest() {
    // A layer must be `sha256:` plus 64 lowercase hex digits. A registry
    // reference carries the same digest syntax behind a repository name.
    let published = edited(PUBLISHED, |m| {
        m.insert(
            "layers".into(),
            json!([format!("example.invalid/app@sha256:{}", "7".repeat(64))]),
        );
    });
    let a = run(&claim_for(&published), Some(&published), Some(REBUILT));
    assert_eq!(a.record_binding.state, Fail);
}

#[test]
fn missing_evidence_cannot_be_evaluated_and_never_passes() {
    let claim = claim_for(PUBLISHED);
    assert_eq!(
        states(&run(&claim, None, Some(REBUILT))),
        [Pass, Pass, Ce, Ce, Ce]
    );
    assert_eq!(
        states(&run(&claim, Some(PUBLISHED), None)),
        [Pass, Pass, Pass, Ce, Ce]
    );
}

#[test]
fn an_unreadable_rebuild_is_an_inability_not_a_finding() {
    let claim = claim_for(PUBLISHED);
    for rebuilt in [
        b"not json".to_vec(),
        edited(REBUILT, |m| {
            m.insert("schema_version".into(), json!(2));
        }),
        edited(REBUILT, |m| {
            m.remove("base_image");
        }),
    ] {
        let a = run(&claim, Some(PUBLISHED), Some(&rebuilt));
        assert_eq!(states(&a), [Pass, Pass, Pass, Ce, Ce]);
    }
}

#[test]
fn an_unknown_record_schema_is_unsupported_not_malformed() {
    let published = edited(PUBLISHED, |m| {
        m.insert("schema_version".into(), json!(2));
    });
    let a = run(&claim_for(&published), Some(&published), Some(REBUILT));
    assert_eq!(a.record_binding.state, Ce);
}

#[test]
fn a_record_missing_a_required_input_is_refused() {
    let published = edited(PUBLISHED, |m| {
        m.remove("tdnf_snapshottime");
    });
    let a = run(&claim_for(&published), Some(&published), Some(REBUILT));
    assert_eq!(a.record_binding.state, Fail);
}

#[test]
fn a_duplicate_key_in_a_record_is_refused_rather_than_resolved() {
    let text = std::str::from_utf8(PUBLISHED).unwrap();
    let published = text
        .replacen('{', "{\n  \"schema_version\": 1,", 1)
        .into_bytes();
    let a = run(
        &claim_for_bytes(&published),
        Some(&published),
        Some(REBUILT),
    );
    assert_eq!(a.record_binding.state, Fail);
}

fn claim_for_bytes(record: &[u8]) -> Value {
    let mut claim = claim_for(PUBLISHED);
    claim["reproductionRecordSha256"] = json!(scitt_receipt::sha256_hex(record));
    claim
}

#[test]
fn a_source_repository_the_policy_does_not_allow_fails() {
    let mut claim = claim_for(PUBLISHED);
    claim["sourceRepository"] = json!("https://github.com/example/fork");
    let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
    assert_eq!(states(&a), [Pass, Fail, Pass, Pass, Pass]);
}

#[test]
fn a_statement_without_a_readable_claim_does_not_reach_the_record() {
    let cases: Vec<(Value, CheckState)> = vec![
        (json!({"other": 1}), Fail),
        (json!([1, 2]), Fail),
        (
            {
                let mut c = claim_for(PUBLISHED);
                c["scittReproduction"] = json!(2);
                c
            },
            Ce,
        ),
        (
            {
                let mut c = claim_for(PUBLISHED);
                c["scittReproduction"] = json!("1");
                c
            },
            Fail,
        ),
        (
            {
                let mut c = claim_for(PUBLISHED);
                c["profile"] = json!("another/profile");
                c
            },
            Fail,
        ),
        (
            {
                let mut c = claim_for(PUBLISHED);
                c["sourceCommit"] = json!("ABC");
                c
            },
            Fail,
        ),
    ];
    for (claim, expected) in cases {
        let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
        assert_eq!(states(&a), [expected, Ce, Ce, Ce, Ce], "{claim}");
    }
}

#[test]
fn payloads_that_are_not_json_or_not_present_are_distinguished() {
    let evidence = || Evidence {
        published_record: Some(PUBLISHED),
        rebuilt_record: Some(REBUILT),
    };
    let a = appraise(
        Payload::NotJson("text/plain".into()),
        evidence(),
        &requirements(),
    );
    assert_eq!(a.reproduction_claim.state, Fail);
    let a = appraise(
        Payload::Unavailable("detached".into()),
        evidence(),
        &requirements(),
    );
    assert_eq!(a.reproduction_claim.state, Ce);
}

#[test]
fn an_unsupported_profile_evaluates_nothing() {
    let payload = serde_json::to_vec(&claim_for(PUBLISHED)).unwrap();
    let a = appraise(
        Payload::Json(&payload),
        Evidence {
            published_record: Some(PUBLISHED),
            rebuilt_record: Some(REBUILT),
        },
        &Requirements {
            profile: "another/profile",
            source_repository: REPOSITORY,
        },
    );
    assert_eq!(states(&a), [Ce, Ce, Ce, Ce, Ce]);
}
