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

/// A schema-version 2 payload, shaped as the MST release pipeline emits it,
/// that commits to `record`.
fn claim_for(record: &[u8]) -> Value {
    let r = record_value(record);
    json!({
        "schema-version": 2,
        "source": {"commit": "f".repeat(40), "branch": "refs/heads/main"},
        "build": {"id": "1", "number": "20260930.1"},
        "component": {
            "app": "mst",
            "variant": "public",
            "image": format!("example.invalid/mst@sha256:{}", "a".repeat(64)),
            "provenance": {
                "source-repository": REPOSITORY,
                "source-commit": r["source_commit"],
                "source-date-epoch": r["source_date_epoch"],
                "version": r["scitt_version"],
                "context-sha256": r["context_sha256"],
                "ccf-version": r["ccf_version"],
                "reproduction-record-sha256": scitt_receipt::sha256_hex(record),
                "reproduction-record-uri":
                    "https://github.com/microsoft/scitt-ccf-ledger/releases/download/0.20.1/reproduce.json",
                "image-digest": format!("sha256:{}", "a".repeat(64)),
            }
        },
        "security-policy-sha256": "b".repeat(64),
    })
}

fn provenance(claim: &mut Value) -> &mut Value {
    &mut claim["component"]["provenance"]
}

fn requirements() -> Requirements<'static> {
    Requirements {
        profile: PROFILE_MST_TBS,
        source_repository: REPOSITORY,
        app: "mst",
        variant: "public",
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
    provenance(&mut claim)["reproduction-record-sha256"] = json!("00".repeat(32));
    let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
    assert_eq!(states(&a), [Pass, Pass, Fail, Ce, Ce]);
    assert_eq!(
        a.findings[0].subject,
        "component.provenance.reproduction-record-sha256"
    );
}

#[test]
fn a_committed_record_that_disagrees_with_the_statement_fails() {
    for (claim_field, value) in [
        ("source-commit", json!("1".repeat(40))),
        ("version", json!("9.9.9")),
        ("context-sha256", json!("2".repeat(64))),
        ("ccf-version", json!("0.0.1")),
        ("source-date-epoch", json!(1)),
    ] {
        let mut claim = claim_for(PUBLISHED);
        provenance(&mut claim)[claim_field] = value;
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
    provenance(&mut claim)["reproduction-record-sha256"] = json!(scitt_receipt::sha256_hex(record));
    claim
}

#[test]
fn a_source_repository_the_policy_does_not_allow_fails() {
    let mut claim = claim_for(PUBLISHED);
    provenance(&mut claim)["source-repository"] = json!("https://github.com/example/fork");
    let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
    assert_eq!(states(&a), [Pass, Fail, Pass, Pass, Pass]);
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
    let mut c = claim_for(PUBLISHED);
    edit(&mut c);
    c
}

#[test]
fn a_statement_without_a_readable_claim_does_not_reach_the_record() {
    let cases: Vec<(&str, Value, CheckState)> = vec![
        ("not an object", json!([1, 2]), Fail),
        ("no schema-version", json!({"other": 1}), Fail),
        ("later schema", with(|c| c["schema-version"] = json!(3)), Ce),
        (
            "legacy schema",
            with(|c| c["schema-version"] = json!(1)),
            Ce,
        ),
        (
            "string schema",
            with(|c| c["schema-version"] = json!("2")),
            Fail,
        ),
        (
            "negative schema",
            with(|c| c["schema-version"] = json!(-2)),
            Fail,
        ),
        (
            "no component",
            with(|c| {
                c.as_object_mut().unwrap().remove("component");
            }),
            Fail,
        ),
        (
            "no provenance",
            with(|c| {
                c["component"].as_object_mut().unwrap().remove("provenance");
            }),
            Fail,
        ),
        (
            "short commit",
            with(|c| provenance(c)["source-commit"] = json!("abc")),
            Fail,
        ),
        (
            "upper-case context",
            with(|c| provenance(c)["context-sha256"] = json!("A".repeat(64))),
            Fail,
        ),
        (
            "string epoch",
            with(|c| provenance(c)["source-date-epoch"] = json!("1790269424")),
            Fail,
        ),
        (
            "negative epoch",
            with(|c| provenance(c)["source-date-epoch"] = json!(-1)),
            Fail,
        ),
        (
            "fractional epoch",
            with(|c| provenance(c)["source-date-epoch"] = json!(1.5)),
            Fail,
        ),
        (
            "empty version",
            with(|c| provenance(c)["version"] = json!("")),
            Fail,
        ),
        (
            "no record uri",
            with(|c| {
                provenance(c)
                    .as_object_mut()
                    .unwrap()
                    .remove("reproduction-record-uri");
            }),
            Fail,
        ),
        (
            "no source repository",
            with(|c| {
                provenance(c)
                    .as_object_mut()
                    .unwrap()
                    .remove("source-repository");
            }),
            Fail,
        ),
        (
            "debug variant",
            with(|c| c["component"]["variant"] = json!("debug")),
            Fail,
        ),
        (
            "another app",
            with(|c| c["component"]["app"] = json!("other")),
            Fail,
        ),
    ];
    for (name, claim, expected) in cases {
        let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
        assert_eq!(states(&a), [expected, Ce, Ce, Ce, Ce], "{name}");
    }
}

#[test]
fn a_component_mismatch_is_reported_with_both_sides() {
    let claim = with(|c| c["component"]["variant"] = json!("debug"));
    let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
    assert_eq!(a.findings.len(), 1);
    assert_eq!(a.findings[0].subject, "component.variant");
    assert_eq!(a.findings[0].expected.as_deref(), Some("public"));
    assert_eq!(a.findings[0].observed.as_deref(), Some("debug"));
}

#[test]
fn informational_payload_fields_do_not_affect_the_verdict() {
    let claim = with(|c| {
        c["component"]["image"] = json!("anything");
        provenance(c)["image-digest"] = json!("not a digest");
        c.as_object_mut().unwrap().remove("security-policy-sha256");
        c.as_object_mut().unwrap().remove("source");
    });
    let a = run(&claim, Some(PUBLISHED), Some(REBUILT));
    assert_eq!(states(&a), [Pass, Pass, Pass, Pass, Pass]);
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
            ..requirements()
        },
    );
    assert_eq!(states(&a), [Ce, Ce, Ce, Ce, Ce]);
}
