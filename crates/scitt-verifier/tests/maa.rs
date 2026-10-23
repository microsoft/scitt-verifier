//! The scoped MAA comparison through the built binary, using real corpus bytes.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn run(name: &str, path: Value, bundle: Option<Value>) -> (i32, Value) {
    let corpus = root().join("corpus");
    let mut policy: Value = serde_json::from_slice(include_bytes!(
        "../../../corpus/policies/image-reproduction.json"
    ))
    .unwrap();
    policy["adapters"] = json!({"azure-attestation": {
        "target": {"host": "attestation.example"},
        "binding": {"path": path, "encoding": "base64"}
    }});
    let dir = root()
        .join("target")
        .join(format!("maa-cli-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy_path = dir.join("policy.json");
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let evidence = dir.join("evidence");
    if let Some(bundle) = bundle {
        std::fs::create_dir_all(&evidence).unwrap();
        std::fs::write(
            evidence.join("maa-evidence.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"))
        .arg("verify")
        .arg("--statement")
        .arg(
            corpus
                .join("fixtures")
                .join("image-reproduction")
                .join("statement.cose"),
        )
        .arg("--scitt-keys")
        .arg(corpus.join("fixtures").join("mst-test-scitt-keys.cbor"))
        .arg("--policy")
        .arg(&policy_path)
        .args([
            "--adapter",
            "azure-attestation",
            "--binding-mode",
            "saved-evidence",
        ])
        .arg("--evidence")
        .arg(evidence)
        .args(["--format", "json"])
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    let record = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid result: {e}; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), record)
}

fn public_bundle() -> Value {
    let certs: Value =
        serde_json::from_slice(include_bytes!("../../../corpus/fixtures/maa-certs.json")).unwrap();
    json!({
        "schemaVersion": 1, "targetHost": "attestation.example",
        "serviceVersion": "metadata-not-an-acceptance-requirement", "certs": certs
    })
}

fn adapter_check<'a>(record: &'a Value, name: &str) -> &'a Value {
    record["appraisal"]["checks"]["adapter"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == name)
        .unwrap()
}

fn assert_statement_accepted(record: &Value) {
    assert_eq!(record["appraisal"]["checks"]["statementSignature"], "pass");
    assert_eq!(record["appraisal"]["checks"]["receiptInclusion"], "pass");
    assert_eq!(record["appraisal"]["checks"]["policy"], "pass");
}

#[test]
fn unavailable_comparison_preserves_explicit_structured_limitations() {
    let (code, record) = run(
        "gaps",
        json!(["security-policy-base64"]),
        Some(public_bundle()),
    );
    assert_eq!(code, 3, "{record}");
    assert_statement_accepted(&record);
    assert_eq!(record["appraisal"]["verdict"], "cannot-evaluate");
    let gaps = record["appraisal"]["notChecked"].as_array().unwrap();
    for code in [
        "MaaSigningKeyBindingNotEstablished",
        "MaaFreshnessNotEstablished",
        "MaaGuestEnforcementNotEstablished",
        "MaaPlatformPolicyNotAppraised",
        "MaaSavedMetadataUnsigned",
        "MaaAppraisalLimitation",
    ] {
        assert!(gaps.iter().any(|gap| gap["code"] == code), "{code}");
    }
    #[cfg(not(feature = "adapter-azure-attestation"))]
    assert!(adapter_check(&record, "snp-validation")["detail"]
        .as_str()
        .unwrap()
        .contains("adapter-azure-attestation"));
}

#[cfg(feature = "adapter-azure-attestation")]
#[test]
fn real_statement_without_the_policy_claim_is_explicitly_unevaluable() {
    let (code, record) = run(
        "absent-policy",
        json!(["security-policy-base64"]),
        Some(public_bundle()),
    );
    assert_eq!(code, 3, "{record}");
    assert_statement_accepted(&record);
    assert!(adapter_check(&record, "cce-policy-host-data")["detail"]
        .as_str()
        .unwrap()
        .contains("no such claim"));
}

#[cfg(feature = "adapter-azure-attestation")]
#[test]
fn missing_saved_evidence_is_reached_after_a_real_claim_is_decoded() {
    // This real fixture's zero-valued source commit is valid base64, but it is
    // deliberately not a CCE policy; it lets this case reach the missing-file check.
    let (code, record) = run("missing-evidence", json!(["source", "commit"]), None);
    assert_eq!(code, 3, "{record}");
    assert_statement_accepted(&record);
    assert!(adapter_check(&record, "snp-validation")["detail"]
        .as_str()
        .unwrap()
        .contains("evidence directory:"));
}

#[cfg(feature = "adapter-azure-attestation")]
#[test]
fn real_snp_reports_fail_a_wrong_statement_claim_digest_regardless_of_version_metadata() {
    // The wrong binding path must fail by digest comparison, not by skipping
    // report authentication or by demanding a matching build string.
    for (name, version) in [
        ("wrong-claim-version", json!("does-not-match-build")),
        ("wrong-claim-no-version", Value::Null),
    ] {
        let mut bundle = public_bundle();
        bundle["serviceVersion"] = version;
        let (code, record) = run(name, json!(["source", "commit"]), Some(bundle));
        assert_eq!(code, 2, "{record}");
        assert_statement_accepted(&record);
        assert_eq!(record["appraisal"]["verdict"], "resource-failed");
        assert_eq!(adapter_check(&record, "snp-validation")["state"], "pass");
        assert_eq!(
            adapter_check(&record, "cce-policy-host-data")["state"],
            "fail"
        );
        let notes = record["appraisal"]["notChecked"].as_array().unwrap();
        assert!(
            notes.iter().any(|note| {
                note["code"] == "MaaAppraisalLimitation"
                    && note["message"].as_str().is_some_and(|message| {
                        message.contains("version metadata does not affect acceptance")
                            || message.contains("it was not compared with the statement")
                    })
            }),
            "{record}"
        );
        let checks = record["appraisal"]["checks"]["adapter"].as_array().unwrap();
        assert_eq!(checks.len(), 3);
        assert!(!checks
            .iter()
            .any(|check| check["name"] == "maa-signing-key-binding"));
    }
}

#[cfg(feature = "adapter-azure-attestation")]
#[test]
fn saved_target_metadata_must_still_match_the_selected_policy() {
    let mut bundle = public_bundle();
    bundle["targetHost"] = json!("other.example");
    let (code, record) = run("wrong-target", json!(["source", "commit"]), Some(bundle));
    assert_eq!(code, 3, "{record}");
    assert_statement_accepted(&record);
    assert!(adapter_check(&record, "snp-validation")["detail"]
        .as_str()
        .unwrap()
        .contains("does not exactly match"));
}
