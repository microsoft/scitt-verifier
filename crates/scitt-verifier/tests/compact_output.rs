//! Presentation must not change records, verdicts, or offline boundaries.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn corpus(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(path)
}

fn command(statement: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"));
    command
        .arg("verify")
        .arg("--statement")
        .arg(corpus(&format!("fixtures/{statement}")))
        .args(["--now", "1800000000"]);
    command
}

fn fixture_run(statement: &str, keys: &str, policy: &str, result: &Path, extra: &[&str]) -> Output {
    command(statement)
        .arg("--scitt-keys")
        .arg(corpus(&format!("fixtures/{keys}")))
        .arg("--policy")
        .arg(corpus(&format!("policies/{policy}")))
        .arg("--result")
        .arg(result)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn compact_verbose_and_disabled_progress_produce_identical_records_and_exits() {
    for (index, statement, keys, policy, code) in [
        (
            0,
            "transparent-statement.cose",
            "mst-test-scitt-keys.cbor",
            "fixture-mst.json",
            0,
        ),
        (
            1,
            "payload-tampered.cose",
            "mst-test-scitt-keys.cbor",
            "fixture-mst.json",
            1,
        ),
        (
            2,
            "transparent-statement.cose",
            "mst-test-scitt-keys.cbor",
            "wrong-issuer.json",
            2,
        ),
        (
            3,
            "transparent-statement.cose",
            "other-service-scitt-keys.cbor",
            "fixture-mst.json",
            3,
        ),
        (
            4,
            "missing.cose",
            "mst-test-scitt-keys.cbor",
            "fixture-mst.json",
            4,
        ),
    ] {
        let result = std::env::temp_dir().join(format!(
            "scitt-compact-record-{}-{index}.json",
            std::process::id()
        ));
        let compact = fixture_run(statement, keys, policy, &result, &[]);
        assert_eq!(compact.status.code(), Some(code));
        let record = std::fs::read(&result).unwrap();
        let verbose = fixture_run(statement, keys, policy, &result, &["--verbose"]);
        assert_eq!(verbose.status.code(), Some(code));
        assert_eq!(std::fs::read(&result).unwrap(), record);
        let json = fixture_run(statement, keys, policy, &result, &["--format", "json"]);
        assert_eq!(json.status.code(), Some(code));
        assert_eq!(json.stdout, record);
        assert_eq!(std::fs::read(&result).unwrap(), record);
        let json_verbose = fixture_run(
            statement,
            keys,
            policy,
            &result,
            &["--format", "json", "--verbose"],
        );
        assert_eq!(json_verbose.status.code(), Some(code));
        assert_eq!(json_verbose.stdout, record);
        let _: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        std::fs::remove_file(result).unwrap();
    }
}

#[test]
fn artifact_stage_is_numbered_only_when_requested() {
    let result = std::env::temp_dir().join(format!(
        "scitt-compact-artifact-{}.json",
        std::process::id()
    ));
    let artifact = corpus("fixtures/artifact.bin");
    let output = fixture_run(
        "transparent-statement.cose",
        "mst-test-scitt-keys.cbor",
        "fixture-mst.json",
        &result,
        &[
            "--binding-mode",
            "payload-bytes",
            "--artifact",
            artifact.to_str().unwrap(),
        ],
    );
    std::fs::remove_file(result).unwrap();
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("[3/4] Check artifact binding"));
    assert!(text.contains("[4/4] Evaluate relying-party policy"));
    assert!(text.contains("\nPASS artifact-transparent\n"));
    assert!(!text.contains("artifact binding was not requested"));
    assert!(!text.contains("Artifact binding:"));
}

fn adapter_policy(path: &Path) {
    let mut policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(corpus("policies/azure-confidential-ledger.json")).unwrap(),
    )
    .unwrap();
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(corpus("policies/fixture-mst.json")).unwrap())
            .unwrap();
    policy["assertions"] = fixture["assertions"].clone();
    std::fs::write(path, serde_json::to_vec(&policy).unwrap()).unwrap();
}

#[test]
fn saved_evidence_never_claims_live_authentication_and_skipped_appraisal_is_named() {
    let policy =
        std::env::temp_dir().join(format!("scitt-compact-saved-{}.json", std::process::id()));
    adapter_policy(&policy);
    let output = command("transparent-statement.cose")
        .arg("--policy")
        .arg(&policy)
        .arg("--scitt-keys")
        .arg(corpus("fixtures/mst-test-scitt-keys.cbor"))
        .args([
            "--adapter",
            "azure-confidential-ledger",
            "--binding-mode",
            "saved-evidence",
            "--evidence",
            "missing-bundle",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(policy).unwrap();
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("[4/5] Load saved evidence"), "{text}");
    assert!(text.contains("[5/5] Appraise node evidence"), "{text}");
    assert!(
        text.find("[4/5]").unwrap() < text.find("[5/5]").unwrap(),
        "{text}"
    );
    assert!(text.contains("NOT RUN"), "{text}");
    assert!(
        !text.contains("Connected to authenticated target"),
        "{text}"
    );
    assert!(!text.contains("Resolving service certificate"), "{text}");
    assert!(!text.contains("Check artifact binding"), "{text}");
    assert!(
        text.contains("Scope: No node evidence was appraised."),
        "{text}"
    );
    #[cfg(not(feature = "adapter-azure-confidential-ledger"))]
    assert!(
        text.contains("compiled without the Azure Confidential Ledger adapter"),
        "{text}"
    );
    #[cfg(feature = "adapter-azure-confidential-ledger")]
    assert!(
        text.contains("execution policy could not be read"),
        "{text}"
    );
}

#[test]
fn live_mode_refused_before_network_never_claims_a_connection() {
    let policy =
        std::env::temp_dir().join(format!("scitt-compact-live-{}.json", std::process::id()));
    adapter_policy(&policy);
    let output = command("transparent-statement.cose")
        .arg("--policy")
        .arg(&policy)
        .args([
            "--online",
            "--ledger",
            "not-allowlisted.invalid",
            "--adapter",
            "azure-confidential-ledger",
            "--binding-mode",
            "live-evidence",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(policy).unwrap();
    assert_eq!(output.status.code(), Some(4));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("[4/5] Authenticate target and collect evidence"),
        "{text}"
    );
    assert!(text.contains("[5/5] Appraise node evidence"), "{text}");
    assert!(text.contains("NOT RUN"), "{text}");
    assert!(
        !text.contains("Connected to authenticated target"),
        "{text}"
    );
    assert!(
        !text.contains("Keys acquired through identity-service-backed TLS"),
        "{text}"
    );
}
