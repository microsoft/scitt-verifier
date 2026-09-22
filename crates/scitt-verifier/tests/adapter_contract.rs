//! Optional workflows must never bypass either policy or statement acceptance.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};

fn corpus(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(path)
}

fn statement_policy() -> Value {
    serde_json::from_slice(include_bytes!("../../../corpus/policies/fixture-mst.json")).unwrap()
}

fn adapter_policy() -> Value {
    let mut policy: Value =
        serde_json::from_slice(include_bytes!("../../../corpus/policies/mst-ledger.json")).unwrap();
    policy["assertions"] = statement_policy()["assertions"].clone();
    policy
}

fn run(name: &str, policy: &Value, statement: &str, extra: &[&str]) -> Output {
    let path = std::env::temp_dir().join(format!(
        "scitt-adapter-contract-{}-{name}.json",
        std::process::id()
    ));
    std::fs::write(&path, serde_json::to_vec(policy).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"));
    command
        .arg("verify")
        .arg("--statement")
        .arg(corpus(&format!("fixtures/{statement}")))
        .arg("--policy")
        .arg(&path)
        .arg("--format")
        .arg("json");
    if !extra.contains(&"--online") {
        command
            .arg("--scitt-keys")
            .arg(corpus("fixtures/mst-test-scitt-keys.cbor"));
    }
    let output = command.args(extra).output().unwrap();
    std::fs::remove_file(path).unwrap();
    output
}

fn assert_code(output: &Output, expected: i32) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _: Value = serde_json::from_str(&stdout).expect("JSON stdout remains one document");
    stdout
}

const SAVED: &[&str] = &[
    "--adapter",
    "mst-ledger",
    "--binding-mode",
    "saved-evidence",
    "--evidence",
    "a-bundle-that-does-not-exist",
];

#[test]
fn required_adapter_cannot_be_omitted_offline_or_online() {
    for (name, args) in [("offline", &[][..]), ("online", &["--online"][..])] {
        let output = run(name, &adapter_policy(), "transparent-statement.cose", args);
        let text = assert_code(&output, 4);
        assert!(text.contains("AdapterPolicyMismatch"), "{text}");
        assert!(!text.contains("PolicyMalformed"), "{text}");
    }
}

#[test]
fn selected_adapter_requires_its_own_policy_namespace() {
    let output = run(
        "no-config",
        &statement_policy(),
        "transparent-statement.cose",
        SAVED,
    );
    let text = assert_code(&output, 4);
    assert!(text.contains("AdapterPolicyMismatch"), "{text}");
}

#[test]
fn old_unpublished_adapter_schema_is_not_silently_accepted() {
    let mut policy = statement_policy();
    policy["ledger"] = json!({"host": "example.confidential-ledger.azure.com"});
    let output = run("old-schema", &policy, "transparent-statement.cose", &[]);
    let text = assert_code(&output, 4);
    assert!(text.contains("PolicyMalformed"), "{text}");
}

#[test]
fn failed_receipt_blocks_adapter_even_with_a_valid_statement_signature() {
    let mut policy = adapter_policy();
    // Receipt acceptance must be enforced by the verdict, not an optional assertion.
    policy["assertions"] = json!({"issuer": statement_policy()["assertions"]["issuer"]});
    let output = run("bad-receipt", &policy, "tampered-statement.cose", SAVED);
    let text = assert_code(&output, 3);
    assert!(
        text.contains("adapter evidence was not appraised"),
        "{text}"
    );
    assert!(!text.contains("could not be read"), "{text}");
}

#[test]
fn failed_signature_blocks_adapter() {
    let output = run(
        "bad-signature",
        &adapter_policy(),
        "payload-tampered.cose",
        SAVED,
    );
    let text = assert_code(&output, 1);
    assert!(
        text.contains("adapter evidence was not appraised"),
        "{text}"
    );
}

#[test]
fn adapter_requirements_do_not_replace_statement_acceptance_policy() {
    let mut policy = adapter_policy();
    policy["assertions"] = json!({});
    let output = run(
        "no-statement-rules",
        &policy,
        "transparent-statement.cose",
        SAVED,
    );
    let text = assert_code(&output, 3);
    assert!(
        text.contains("adapter evidence was not appraised"),
        "{text}"
    );
    assert!(!text.contains("PolicyMalformed"), "{text}");
}

#[cfg(not(feature = "adapter-mst-ledger"))]
#[test]
fn valid_adapter_policy_in_an_adapterless_build_is_not_malformed_or_a_pass() {
    let output = run(
        "not-built",
        &adapter_policy(),
        "transparent-statement.cose",
        SAVED,
    );
    let text = assert_code(&output, 3);
    assert!(
        text.contains("compiled without the mst-ledger adapter"),
        "{text}"
    );
    assert!(!text.contains("PolicyMalformed"), "{text}");
}
