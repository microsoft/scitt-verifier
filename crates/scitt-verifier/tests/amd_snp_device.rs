//! The amd-snp-device adapter through the built binary.
//!
//! The SNP evidence is TEE-Attestation-Verification's public Turin fixture;
//! see `adapters/amd-snp-device/tests/fixtures/README.md`. The corpus
//! hardware BOM statement names that chip, so the binding and every other
//! check pass, but the report carries no nonce: freshness, and with it the
//! run, cannot be established from public bytes alone. A full exit-0 run
//! needs a report collected against a fresh nonce; see the ignored test at
//! the end of this file.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(path)
}

fn snp_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../adapters/amd-snp-device/tests/fixtures")
            .join(name),
    )
    .unwrap()
}

/// A verified statement whose payload is JSON but describes no hardware.
fn statement() -> PathBuf {
    corpus("fixtures/image-reproduction/statement.cose")
}

/// A verified hardware BOM naming the chip that signed the fixture report.
#[cfg(feature = "adapter-amd-snp-device")]
fn hbom_statement() -> PathBuf {
    corpus("fixtures/amd-snp-device/statement.cose")
}

#[cfg(feature = "adapter-amd-snp-device")]
fn hbom_policy() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../corpus/policies/amd-snp-device.json"
    ))
    .unwrap()
}

fn section() -> Value {
    json!({
        "profile": "spdx3-hbom",
        "category": "packaged soc",
        "minimumTcb": [{ "generation": "turin", "reportedTcb": "0x5100000004010101" }]
    })
}

/// The corpus policy that accepts the statement, with its adapter replaced.
fn policy() -> Value {
    let mut policy: Value = serde_json::from_slice(include_bytes!(
        "../../../corpus/policies/image-reproduction.json"
    ))
    .unwrap();
    policy["adapters"] = json!({ "amd-snp-device": section() });
    policy
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("scitt-snpdev-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An evidence directory with the fixture report, VCEK and chain.
fn evidence(name: &str) -> PathBuf {
    let dir = scratch(name).join("evidence");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("report.bin"),
        snp_fixture("turin_attestation_report.bin"),
    )
    .unwrap();
    std::fs::write(dir.join("vcek.der"), snp_fixture("turin_vcek.pem")).unwrap();
    let mut chain = snp_fixture("turin_kds_ask.pem");
    chain.extend(snp_fixture("turin_kds_ark.pem"));
    std::fs::write(dir.join("cert_chain.pem"), chain).unwrap();
    dir
}

const ADAPTER: &[&str] = &[
    "--binding-mode",
    "saved-evidence",
    "--adapter",
    "amd-snp-device",
    "--format",
    "json",
];

fn run(name: &str, policy: &Value, evidence: &Path, adapter: &[&str]) -> (i32, Value) {
    run_on(&statement(), name, policy, evidence, adapter)
}

fn run_on(
    statement: &Path,
    name: &str,
    policy: &Value,
    evidence: &Path,
    adapter: &[&str],
) -> (i32, Value) {
    let policy_path = scratch(&format!("{name}-policy")).join("policy.json");
    std::fs::write(&policy_path, serde_json::to_vec(policy).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"))
        .arg("verify")
        .arg("--statement")
        .arg(statement)
        .arg("--scitt-keys")
        .arg(corpus("fixtures/mst-test-scitt-keys.cbor"))
        .arg("--policy")
        .arg(&policy_path)
        .args(adapter)
        .arg("--evidence")
        .arg(evidence)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let record: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be one JSON record ({e}): {stdout}"));
    (output.status.code().unwrap(), record)
}

fn state_of(record: &Value, name: &str) -> String {
    record["appraisal"]["checks"]["adapter"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} check in {record}"))["state"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The report authenticates, but the statement names no device, so the run
/// fails rather than binding the chip to nothing.
#[cfg(feature = "adapter-amd-snp-device")]
#[test]
fn a_statement_that_names_no_device_fails_even_with_a_genuine_report() {
    let (code, record) = run("no-device", &policy(), &evidence("no-device"), ADAPTER);
    assert_eq!(code, 2, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "resource-failed");
    assert_eq!(record["artifactBinding"]["adapter"], "amd-snp-device");
    assert_eq!(state_of(&record, "device-claim"), "fail");
    assert_eq!(state_of(&record, "snp-report"), "pass");
    assert_eq!(state_of(&record, "tcb-floor"), "pass");
    // No nonce was supplied, so freshness cannot be established.
    assert_eq!(state_of(&record, "freshness"), "cannot-evaluate");
    assert_eq!(state_of(&record, "device-binding"), "cannot-evaluate");
    let gaps = record["appraisal"]["notChecked"].to_string();
    assert!(gaps.contains("GuestMeasurementNotAppraised"), "{gaps}");
    assert!(
        gaps.contains("AmdCertificateRevocationNotChecked"),
        "{gaps}"
    );
}

/// The statement names the chip that signed the report, and the report
/// authenticates and meets the floor, so the binding holds. Without a nonce
/// the report could be a replay, so the run still cannot pass.
#[cfg(feature = "adapter-amd-snp-device")]
#[test]
fn a_matching_device_binds_but_without_a_nonce_is_not_fresh() {
    let (code, record) = run_on(
        &hbom_statement(),
        "bound",
        &hbom_policy(),
        &evidence("bound"),
        ADAPTER,
    );
    assert_eq!(code, 3, "{record}");
    for check in ["statementSignature", "receiptInclusion", "policy"] {
        assert_eq!(record["appraisal"]["checks"][check], "pass", "{record}");
    }
    assert_eq!(record["appraisal"]["verdict"], "cannot-evaluate");
    for name in ["device-claim", "snp-report", "tcb-floor", "device-binding"] {
        assert_eq!(state_of(&record, name), "pass", "{name}: {record}");
    }
    assert_eq!(state_of(&record, "freshness"), "cannot-evaluate");
}

/// The fixture report was not produced for this nonce, so it is stale.
#[cfg(feature = "adapter-amd-snp-device")]
#[test]
fn a_report_that_does_not_carry_the_nonce_fails() {
    let evidence = evidence("stale");
    std::fs::write(
        evidence.join("nonce.hex"),
        "1111111111111111111111111111111122222222222222222222222222222222",
    )
    .unwrap();
    let (code, record) = run_on(
        &hbom_statement(),
        "stale",
        &hbom_policy(),
        &evidence,
        ADAPTER,
    );
    assert_eq!(code, 2, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "resource-failed");
    assert_eq!(state_of(&record, "freshness"), "fail");
    assert_eq!(state_of(&record, "device-binding"), "pass");
}

/// A build without the adapter answers every check cannot-evaluate.
#[cfg(not(feature = "adapter-amd-snp-device"))]
#[test]
fn a_build_without_the_adapter_cannot_evaluate() {
    let (code, record) = run("no-feature", &policy(), &evidence("no-feature"), ADAPTER);
    assert_eq!(code, 3, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "cannot-evaluate");
    for name in [
        "device-claim",
        "snp-report",
        "tcb-floor",
        "freshness",
        "device-binding",
    ] {
        assert_eq!(state_of(&record, name), "cannot-evaluate", "{name}");
    }
}

#[test]
fn missing_evidence_is_never_a_pass() {
    // An unreadable directory stops before anything is appraised.
    let (code, record) = run(
        "no-dir",
        &policy(),
        &scratch("no-dir").join("absent"),
        ADAPTER,
    );
    assert_eq!(code, 3, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "cannot-evaluate");

    // An empty one leaves the report unauthenticated. This statement names no
    // device, so with the adapter built the claim fails as well.
    let empty = scratch("empty").join("evidence");
    std::fs::create_dir_all(&empty).unwrap();
    let (code, record) = run("empty", &policy(), &empty, ADAPTER);
    assert_ne!(code, 0, "{record}");
    assert_eq!(record["appraisal"]["pass"], false);
    assert_eq!(state_of(&record, "snp-report"), "cannot-evaluate");
    assert_eq!(state_of(&record, "device-binding"), "cannot-evaluate");
}

#[test]
fn the_adapter_has_no_live_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"))
        .args([
            "verify",
            "--statement",
            "s.cose",
            "--online",
            "--policy",
            "p.json",
            "--binding-mode",
            "live-evidence",
            "--adapter",
            "amd-snp-device",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("collected on the device"));
}

#[test]
fn a_policy_requiring_this_adapter_cannot_be_run_without_it() {
    let (code, record) = run(
        "omitted",
        &policy(),
        &evidence("omitted"),
        &[
            "--format",
            "json",
            "--binding-mode",
            "saved-evidence",
            "--adapter",
            "image-reproduction",
        ],
    );
    assert_eq!(code, 4, "{record}");
    assert!(record.to_string().contains("AdapterPolicyMismatch"));
}

#[test]
fn a_policy_configuring_two_adapters_is_refused() {
    let mut policy = policy();
    let other: Value = serde_json::from_slice(include_bytes!(
        "../../../corpus/policies/image-reproduction.json"
    ))
    .unwrap();
    policy["adapters"]["image-reproduction"] = other["adapters"]["image-reproduction"].clone();
    let (code, record) = run("two", &policy, &evidence("two"), ADAPTER);
    assert_eq!(code, 4, "{record}");
    assert!(record
        .to_string()
        .contains("split it into one policy per adapter"));
}

/// The whole chain on real hardware: a registered BOM naming the chip, and a
/// report the guest produced for a fresh nonce (see `docs/adapters.md`).
#[cfg(feature = "adapter-amd-snp-device")]
#[test]
#[ignore = "requires a registered BOM and a report collected for a fresh nonce; set SCITT_SNPDEV_E2E_DIR"]
fn genuine_device_and_fresh_report_exit_zero() {
    let dir = PathBuf::from(std::env::var_os("SCITT_SNPDEV_E2E_DIR").expect(
        "set SCITT_SNPDEV_E2E_DIR to a directory with statement.cose, policy.json, keys.cbor \
         and evidence/ (report.bin, vcek.der, cert_chain.pem, nonce.hex)",
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"))
        .arg("verify")
        .arg("--statement")
        .arg(dir.join("statement.cose"))
        .arg("--scitt-keys")
        .arg(dir.join("keys.cbor"))
        .arg("--policy")
        .arg(dir.join("policy.json"))
        .args(ADAPTER)
        .arg("--evidence")
        .arg(dir.join("evidence"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let record: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(record["appraisal"]["verdict"], "resource-transparent");
    for name in [
        "device-claim",
        "snp-report",
        "tcb-floor",
        "freshness",
        "device-binding",
    ] {
        assert_eq!(state_of(&record, name), "pass", "{name}: {record}");
    }
    assert!(!record["appraisal"]["notChecked"]
        .as_array()
        .unwrap()
        .is_empty());
}
