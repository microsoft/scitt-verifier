//! Certificate fixtures are synthetic; the registered corpus payload stands
//! in for HBOM bytes, without claiming it is a hardware inventory document.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};

fn corpus(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(file)
}

fn policy() -> Value {
    let roots = std::fs::read_to_string(corpus("fixtures/synthetic-hbom/root.pem")).unwrap();
    let der = scitt_receipt::chain::parse_pem_certificates(&roots).unwrap();
    json!({
        "policyId": "synthetic/certificate-hbom", "policyVersion": "1",
        "assertions": serde_json::from_slice::<Value>(include_bytes!("../../../corpus/policies/fixture-mst.json")).unwrap()["assertions"],
        "adapters": { "certificate-hbom": {
            "source": { "kind": "statement-payload" },
            "rootSha256": scitt_receipt::sha256_hex(&der[0]),
            "leafEku": "1.3.6.1.4.1.55555.1.2",
            "profile": { "oid": "1.3.6.1.4.1.55555.1.1", "digest": "sha384", "encoding": "raw" }
        }}
    })
}

fn run(
    name: &str,
    policy: &Value,
    certificate: &str,
    root: &str,
    statement: &str,
    now: &str,
    select: bool,
) -> Output {
    run_with_flags(
        name,
        policy,
        select.then_some(certificate),
        select.then_some(root),
        statement,
        now,
        select,
    )
}

fn run_with_flags(
    name: &str,
    policy: &Value,
    certificate: Option<&str>,
    root: Option<&str>,
    statement: &str,
    now: &str,
    select: bool,
) -> Output {
    let path = std::env::temp_dir().join(format!("scitt-hbom-{}-{name}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec(policy).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"));
    command
        .args(["verify", "--statement"])
        .arg(corpus(&format!("fixtures/{statement}")))
        .arg("--scitt-keys")
        .arg(corpus("fixtures/mst-test-scitt-keys.cbor"))
        .arg("--policy")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .arg("--now")
        .arg(now);
    if select {
        command.args([
            "--adapter",
            "certificate-hbom",
            "--binding-mode",
            "certificate-hbom",
        ]);
    }
    if let Some(certificate) = certificate {
        command
            .arg("--evidence")
            .arg(corpus(&format!("fixtures/synthetic-hbom/{certificate}")));
    }
    if let Some(root) = root {
        command
            .arg("--certificate-roots")
            .arg(corpus(&format!("fixtures/synthetic-hbom/{root}")));
    }
    let output = command.output().unwrap();
    std::fs::remove_file(path).unwrap();
    output
}

fn assert_result(output: Output, expected: i32, trust: &str, binding: &str) {
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout: {text}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record: Value = serde_json::from_str(&text).unwrap();
    let checks = record["appraisal"]["checks"]["adapter"].as_array().unwrap();
    assert_eq!(checks.len(), 2, "{text}");
    assert_eq!(checks[0]["state"], trust, "{text}");
    assert_eq!(checks[1]["state"], binding, "{text}");
    assert_eq!(checks[0]["name"], "certificate-trust");
    assert_eq!(checks[1]["name"], "hbom-commitment");
}

#[test]
fn passing_json_result_is_scoped_and_discloses_unchecked_hardware_claims() {
    let output = run(
        "scoped-pass",
        &policy(),
        "good.pem",
        "root.pem",
        "transparent-statement.cose",
        "1785197841",
        true,
    );
    assert_eq!(output.status.code(), Some(0));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["evaluatedAt"], 1785197841);
    assert_eq!(result["appraisal"]["verdict"], "resource-transparent");
    assert_eq!(result["appraisal"]["pass"], true);
    assert_eq!(result["relyingPartyPolicy"]["satisfied"], true);
    let checks = result["appraisal"]["checks"]["adapter"].as_array().unwrap();
    assert_eq!(checks.len(), 2);
    assert_eq!(checks[0]["name"], "certificate-trust");
    assert_eq!(checks[0]["state"], "pass");
    assert_eq!(checks[1]["name"], "hbom-commitment");
    assert_eq!(checks[1]["state"], "pass");

    let scope = result["appraisal"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "ResourceAppraisalScoped")
        .expect("passing adapter must publish its scope");
    let message = scope["message"].as_str().unwrap();
    assert!(
        message.contains("offline certificate association"),
        "{message}"
    );
    assert!(
        message.contains("no device possession or workload state verified"),
        "{message}"
    );

    let gaps = result["appraisal"]["notChecked"].as_array().unwrap();
    for code in [
        "DevicePossessionNotChecked",
        "WorkloadStateNotChecked",
        "DeviceCertificateRevocationNotChecked",
    ] {
        assert!(
            gaps.iter().any(|gap| gap["code"] == code),
            "missing {code}: {gaps:?}"
        );
    }
}

#[test]
fn synthetic_certificate_binding_and_failure_modes() {
    let p = policy();
    for (name, cert, root, now, code, trust, binding) in [
        (
            "good",
            "good.pem",
            "root.pem",
            "1785197841",
            0,
            "pass",
            "pass",
        ),
        (
            "mismatch",
            "mismatch.pem",
            "root.pem",
            "1785197841",
            2,
            "pass",
            "fail",
        ),
        (
            "wrong-root",
            "good.pem",
            "untrusted-root.pem",
            "1785197841",
            2,
            "fail",
            "cannot-evaluate",
        ),
        (
            "broken-signature",
            "broken.pem",
            "root.pem",
            "1785197841",
            2,
            "fail",
            "cannot-evaluate",
        ),
        (
            "expired",
            "expired.pem",
            "root.pem",
            "1785197841",
            2,
            "fail",
            "cannot-evaluate",
        ),
        (
            "missing",
            "missing.pem",
            "root.pem",
            "1785197841",
            2,
            "pass",
            "fail",
        ),
        (
            "malformed",
            "malformed.pem",
            "root.pem",
            "1785197841",
            2,
            "pass",
            "fail",
        ),
        (
            "ambiguous",
            "ambiguous.pem",
            "root.pem",
            "1785197841",
            2,
            "fail",
            "cannot-evaluate",
        ),
        (
            "der-as-raw",
            "der-octet.pem",
            "root.pem",
            "1785197841",
            2,
            "pass",
            "fail",
        ),
    ] {
        assert_result(
            run(
                name,
                &p,
                cert,
                root,
                "transparent-statement.cose",
                now,
                true,
            ),
            code,
            trust,
            binding,
        );
    }
}

#[test]
fn explicit_der_encoding_and_pin_are_enforced() {
    let mut p = policy();
    p["adapters"]["certificate-hbom"]["profile"]["encoding"] = json!("der-octet-string");
    assert_result(
        run(
            "der",
            &p,
            "der-octet.pem",
            "root.pem",
            "transparent-statement.cose",
            "1785197841",
            true,
        ),
        0,
        "pass",
        "pass",
    );
    p["adapters"]["certificate-hbom"]["rootSha256"] = json!("00".repeat(32));
    assert_result(
        run(
            "pin",
            &p,
            "der-octet.pem",
            "root.pem",
            "transparent-statement.cose",
            "1785197841",
            true,
        ),
        2,
        "fail",
        "cannot-evaluate",
    );
    p["adapters"]["certificate-hbom"]["rootSha256"] =
        policy()["adapters"]["certificate-hbom"]["rootSha256"].clone();
    p["adapters"]["certificate-hbom"]["leafEku"] = json!("1.2.3.4");
    assert_result(
        run(
            "role",
            &p,
            "der-octet.pem",
            "root.pem",
            "transparent-statement.cose",
            "1785197841",
            true,
        ),
        2,
        "fail",
        "cannot-evaluate",
    );
}

#[test]
fn independently_pinned_unrelated_root_cannot_authenticate_leaf() {
    let unrelated =
        std::fs::read_to_string(corpus("fixtures/synthetic-hbom/untrusted-root.pem")).unwrap();
    let unrelated_der = scitt_receipt::chain::parse_pem_certificates(&unrelated).unwrap();
    let mut p = policy();
    p["adapters"]["certificate-hbom"]["rootSha256"] =
        json!(scitt_receipt::sha256_hex(&unrelated_der[0]));
    let output = run(
        "pinned-unrelated-root",
        &p,
        "good.pem",
        "untrusted-root.pem",
        "transparent-statement.cose",
        "1785197841",
        true,
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2), "{text}");
    let record: Value = serde_json::from_str(&text).unwrap();
    let checks = &record["appraisal"]["checks"]["adapter"];
    assert_eq!(checks[0]["state"], "fail", "{text}");
    assert_eq!(checks[1]["state"], "cannot-evaluate", "{text}");
    assert!(
        checks[0]["detail"]
            .as_str()
            .unwrap()
            .contains("chain ends at"),
        "must reach certificate path validation, not merely fail a pin check: {text}"
    );
}

#[test]
fn missing_evidence_or_roots_flags_are_refused_and_unreadable_files_cannot_pass() {
    let p = policy();
    for (name, cert, root, expected) in [
        (
            "missing-evidence-flag",
            None,
            Some("root.pem"),
            "--evidence",
        ),
        (
            "missing-roots-flag",
            Some("good.pem"),
            None,
            "--certificate-roots",
        ),
    ] {
        let output = run_with_flags(
            name,
            &p,
            cert,
            root,
            "transparent-statement.cose",
            "1785197841",
            true,
        );
        assert_eq!(output.status.code(), Some(4), "{name}");
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
    for (name, cert, root) in [
        ("unreadable-evidence", "no-such.pem", "root.pem"),
        ("unreadable-roots", "good.pem", "no-such.pem"),
    ] {
        assert_result(
            run(
                name,
                &p,
                cert,
                root,
                "transparent-statement.cose",
                "1785197841",
                true,
            ),
            3,
            "cannot-evaluate",
            "cannot-evaluate",
        );
    }
}

#[test]
fn unsupported_profiles_and_missing_selector_are_refused() {
    let mut p = policy();
    p["adapters"]["certificate-hbom"]["profile"]["oid"] = json!("1.3.6.1.4.1.3704.5.2");
    let output = run(
        "unsupported-oid",
        &p,
        "good.pem",
        "root.pem",
        "transparent-statement.cose",
        "1785197841",
        true,
    );
    assert_eq!(output.status.code(), Some(4));
    let mut p = policy();
    p["adapters"]["certificate-hbom"]["profile"]["encoding"] = json!("hex");
    let output = run(
        "unsupported-encoding",
        &p,
        "good.pem",
        "root.pem",
        "transparent-statement.cose",
        "1785197841",
        true,
    );
    assert_eq!(output.status.code(), Some(4));
    let output = run(
        "omitted",
        &policy(),
        "good.pem",
        "root.pem",
        "transparent-statement.cose",
        "1785197841",
        false,
    );
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn unaccepted_statement_never_appraises_certificate() {
    let output = run(
        "tampered",
        &policy(),
        "good.pem",
        "root.pem",
        "payload-tampered.cose",
        "1785197841",
        true,
    );
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("adapter evidence was not appraised"),
        "{text}"
    );
}

#[test]
fn policy_rejection_prevents_certificate_file_access() {
    let mut p = policy();
    p["assertions"]["issuer"] = json!(["unrelated-log.invalid"]);
    let output = run(
        "unaccepted-policy",
        &p,
        "no-such.pem",
        "root.pem",
        "transparent-statement.cose",
        "1785197841",
        true,
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2), "{text}");
    assert!(
        text.contains("adapter evidence was not appraised"),
        "{text}"
    );
    assert!(!text.contains("could not open"), "{text}");
}
