//! The image-reproduction adapter through the built binary.
//!
//! The statement is minted and registered on the corpus ledger; the records
//! are scitt-ccf-ledger's published 0.20.1 reproduction record and that
//! release rebuilt on its own CI runners. See `corpus/README.md`.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(path)
}

const DIR: &str = "fixtures/image-reproduction";

fn policy() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../corpus/policies/image-reproduction.json"
    ))
    .unwrap()
}

fn published() -> Vec<u8> {
    std::fs::read(corpus(&format!("{DIR}/published-reproduce.json"))).unwrap()
}

fn rebuilt() -> Vec<u8> {
    std::fs::read(corpus(&format!("{DIR}/rebuilt-reproduce.json"))).unwrap()
}

/// A scratch directory unique to one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("scitt-image-repro-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An evidence directory holding the given records; `None` leaves one out.
fn evidence(name: &str, published: Option<&[u8]>, rebuilt: Option<&[u8]>) -> PathBuf {
    let dir = scratch(name).join("evidence");
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(bytes) = published {
        std::fs::write(dir.join("published-reproduce.json"), bytes).unwrap();
    }
    if let Some(bytes) = rebuilt {
        std::fs::write(dir.join("rebuilt-reproduce.json"), bytes).unwrap();
    }
    dir
}

fn edited(bytes: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    edit(&mut value);
    serde_json::to_vec_pretty(&value).unwrap()
}

struct Run {
    code: i32,
    stdout: String,
}

fn run_with(name: &str, policy: &Value, statement: &Path, evidence: &Path, extra: &[&str]) -> Run {
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
        .args(extra)
        .arg("--evidence")
        .arg(evidence)
        .output()
        .unwrap();
    Run {
        code: output.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    }
}

const ADAPTER: &[&str] = &[
    "--binding-mode",
    "saved-evidence",
    "--adapter",
    "image-reproduction",
];

fn run_json(name: &str, policy: &Value, evidence: &Path) -> (i32, Value) {
    let mut args = ADAPTER.to_vec();
    args.extend(["--format", "json"]);
    let run = run_with(
        name,
        policy,
        &corpus(&format!("{DIR}/statement.cose")),
        evidence,
        &args,
    );
    let record: Value = serde_json::from_str(&run.stdout)
        .unwrap_or_else(|e| panic!("stdout must be one JSON record ({e}): {}", run.stdout));
    (run.code, record)
}

fn check_states(record: &Value) -> Vec<(String, String)> {
    record["appraisal"]["checks"]["adapter"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap().to_string(),
                c["state"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn state_of(record: &Value, name: &str) -> String {
    check_states(record)
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no {name} check in {record}"))
        .1
}

#[test]
fn fixtures_are_byte_exact() {
    // The record is authenticated by the SHA-256 of these exact bytes; a
    // checkout that rewrote line endings would break the binding silently.
    for (name, expected) in [
        ("statement.cose", 2760usize),
        ("published-reproduce.json", 1033),
        ("rebuilt-reproduce.json", 1033),
    ] {
        let len = std::fs::read(corpus(&format!("{DIR}/{name}")))
            .unwrap()
            .len();
        assert_eq!(len, expected, "{name} was transformed by the checkout");
    }
}

#[test]
fn the_real_rebuild_of_the_real_release_is_resource_transparent() {
    let (code, record) = run_json("pass", &policy(), &corpus(DIR));
    assert_eq!(code, 0, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "resource-transparent");
    assert_eq!(record["artifactBinding"]["adapter"], "image-reproduction");
    assert_eq!(
        check_states(&record),
        [
            "reproduction-claim",
            "source-repository",
            "record-binding",
            "rebuild-inputs",
            "rebuild-layers"
        ]
        .map(|n| (n.to_string(), "pass".to_string()))
    );
    // The scope is published with the pass, so it survives being quoted.
    let scoped = record["appraisal"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "ResourceAppraisalScoped")
        .expect("a pass carries its scope");
    assert!(
        scoped["message"]
            .as_str()
            .unwrap()
            .contains("operator-asserted"),
        "{scoped}"
    );
}

#[test]
fn the_text_verdict_states_its_scope() {
    let run = run_with(
        "text",
        &policy(),
        &corpus(&format!("{DIR}/statement.cose")),
        &corpus(DIR),
        ADAPTER,
    );
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert!(
        run.stdout.contains("PASS resource-transparent"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("not an independent rebuild"),
        "{}",
        run.stdout
    );
}

#[test]
fn input_drift_fails_and_is_reported_apart_from_the_layers() {
    let rebuilt = edited(&rebuilt(), |v| {
        v["base_image"] = json!("example.invalid/base@sha256:0000");
    });
    let dir = evidence("drift", Some(&published()), Some(&rebuilt));
    let (code, record) = run_json("drift", &policy(), &dir);
    assert_eq!(code, 2, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "resource-failed");
    assert_eq!(state_of(&record, "rebuild-inputs"), "fail");
    assert_eq!(state_of(&record, "rebuild-layers"), "pass");
    let finding = &record["appraisal"]["adapterFindings"][0];
    assert_eq!(finding["subject"], "base_image");
    assert_eq!(finding["observed"], "example.invalid/base@sha256:0000");
}

#[test]
fn reordered_layers_fail() {
    let rebuilt = edited(&rebuilt(), |v| {
        v["layers"].as_array_mut().unwrap().reverse();
    });
    let dir = evidence("reordered", Some(&published()), Some(&rebuilt));
    let (code, record) = run_json("reordered", &policy(), &dir);
    assert_eq!(code, 2, "{record}");
    assert_eq!(state_of(&record, "rebuild-inputs"), "pass");
    assert_eq!(state_of(&record, "rebuild-layers"), "fail");
}

#[test]
fn a_record_other_than_the_committed_one_fails() {
    // Well-formed, same commit and version, but not the bytes the statement
    // commits to.
    let other = edited(&published(), |v| {
        v["tdnf_snapshottime"] = json!("1");
    });
    let dir = evidence("wrong-record", Some(&other), Some(&other));
    let (code, record) = run_json("wrong-record", &policy(), &dir);
    assert_eq!(code, 2, "{record}");
    assert_eq!(state_of(&record, "record-binding"), "fail");
    assert_eq!(state_of(&record, "rebuild-layers"), "cannot-evaluate");
}

#[test]
fn missing_evidence_is_cannot_evaluate_never_a_pass() {
    for (name, dir) in [
        (
            "no-rebuild",
            evidence("no-rebuild", Some(&published()), None),
        ),
        ("no-record", evidence("no-record", None, Some(&rebuilt()))),
        ("no-dir", scratch("no-dir").join("absent")),
    ] {
        let (code, record) = run_json(name, &policy(), &dir);
        assert_eq!(code, 3, "{name}: {record}");
        assert_eq!(record["appraisal"]["verdict"], "cannot-evaluate", "{name}");
    }
}

#[test]
fn a_source_repository_the_policy_does_not_allow_fails() {
    let mut policy = policy();
    policy["adapters"]["image-reproduction"]["sourceRepository"] =
        json!("https://github.com/example/other");
    let (code, record) = run_json("repository", &policy, &corpus(DIR));
    assert_eq!(code, 2, "{record}");
    assert_eq!(state_of(&record, "source-repository"), "fail");
}

#[test]
fn a_statement_for_another_component_fails() {
    for (key, value) in [("app", "other"), ("variant", "debug")] {
        let mut policy = policy();
        policy["adapters"]["image-reproduction"]["component"][key] = json!(value);
        let (code, record) = run_json(key, &policy, &corpus(DIR));
        assert_eq!(code, 2, "{key}: {record}");
        assert_eq!(state_of(&record, "reproduction-claim"), "fail", "{key}");
    }
}

#[test]
fn an_unsupported_profile_cannot_be_evaluated() {
    let mut policy = policy();
    policy["adapters"]["image-reproduction"]["profile"] = json!("example/unknown-v9");
    let (code, record) = run_json("profile", &policy, &corpus(DIR));
    assert_eq!(code, 3, "{record}");
    assert!(check_states(&record)
        .iter()
        .all(|(_, state)| state == "cannot-evaluate"));
}

#[test]
fn a_statement_that_fails_verification_never_reaches_the_adapter() {
    // Flip one byte inside the signed payload: the signature no longer holds.
    let mut statement = std::fs::read(corpus(&format!("{DIR}/statement.cose"))).unwrap();
    let needle = b"reproduction-record-sha256";
    let at = statement
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the payload names its record digest");
    statement[at] ^= 0x01;
    let path = scratch("tampered").join("statement.cose");
    std::fs::write(&path, statement).unwrap();

    let mut args = ADAPTER.to_vec();
    args.extend(["--format", "json"]);
    let run = run_with("tampered", &policy(), &path, &corpus(DIR), &args);
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert!(
        run.stdout.contains("adapter evidence was not appraised"),
        "{}",
        run.stdout
    );
}

#[test]
fn hostile_text_in_a_rebuild_record_is_escaped() {
    let rebuilt = edited(&rebuilt(), |v| {
        v["base_image"] = json!("x\r\nPASS resource-transparent\u{1b}[32m");
    });
    let dir = evidence("hostile", Some(&published()), Some(&rebuilt));
    for verbose in [false, true] {
        let mut args = ADAPTER.to_vec();
        if verbose {
            args.push("--verbose");
        }
        let run = run_with(
            "hostile",
            &policy(),
            &corpus(&format!("{DIR}/statement.cose")),
            &dir,
            &args,
        );
        assert_eq!(run.code, 2, "{}", run.stdout);
        assert!(!run.stdout.contains('\u{1b}'), "{}", run.stdout);
        assert!(
            !run.stdout
                .lines()
                .any(|l| l.starts_with("PASS resource-transparent")),
            "{}",
            run.stdout
        );
    }
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
            "image-reproduction",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no live evidence"));
}

#[test]
fn a_policy_requiring_this_adapter_cannot_be_run_without_it() {
    let run = run_with(
        "omitted",
        &policy(),
        &corpus(&format!("{DIR}/statement.cose")),
        &corpus(DIR),
        &[
            "--format",
            "json",
            "--binding-mode",
            "saved-evidence",
            "--adapter",
            "azure-confidential-ledger",
        ],
    );
    assert_eq!(run.code, 4, "{}", run.stdout);
    assert!(
        run.stdout.contains("AdapterPolicyMismatch"),
        "{}",
        run.stdout
    );
}

#[test]
fn a_policy_configuring_two_adapters_is_refused() {
    let mut policy = policy();
    let ledger: Value = serde_json::from_slice(include_bytes!(
        "../../../corpus/policies/azure-confidential-ledger.json"
    ))
    .unwrap();
    policy["adapters"]["azure-confidential-ledger"] =
        ledger["adapters"]["azure-confidential-ledger"].clone();
    let (code, record) = run_json("two", &policy, &corpus(DIR));
    assert_eq!(code, 4, "{record}");
    assert!(record
        .to_string()
        .contains("split it into one policy per adapter"));
}
