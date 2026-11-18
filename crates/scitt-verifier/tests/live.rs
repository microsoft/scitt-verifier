//! Opt-in CLI coverage using real receipts from corpus/tools/seed_ledger.py.
//! Set SCITT_LIVE_CORPUS to its output, then run this target with --ignored.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus");
    path.extend(parts);
    path
}

fn live_corpus() -> PathBuf {
    std::env::var_os("SCITT_LIVE_CORPUS")
        .map(PathBuf::from)
        .expect("set SCITT_LIVE_CORPUS to the seed_ledger.py output directory")
}

fn verify(statement: &Path, policy: &str, extra: &[&std::ffi::OsStr]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"))
        .arg("verify")
        .arg("--statement")
        .arg(statement)
        .arg("--policy")
        .arg(corpus(&["policies", policy]))
        .args(["--format", "json"])
        .args(extra)
        .output()
        .expect("binary must run");
    let record = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "expected JSON ({error}); stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (
        output.status.code().expect("process must exit normally"),
        record,
    )
}

#[test]
#[ignore = "requires a seeded live ledger; set SCITT_LIVE_CORPUS"]
fn fresh_receipts_verify_online_and_with_saved_keys() {
    let live = live_corpus();
    let statement = live.join("transparent-statement.cose");
    let keys = live.join("mst-test-scitt-keys.cbor");
    for extra in [
        vec!["--online".as_ref()],
        vec!["--scitt-keys".as_ref(), keys.as_os_str()],
    ] {
        let (code, record) = verify(&statement, "fixture-mst.json", &extra);
        assert_eq!(code, 0, "{record}");
        assert_eq!(record["appraisal"]["verdict"], "statement-transparent");
        let mut with_artifact = extra;
        let artifact = live.join("artifact.bin");
        with_artifact.extend([
            "--binding-mode".as_ref(),
            "payload-bytes".as_ref(),
            "--artifact".as_ref(),
            artifact.as_os_str(),
        ]);
        let (code, record) = verify(&statement, "fixture-mst.json", &with_artifact);
        assert_eq!(code, 0, "{record}");
        assert_eq!(record["appraisal"]["verdict"], "artifact-transparent");
    }
    for name in [
        "cbor-header.cose",
        "nested-sign1.cose",
        "image-reproduction/statement.cose",
        "amd-snp-device/statement.cose",
    ] {
        let (code, record) = verify(
            &live.join(name),
            "minimal.json",
            &["--scitt-keys".as_ref(), keys.as_os_str()],
        );
        assert_eq!(code, 0, "{name}: {record}");
        assert_eq!(record["appraisal"]["verdict"], "statement-transparent");
    }
    let (code, record) = verify(
        &live.join("image-reproduction").join("statement.cose"),
        "image-reproduction.json",
        &[
            "--online".as_ref(),
            "--binding-mode".as_ref(),
            "saved-evidence".as_ref(),
            "--adapter".as_ref(),
            "image-reproduction".as_ref(),
            "--evidence".as_ref(),
            live.join("image-reproduction").as_os_str(),
        ],
    );
    assert_eq!(code, 0, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "resource-transparent");
}

#[test]
#[ignore = "requires real receipts from seed_ledger.py; set SCITT_LIVE_CORPUS"]
fn fresh_receipts_preserve_refusals_and_appended_receipt_semantics() {
    let live = live_corpus();
    let keys = live.join("mst-test-scitt-keys.cbor");
    for (name, policy, expected_code, verdict) in [
        (
            "tampered-statement.cose",
            "fixture-mst.json",
            3,
            "cannot-evaluate",
        ),
        ("payload-tampered.cose", "fixture-mst.json", 1, "untrusted"),
        (
            "appended-receipt.cose",
            "fixture-mst-unpinned-count.json",
            0,
            "statement-transparent",
        ),
        (
            "appended-receipt.cose",
            "fixture-mst.json",
            2,
            "policy-failed",
        ),
    ] {
        let (code, record) = verify(
            &live.join(name),
            policy,
            &["--scitt-keys".as_ref(), keys.as_os_str()],
        );
        assert_eq!(code, expected_code, "{name}: {record}");
        assert_eq!(record["appraisal"]["verdict"], verdict, "{name}: {record}");
    }
    let (code, record) = verify(
        &live.join("transparent-statement.cose"),
        "fixture-mst.json",
        &[
            "--scitt-keys".as_ref(),
            keys.as_os_str(),
            "--binding-mode".as_ref(),
            "payload-bytes".as_ref(),
            "--artifact".as_ref(),
            live.join("bad-artifact.bin").as_os_str(),
        ],
    );
    assert_eq!(code, 1, "{record}");
    assert_eq!(record["appraisal"]["verdict"], "untrusted");
}

#[test]
#[ignore = "requires receipts from a recreated ledger; set SCITT_LIVE_CORPUS"]
fn a_recreated_ledger_does_not_authenticate_its_predecessors_receipts() {
    let keys = live_corpus().join("mst-test-scitt-keys.cbor");
    let historical_keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
    assert_ne!(
        std::fs::read(&keys).unwrap(),
        std::fs::read(&historical_keys).unwrap(),
        "this test requires a new service identity"
    );
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    for extra in [
        vec!["--online".as_ref()],
        vec!["--scitt-keys".as_ref(), keys.as_os_str()],
    ] {
        let (code, record) = verify(&statement, "fixture-mst.json", &extra);
        assert_eq!(code, 3, "{record}");
        assert_eq!(record["appraisal"]["verdict"], "cannot-evaluate");
        assert!(
            record["appraisal"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|diagnostic| diagnostic["code"] == "ReceiptKeyUnknown"),
            "an acquisition failure is not proof of identity separation: {record}"
        );
        if record.get("acquisition").is_some() {
            assert_eq!(record["acquisition"]["ledgers"][0]["acquired"], true);
        }
    }
}
