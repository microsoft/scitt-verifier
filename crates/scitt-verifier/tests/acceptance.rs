//! Acceptance tests over the built binary.
//!
//! These pin the *contract*, not the implementation: exit codes, refusals, and
//! the presence of the honesty fields in the evidence record. A pipeline
//! branches on these numbers, so changing one is a breaking change.

use std::path::PathBuf;
use std::process::Command;

fn corpus(parts: &[&str]) -> String {
    let mut path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "corpus"]
        .iter()
        .collect();
    for part in parts {
        path.push(part);
    }
    path.display().to_string()
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_scitt-verifier"))
        .args(args)
        .output()
        .expect("binary must run");
    Run {
        code: output.status.code().expect("process must exit normally"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn verify(extra: &[&str]) -> Run {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-july-scitt-keys.cbor"]);
    let policy = corpus(&["policies", "fixture-mst.json"]);
    let mut args = vec![
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy,
    ];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn a_genuine_statement_exits_zero() {
    let r = verify(&[]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("Verdict: verified"));
}

#[test]
fn a_tampered_payload_exits_one() {
    let statement = corpus(&["fixtures", "payload-tampered.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-july-scitt-keys.cbor"]);
    let policy = corpus(&["policies", "fixture-mst.json"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy,
    ]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(r.stdout.contains("untrusted"));
}

#[test]
fn stale_trust_material_exits_three_not_one() {
    // The distinction this test defends: a rotated signing key must not be
    // reported with the same exit code as a forged artifact. One is an
    // operational chore; the other is an incident.
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "stale-scitt-keys.cbor"]);
    let policy = corpus(&["policies", "fixture-mst.json"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy,
    ]);
    assert_eq!(r.code, 3, "{}", r.stdout);
    assert!(r.stdout.contains("This is not a pass"));
}

#[test]
fn a_policy_that_rejects_the_issuer_exits_two() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-july-scitt-keys.cbor"]);
    let policy = corpus(&["policies", "wrong-issuer.json"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy,
    ]);
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(r.stdout.contains("policyFailed"));
}

/// Fixtures must survive checkout byte-for-byte.
///
/// `artifact.bin` is pure ASCII ending in CRLF, so without the `*.bin binary`
/// rule in `.gitattributes` git classifies it as text and silently rewrites the
/// line ending on platforms with `core.autocrlf`. That drops one byte, the
/// payload no longer matches, and the failure surfaces as a confusing binding
/// error rather than a corrupted checkout. Fail loudly and specifically here.
#[test]
fn fixtures_are_byte_exact() {
    for (name, expected) in [
        ("artifact.bin", 21usize),
        ("bad-artifact.bin", 20),
        ("transparent-statement.cose", 9270),
        ("tampered-statement.cose", 9270),
        ("payload-tampered.cose", 9270),
        ("musa-mst-july-scitt-keys.cbor", 1219),
        ("stale-scitt-keys.cbor", 523),
    ] {
        let bytes = std::fs::read(corpus(&["fixtures", name]))
            .unwrap_or_else(|e| panic!("fixture {name} must be readable: {e}"));
        assert_eq!(
            bytes.len(),
            expected,
            "fixture {name} is {} bytes, expected {expected}. The checkout \
             transformed it — check .gitattributes and core.autocrlf.",
            bytes.len()
        );
    }

    assert_eq!(
        std::fs::read(corpus(&["fixtures", "artifact.bin"])).unwrap(),
        b"Hello from MST Team\r\n",
        "artifact.bin must keep its CRLF; the statement signs these exact bytes"
    );
}

#[test]
fn a_matching_artifact_binds() {
    let artifact = corpus(&["fixtures", "artifact.bin"]);
    let r = verify(&["--artifact", &artifact, "--binding-mode", "payload-bytes"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.stdout.contains("byte-identical"));
}

#[test]
fn a_different_artifact_exits_one() {
    // The statement is genuine and the receipt is genuine. What is wrong is
    // that they are not about this file — which is exactly the failure a
    // signature-only check cannot see.
    let artifact = corpus(&["fixtures", "bad-artifact.bin"]);
    let r = verify(&["--artifact", &artifact, "--binding-mode", "payload-bytes"]);
    assert_eq!(r.code, 1, "{}", r.stdout);
}

#[test]
fn an_unknown_option_exits_four() {
    let r = verify(&["--assume-good"]);
    assert_eq!(r.code, 4);
    assert!(r.stderr.contains("unknown option"));
}

#[test]
fn a_missing_policy_exits_four() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-july-scitt-keys.cbor"]);
    let r = run(&["verify", "--statement", &statement, "--scitt-keys", &keys]);
    assert_eq!(r.code, 4);
    assert!(r.stderr.contains("--policy is required"));
}

#[test]
fn an_unimplemented_binding_mode_is_refused() {
    let artifact = corpus(&["fixtures", "artifact.bin"]);
    let r = verify(&["--artifact", &artifact, "--binding-mode", "payload-digest"]);
    assert_eq!(r.code, 4);
    assert!(r.stderr.contains("not implemented"), "{}", r.stderr);
}

#[test]
fn an_artifact_that_would_be_ignored_is_refused() {
    let artifact = corpus(&["fixtures", "artifact.bin"]);
    let r = verify(&["--artifact", &artifact]);
    assert_eq!(r.code, 4);
    assert!(r.stderr.contains("ignored"), "{}", r.stderr);
}

#[test]
fn evidence_records_what_was_not_checked() {
    let dir = std::env::temp_dir().join("scitt-verifier-acceptance");
    std::fs::create_dir_all(&dir).unwrap();
    let evidence = dir.join("evidence.json");
    let evidence_str = evidence.display().to_string();

    let r = verify(&["--evidence", &evidence_str, "--format", "json"]);
    assert_eq!(r.code, 0, "{}", r.stdout);

    let written = std::fs::read_to_string(&evidence).unwrap();
    let value: serde_json::Value = serde_json::from_str(&written).unwrap();

    assert_eq!(value["verdict"], "verified");
    assert_eq!(value["exitCode"], 0);
    assert_eq!(value["schemaVersion"], "scitt-verifier/evidence/v1");
    assert_eq!(value["artifactBinding"]["mode"], "none");

    // A green run must still say what it did not establish.
    let gaps = value["notChecked"]
        .as_array()
        .expect("notChecked must be present");
    assert!(
        !gaps.is_empty(),
        "a passing run must still declare its gaps"
    );
    assert!(
        gaps.iter()
            .any(|g| g.as_str().unwrap().contains("artifact binding")),
        "unbound runs must say so: {gaps:?}"
    );
    assert!(
        gaps.iter()
            .any(|g| g.as_str().unwrap().contains("trusted root")),
        "chain validation gap must be declared: {gaps:?}"
    );

    let _ = std::fs::remove_file(&evidence);
}

#[test]
fn json_output_is_parseable() {
    let r = verify(&["--format", "json"]);
    assert_eq!(r.code, 0);
    serde_json::from_str::<serde_json::Value>(&r.stdout).expect("stdout must be valid JSON");
}

#[test]
fn now_is_overridable_for_reproducible_runs() {
    let a = verify(&["--now", "1700000000", "--format", "json"]);
    let b = verify(&["--now", "1700000000", "--format", "json"]);
    assert_eq!(
        a.stdout, b.stdout,
        "identical inputs must produce identical output"
    );
}

#[test]
fn inspect_never_gates() {
    let statement = corpus(&["fixtures", "payload-tampered.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    assert_eq!(r.code, 0, "inspect reports; it does not judge");
    assert!(r.stdout.contains("does not verify anything"));
}

#[test]
fn help_and_version_succeed() {
    assert_eq!(run(&["--help"]).code, 0);
    assert_eq!(run(&["--version"]).code, 0);
}
