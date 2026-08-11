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
fn a_genuine_statement_without_an_artifact_is_only_statement_transparent() {
    // The distinction this test defends: a run that never looked at an
    // artifact must not print the same word as one that did.
    let r = verify(&[]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.starts_with("PASS statement-transparent"),
        "the decision must be the first thing on screen: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("artifact binding was not requested"),
        "an unbound pass must say so: {}",
        r.stdout
    );
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

/// A broken receipt beside a good one must not deny the gate.
///
/// Receipts ride in the statement's *unprotected* header, which no signature
/// covers, so anyone who handles the file — a mirror, a registry, a CI cache —
/// can append one without holding any key. If a broken receipt could flip the
/// verdict, every courier would hold a veto over the gate, and the operator
/// would be told "do not deploy this artifact" about an artifact that is fine.
///
/// RFC 9943 s7.1 sets the bar at "at least one Issuer of a Receipt" and lets a
/// Relying Party verify a single acceptable Receipt and disregard the rest.
/// Transparency is a positive proof; noise appended beside it cannot retract it.
#[test]
fn an_appended_broken_receipt_does_not_deny_the_gate() {
    let statement = corpus(&["fixtures", "appended-receipt.cose"]);
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
    assert_eq!(
        r.code, 0,
        "a genuine receipt still verifies, so the gate must pass:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.starts_with("PASS statement-transparent"),
        "{}",
        r.stdout
    );
    // Passing is not the same as staying silent. The junk receipt is still
    // reported, because a file that grew a receipt in transit is worth knowing
    // about even when it changes nothing.
    assert!(
        r.stdout.contains("ReceiptRootSignatureInvalid"),
        "the disregarded receipt must still be reported: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("Do not deploy"),
        "a broken receipt says nothing about the artifact and must not be \
         described as though it did: {}",
        r.stdout
    );
}

/// When nothing verifies, the answer is "could not tell", not "untrusted".
///
/// `tampered-statement.cose` carries a valid Issuer signature and one receipt
/// whose Merkle root signature does not verify. Nothing here indicts the
/// artifact: the bytes are exactly what the Issuer signed. What is missing is
/// proof that they were ever registered, and an unproven claim is not a
/// disproven one.
#[test]
fn a_statement_whose_only_receipt_fails_exits_three_not_one() {
    let statement = corpus(&["fixtures", "tampered-statement.cose"]);
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
    assert_eq!(
        r.code, 3,
        "no verified receipt means the transparency question is open, not \
         answered in the negative:\n{}",
        r.stdout
    );
    assert!(r.stdout.contains("cannot-evaluate"), "{}", r.stdout);
    assert!(
        r.stdout.contains("NoVerifiedReceipt"),
        "the run must name why it could not decide: {}",
        r.stdout
    );
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
    assert!(
        r.stdout.contains("ReceiptKeyUnknown"),
        "stale keys must be named, not left for the reader to infer: {}",
        r.stdout
    );
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
    assert!(r.stdout.starts_with("STOP policy-failed"));
    assert!(
        r.stdout.contains("PolicyAssertionFailed"),
        "a policy failure must name the assertion that stopped it: {}",
        r.stdout
    );
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
        ("appended-receipt.cose", 10074),
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
    assert!(
        r.stdout.starts_with("PASS artifact-transparent"),
        "a bound run must claim the artifact, not just the statement: {}",
        r.stdout
    );
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
fn the_record_says_what_was_not_checked() {
    let dir = std::env::temp_dir().join("scitt-verifier-acceptance");
    std::fs::create_dir_all(&dir).unwrap();
    let result = dir.join("result.json");
    let result_str = result.display().to_string();
    let facts = dir.join("facts.json");
    let facts_str = facts.display().to_string();

    let r = verify(&[
        "--result",
        &result_str,
        "--facts",
        &facts_str,
        "--format",
        "json",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);

    let written = std::fs::read_to_string(&result).unwrap();
    let value: serde_json::Value = serde_json::from_str(&written).unwrap();

    assert_eq!(value["schemaVersion"], "scitt-verifier/result/v0");
    assert_eq!(value["appraisal"]["verdict"], "statement-transparent");
    assert_eq!(value["appraisal"]["exitCode"], 0);
    assert_eq!(value["artifactBinding"]["mode"], "none");
    assert!(
        value["appraisal"]["primaryDiagnostic"].is_null(),
        "a pass has nothing that stopped it"
    );

    // Trust provenance is first-class, not prose. A consumer must be able to
    // query for runs that trusted an unsigned key set.
    assert_eq!(value["trust"]["mode"], "unsigned-scitt-keys");

    let checks = &value["appraisal"]["checks"];
    assert_eq!(checks["statementSignature"], "pass");
    assert_eq!(checks["receiptInclusion"], "pass");
    assert_eq!(checks["artifactBinding"], "not-checked");
    assert_eq!(checks["policy"], "pass");

    // The rules and the decision they produced are separate sections, so a
    // reader can cite the policy that gated a release without reading a verdict
    // into it, and vice versa.
    assert_eq!(value["relyingPartyPolicy"]["status"], "evaluated");
    assert_eq!(value["relyingPartyPolicy"]["satisfied"], true);
    assert!(
        value["relyingPartyPolicy"]["verdict"].is_null(),
        "the rules section must not carry the decision"
    );

    // Provenance is what stops a downstream engine treating an issuer-signed
    // claim and an operator assertion as equally solid.
    assert_eq!(
        value["signedStatement"]["provenance"]["coveredBy"],
        "statement-signer"
    );
    assert_eq!(
        value["receipts"]["entries"][0]["provenance"]["coveredBy"],
        "transparency-service"
    );
    assert_eq!(
        value["artifactBinding"]["provenance"]["coveredBy"],
        "operator"
    );

    // A green run must still say what it did not establish, in a form that
    // machines can count rather than grep.
    let gaps = value["appraisal"]["notChecked"]
        .as_array()
        .expect("notChecked must be present");
    assert!(
        !gaps.is_empty(),
        "a passing run must still declare its gaps"
    );
    for g in gaps {
        assert!(g["code"].is_string(), "each gap needs a stable code: {g}");
        assert!(g["category"].is_string(), "each gap needs a category: {g}");
        assert!(g["impact"].is_string(), "each gap needs an impact: {g}");
    }
    assert!(
        gaps.iter()
            .any(|g| g["code"] == "ArtifactBindingNotRequested"),
        "unbound runs must say so: {gaps:?}"
    );
    assert!(
        gaps.iter()
            .any(|g| g["code"] == "CertificateChainNotValidated"),
        "chain validation gap must be declared: {gaps:?}"
    );

    // The facts projection must carry the observations and none of our
    // judgement, so that a system using it cannot forward our verdict as its
    // own conclusion.
    let facts_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&facts).unwrap()).unwrap();
    assert_eq!(facts_value["schemaVersion"], "scitt-verifier/facts/v0");
    assert!(facts_value["signedStatement"]["claimDigest"].is_string());
    assert!(
        facts_value.get("appraisal").is_none(),
        "the facts document must not carry a verdict: {facts_value}"
    );
    assert!(
        facts_value.get("relyingPartyPolicy").is_none(),
        "the facts document must not carry the policy: {facts_value}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The guarantee a pipeline depends on.
///
/// Both shipped CI examples publish the record with `always()`. If an early
/// failure writes no file, the archive is empty exactly when someone needs it —
/// during an incident. Every one of these paths must leave a record.
#[test]
fn every_failure_path_still_writes_a_record() {
    let dir = std::env::temp_dir().join("scitt-verifier-acceptance-failures");
    std::fs::create_dir_all(&dir).unwrap();

    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-july-scitt-keys.cbor"]);
    let stale = corpus(&["fixtures", "stale-scitt-keys.cbor"]);
    let policy = corpus(&["policies", "fixture-mst.json"]);
    let artifact = corpus(&["fixtures", "artifact.bin"]);
    let missing = dir.join("does-not-exist").display().to_string();

    // A file that exists but is not what it claims to be.
    let garbage = dir.join("garbage.bin");
    std::fs::write(&garbage, b"not cbor, not json, not anything").unwrap();
    let garbage = garbage.display().to_string();

    let cases: Vec<(&str, Vec<&str>, i32)> = vec![
        ("missing statement", vec![&missing, &keys, &policy], 4),
        ("missing key set", vec![&statement, &missing, &policy], 4),
        ("missing policy", vec![&statement, &keys, &missing], 4),
        ("malformed policy", vec![&statement, &keys, &garbage], 4),
        ("malformed key set", vec![&statement, &garbage, &policy], 3),
        ("malformed statement", vec![&garbage, &keys, &policy], 3),
        ("stale trust material", vec![&statement, &stale, &policy], 3),
    ];

    for (name, paths, expected_code) in cases {
        let record = dir.join(format!("{}.json", name.replace(' ', "-")));
        let record_str = record.display().to_string();
        let _ = std::fs::remove_file(&record);

        let r = run(&[
            "verify",
            "--statement",
            paths[0],
            "--scitt-keys",
            paths[1],
            "--policy",
            paths[2],
            "--result",
            &record_str,
            "--format",
            "json",
        ]);

        assert_eq!(
            r.code, expected_code,
            "{name}: expected exit {expected_code}\nstdout: {}\nstderr: {}",
            r.stdout, r.stderr
        );

        let written = std::fs::read_to_string(&record)
            .unwrap_or_else(|e| panic!("{name}: a record must exist even on failure: {e}"));
        let value: serde_json::Value = serde_json::from_str(&written)
            .unwrap_or_else(|e| panic!("{name}: the record must be valid JSON: {e}"));

        assert_eq!(value["appraisal"]["exitCode"], expected_code, "{name}");
        assert!(
            value["appraisal"]["primaryDiagnostic"]["code"].is_string(),
            "{name}: a failure must name what stopped it: {value}"
        );
        assert!(
            value["appraisal"]["primaryDiagnostic"]["action"].is_string(),
            "{name}: a failure must say what to do about it: {value}"
        );

        // A block we never reached must say so rather than being null, so that
        // "we did not look" cannot be read as "the input did not carry it".
        for section in ["signedStatement", "receipts", "relyingPartyPolicy"] {
            assert!(
                value[section]["status"].is_string(),
                "{name}: {section} must declare whether it was evaluated: {value}"
            );
        }

        // stdout must be the same protocol on every path, or a JSON consumer
        // has to parse two.
        serde_json::from_str::<serde_json::Value>(&r.stdout)
            .unwrap_or_else(|e| panic!("{name}: --format json must emit JSON on stdout: {e}"));
    }

    // An unreadable artifact fails late, after the statement checks have run.
    // Those results must survive into the record rather than being discarded.
    let record = dir.join("unreadable-artifact.json");
    let record_str = record.display().to_string();
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy,
        "--artifact",
        &missing,
        "--binding-mode",
        "payload-bytes",
        "--result",
        &record_str,
        "--format",
        "json",
    ]);
    assert_eq!(r.code, 4, "{}", r.stderr);
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(
        value["appraisal"]["primaryDiagnostic"]["code"],
        "ArtifactUnreadable"
    );
    assert_eq!(
        value["appraisal"]["checks"]["statementSignature"], "pass",
        "checks that did run must be reported: {value}"
    );
    // The operator asked for a binding and we could not find out. Reporting
    // that as "not-checked" would claim nobody asked.
    assert_eq!(
        value["appraisal"]["checks"]["artifactBinding"], "cannot-evaluate",
        "a requested-but-unperformed binding is not the same as an unrequested one: {value}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::write(&artifact, std::fs::read(&artifact).unwrap());
}

/// A failed record write must not leave stdout claiming success.
///
/// The document is built from the assessment, so a naive implementation prints
/// `artifact-transparent` / `exitCode: 0` while the process exits 4 — two
/// contradictory answers from one run, and the consumer reading stdout gets the
/// wrong one.
#[test]
fn a_failed_record_write_is_reflected_in_the_output() {
    let dir = std::env::temp_dir().join("scitt-verifier-record-write");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // A path whose parent does not exist: a common CI mistake.
    let unwritable = dir.join("no-such-dir").join("result.json");
    let unwritable = unwritable.display().to_string();

    let artifact = corpus(&["fixtures", "artifact.bin"]);
    let r = verify(&[
        "--artifact",
        &artifact,
        "--binding-mode",
        "payload-bytes",
        "--result",
        &unwritable,
        "--format",
        "json",
    ]);

    assert_eq!(r.code, 4, "a pass with no audit trail is not actionable");

    let value: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("stdout must still be JSON");
    assert_eq!(
        value["appraisal"]["exitCode"], 4,
        "the document must not disagree with the process: {value}"
    );
    assert_eq!(value["appraisal"]["verdict"], "usage-error");
    assert_eq!(
        value["appraisal"]["primaryDiagnostic"]["code"],
        "RecordWriteFailed"
    );
    assert_eq!(
        value["appraisal"]["primaryDiagnostic"]["category"],
        "internal"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same guarantee for the facts projection.
///
/// A gate that hands facts to another engine has the same audit obligation as
/// one that decides itself: if the handoff file never landed, the run must not
/// report success.
#[test]
fn a_failed_facts_write_is_also_fatal() {
    let dir = std::env::temp_dir().join("scitt-verifier-facts-write");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let unwritable = dir.join("no-such-dir").join("facts.json");

    let r = verify(&[
        "--facts",
        &unwritable.display().to_string(),
        "--format",
        "json",
    ]);

    assert_eq!(r.code, 4, "{}", r.stdout);
    let value: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(
        value["appraisal"]["primaryDiagnostic"]["code"],
        "RecordWriteFailed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The retired flag must fail loudly rather than being silently accepted.
#[test]
fn the_renamed_evidence_flag_explains_itself() {
    let r = verify(&["--evidence", "x.json"]);
    assert_eq!(r.code, 4);
    assert!(r.stderr.contains("--result"), "{}", r.stderr);
}

/// Every non-pass verdict must name what stopped it.
///
/// A policy whose only assertion is `requireKidBoundToKey: false` parses, is
/// not empty, and evaluates to zero results — so it is neither satisfied,
/// failed, nor unevaluable. That is exit 3, and without an explicit diagnostic
/// the operator gets a red gate with no stated reason.
#[test]
fn a_policy_that_evaluates_nothing_still_names_the_problem() {
    let dir = std::env::temp_dir().join("scitt-verifier-empty-policy");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("no-op.json");
    std::fs::write(
        &policy,
        br#"{"policyId":"no-op","policyVersion":"1","assertions":{"requireKidBoundToKey":false}}"#,
    )
    .unwrap();

    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-july-scitt-keys.cbor"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy.display().to_string(),
        "--format",
        "json",
    ]);

    assert_eq!(r.code, 3, "a policy that decides nothing is not a pass");
    let value: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(
        value["appraisal"]["primaryDiagnostic"]["code"], "PolicyProducedNoAssertions",
        "a red gate must never be silent about why: {value}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--format json` must mean JSON on every path, not just the happy one.
#[test]
fn json_mode_is_one_protocol() {
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
        "--format",
        "json",
    ]);
    assert_eq!(r.code, 3);
    let value: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("failures must be JSON too");
    assert_eq!(value["appraisal"]["verdict"], "cannot-evaluate");
    assert_eq!(value["appraisal"]["primaryDiagnostic"]["category"], "trust");
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

/// `inspect` reports; it does not judge. But it must still distinguish input it
/// could not read from input it could read and not decode.
#[test]
fn inspect_never_gates() {
    let statement = corpus(&["fixtures", "payload-tampered.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    assert_eq!(r.code, 0, "inspect reports; it does not judge");
    assert!(r.stdout.contains("does not verify anything"));
}

#[test]
fn inspect_separates_unreadable_from_undecodable() {
    let dir = std::env::temp_dir().join("scitt-verifier-inspect");
    std::fs::create_dir_all(&dir).unwrap();
    let garbage = dir.join("garbage.bin");
    std::fs::write(&garbage, b"not a COSE_Sign1").unwrap();

    let missing = run(&[
        "inspect",
        "--statement",
        &dir.join("absent.cose").display().to_string(),
    ]);
    assert_eq!(
        missing.code, 4,
        "unreadable input is the operator's problem"
    );

    let undecodable = run(&["inspect", "--statement", &garbage.display().to_string()]);
    assert_eq!(
        undecodable.code, 3,
        "a file we read but cannot decode is a finding about the file, not a usage error"
    );
    assert_ne!(
        missing.code, undecodable.code,
        "these two failures must never look alike"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn help_and_version_succeed() {
    assert_eq!(run(&["--help"]).code, 0);
    assert_eq!(run(&["--version"]).code, 0);
}
