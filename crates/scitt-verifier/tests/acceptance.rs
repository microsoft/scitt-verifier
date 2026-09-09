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
    // Deliberately a policy with no `receiptCount`. The property under test is
    // the verdict's own behaviour: an unverifiable receipt beside a good one
    // changes nothing. An operator who wants the stricter rule asks for it, and
    // `an_appended_receipt_fails_a_policy_that_pins_the_count` covers that.
    let policy = corpus(&["policies", "fixture-mst-unpinned-count.json"]);
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

/// The other half of the same fixture: what the verdict disregards, policy can
/// still refuse.
///
/// `receiptCount` counts receipts *present*, so it sees the appended one that
/// `verified_receipts()` cannot. This is the only way an operator learns the
/// file is not the one the transparency service returned, and it fails as a
/// policy decision — exit 2 — rather than as a claim about the artifact, which
/// is still exactly what its Issuer signed.
#[test]
fn an_appended_receipt_fails_a_policy_that_pins_the_count() {
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
        r.code, 2,
        "an inserted receipt must fail the operator's stated expectation:\n{}",
        r.stdout
    );
    assert!(r.stdout.contains("policy-failed"), "{}", r.stdout);
    assert!(
        r.stdout.contains("receiptCount"),
        "the run must name the assertion that refused it: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("Do not deploy"),
        "an inserted receipt indicts the file's handling, not the artifact: {}",
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

/// `--issuer` was removed: a receipt from another service is signed by that
/// service's key and so fails receipt verification anyway, and requiring a
/// particular issuer is a relying-party rule that belongs in the policy
/// document. A pipeline still passing the flag must fail loudly rather than
/// silently drop a check its author believed was running.
#[test]
fn the_removed_issuer_flag_is_refused_rather_than_ignored() {
    let r = verify(&["--issuer", "musa-mst-aug-2.confidential-ledger.azure.com"]);
    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(r.stderr.contains("unknown option"), "{}", r.stderr);
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

/// The record on disk must never contradict the exit code.
///
/// The mixed case is the dangerous one and neither test above reaches it: when
/// `--result` succeeds and `--facts` fails, the run exits 4 while a file
/// claiming `"pass": true` sits on disk. Stdout being correct is not enough —
/// the terminal scrolls away and the record is what gets kept, attached to a
/// release, and read months later by someone reconstructing what was verified.
#[test]
fn a_written_record_never_contradicts_the_exit_code() {
    let dir = std::env::temp_dir().join("scitt-verifier-mixed-write");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let good = dir.join("result.json");
    let bad = dir.join("no-such-dir").join("facts.json");

    let r = verify(&[
        "--result",
        &good.display().to_string(),
        "--facts",
        &bad.display().to_string(),
        "--format",
        "json",
    ]);

    assert_eq!(r.code, 4, "a lost handoff file is still a lost audit trail");

    let written = std::fs::read_to_string(&good).expect("the record that could be written must be");
    let on_disk: serde_json::Value = serde_json::from_str(&written).unwrap();

    assert_eq!(
        on_disk["appraisal"]["exitCode"], 4,
        "the persisted record disagrees with the process that wrote it: {on_disk}"
    );
    assert_eq!(on_disk["appraisal"]["verdict"], "usage-error");
    assert_eq!(
        on_disk["appraisal"]["pass"], false,
        "a record claiming success for a failed run is worse than no record"
    );

    // The written record and stdout are the same document, which is what
    // `--result` promises. Comparing them also catches a fix that corrects one
    // path and leaves the other behind.
    let printed: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(
        on_disk, printed,
        "the file and stdout must be the same document"
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

// ---------------------------------------------------------------------------
// COSE Hash Envelope binding (RFC 9995)
//
// The fixture is a real `CoseSignTool indirect-sign` envelope, not a
// hand-rolled one, so these tests fail if our reading of the RFC diverges from
// an independent implementation's writing of it.
//
// It carries no receipt, so a bound run still stops at exit 3. That is the
// honest answer — an artifact bound to a merely-signed statement is not
// transparent — and it is why these tests assert on the binding *detail* as
// well as the code.
// ---------------------------------------------------------------------------

fn verify_envelope(extra: &[&str]) -> Run {
    let statement = corpus(&["fixtures", "hash-envelope.cose"]);
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
fn a_hash_envelope_binds_to_the_artifact_it_hashes() {
    let artifact = corpus(&["fixtures", "hash-envelope-artifact.spdx.json"]);
    let r = verify_envelope(&["--artifact", &artifact, "--binding-mode", "payload-digest"]);
    assert!(
        r.stdout.contains("SHA-256"),
        "a bound digest run must name the algorithm it used: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("do not"),
        "a matching artifact must not be accused: {}",
        r.stdout
    );
    // No receipt in this fixture, so transparency cannot be claimed even
    // though the binding held.
    assert_eq!(r.code, 3, "{}", r.stdout);
}

#[test]
fn a_hash_envelope_rejects_a_different_artifact() {
    // The signature is genuine and the envelope is well-formed. What is wrong
    // is that this is not the file that was signed.
    let artifact = corpus(&["fixtures", "hash-envelope-bad-artifact.spdx.json"]);
    let r = verify_envelope(&["--artifact", &artifact, "--binding-mode", "payload-digest"]);
    assert_eq!(
        r.code, 1,
        "a digest mismatch is a finding about the artifact: {}",
        r.stdout
    );
}

/// Naming the wrong mode must never look like a tampered artifact.
///
/// `payload-bytes` against an envelope compares the whole file to a 32-byte
/// digest. Reported as a mismatch, that tells an operator to distrust a build
/// that is in fact fine — the most damaging output this tool can produce.
#[test]
fn payload_bytes_against_a_hash_envelope_cannot_compare() {
    let artifact = corpus(&["fixtures", "hash-envelope-artifact.spdx.json"]);
    let r = verify_envelope(&["--artifact", &artifact, "--binding-mode", "payload-bytes"]);
    assert_ne!(
        r.code, 1,
        "a mode error is not evidence about the artifact: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("payload-digest"),
        "the refusal must name the mode that would work: {}",
        r.stdout
    );
}

/// The mirror image: `payload-digest` against an ordinary statement.
#[test]
fn payload_digest_against_a_plain_statement_cannot_compare() {
    let artifact = corpus(&["fixtures", "artifact.bin"]);
    let r = verify(&["--artifact", &artifact, "--binding-mode", "payload-digest"]);
    assert_ne!(r.code, 1, "not an envelope is not a mismatch: {}", r.stdout);
    assert!(
        r.stdout.contains("258"),
        "the refusal must say what was missing: {}",
        r.stdout
    );
}

/// The regression that would hurt most.
///
/// This corpus statement has a genuine receipt and a passing policy, so every
/// gate except the binding succeeds. An earlier `decide()` enumerated binding
/// modes by name; `payload-digest` was not in the list, fell through to the
/// catch-all, and returned `PASS statement-transparent` with exit 0 — plus a
/// diagnostic claiming binding "was not requested", when the operator had
/// requested it and the tool had failed to perform it.
///
/// A requested-but-unperformed binding must never be reported as any kind of
/// pass, whichever mode is named.
#[test]
fn a_requested_binding_that_cannot_be_performed_is_never_a_pass() {
    let artifact = corpus(&["fixtures", "artifact.bin"]);
    let r = verify(&["--artifact", &artifact, "--binding-mode", "payload-digest"]);
    assert_ne!(
        r.code, 0,
        "the operator asked about an artifact and got no answer: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("PASS"),
        "an unevaluable binding is not a pass: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("was not requested"),
        "it was requested; saying otherwise misreports the operator: {}",
        r.stdout
    );
}

/// `inspect` must not publish a hash-of-a-hash as the payload digest.
///
/// For an envelope the payload *is* a digest, so a `sha256` field over it
/// identifies nothing — and invites a consumer to compare it against their
/// artifact's digest and conclude, wrongly, that they do not match.
#[test]
fn inspect_reports_a_hash_envelope_as_a_digest() {
    let statement = corpus(&["fixtures", "hash-envelope.cose"]);
    let r = run(&["inspect", "--statement", &statement, "--format", "json"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let value: serde_json::Value = serde_json::from_str(&r.stdout).expect("stdout must be JSON");
    let payload = &value["payload"];
    assert!(
        payload["sha256"].is_null(),
        "a digest of a digest must not be published as the payload hash: {payload}"
    );
    assert_eq!(payload["hashEnvelope"]["hashAlg"], "SHA-256");
    assert_eq!(
        payload["hashEnvelope"]["preimageContentType"],
        "application/spdx+json"
    );
    assert!(
        payload["hashEnvelope"]["digest"].is_string(),
        "the artifact digest must be published in full: {payload}"
    );
}

/// The fixtures are hashed byte-for-byte, so a checkout that rewrites their
/// line endings would break the binding tests in a way that looks like a code
/// bug. Fail loudly and point at the cause instead.
#[test]
fn hash_envelope_fixtures_keep_their_exact_bytes() {
    for (name, expected) in [
        ("hash-envelope.cose", 702usize),
        ("hash-envelope-artifact.spdx.json", 57),
        ("hash-envelope-bad-artifact.spdx.json", 44),
    ] {
        let bytes = std::fs::read(corpus(&["fixtures", name])).unwrap();
        assert_eq!(
            bytes.len(),
            expected,
            "fixture {name} is {} bytes, expected {expected}. The checkout \
             transformed it — check .gitattributes and core.autocrlf.",
            bytes.len()
        );
    }
}

/// `statementSubject` reads a claim the issuer signed and the ledger's claim
/// digest covers, so unlike `signerSubjectContains` it survives re-signing by
/// a different certificate. These pin the exit codes a gate branches on.
fn verify_with_subject_policy(name: &str, criteria: &str) -> Run {
    let dir = std::env::temp_dir().join(format!("scitt-verifier-subject-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"policyId":"subject","policyVersion":"1","assertions":{{"receiptCount":1,"statementSubject":{criteria}}}}}"#
        ),
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
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[test]
fn a_matching_statement_subject_passes() {
    let r = verify_with_subject_policy("match", r#"{"equals":"unknown.intent"}"#);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("[pass] statementSubject"),
        "the assertion must be shown as having run: {}",
        r.stdout
    );
}

#[test]
fn a_statement_about_something_else_fails_the_policy() {
    // The whole point: a genuine, transparent statement from an accepted
    // issuer must still be refused when it is about a different subject.
    let r = verify_with_subject_policy("mismatch", r#"{"equals":"some.other.thing"}"#);
    assert_eq!(
        r.code, 2,
        "a subject mismatch is a policy failure, not a crypto failure: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("[FAIL] statementSubject"),
        "the failing assertion must be named: {}",
        r.stdout
    );
}

/// The real `iss` claim in the corpus statement. A `did:x509` binds the CA
/// fingerprint and the EKU, and Microsoft Signing Transparency authenticates it
/// at registration, so a receipt over this claim means the service checked the
/// signer was entitled to the identity.
const FIXTURE_ISSUER: &str = "did:x509:0:sha256:1UncIxT3oW5JalFUkbJzvJwJjkCgcNYe8WAocPDEAtg::eku:1.3.6.1.4.1.311.97.1.3.1.29433.35007.34545.16815.37291.11644.53265.56135";

fn verify_with_issuer_policy(name: &str, criteria: &str) -> Run {
    let dir = std::env::temp_dir().join(format!("scitt-verifier-issuer-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"policyId":"issuer","policyVersion":"1","assertions":{{"receiptCount":1,"statementIssuer":{criteria}}}}}"#
        ),
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
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[test]
fn a_matching_statement_issuer_passes() {
    let r = verify_with_issuer_policy("match", &format!(r#"{{"equals":"{FIXTURE_ISSUER}"}}"#));
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("[pass] statementIssuer"),
        "the assertion must be shown as having run: {}",
        r.stdout
    );
}

#[test]
fn a_statement_from_another_issuer_fails_the_policy() {
    // Cryptographically identical run, refused on identity alone: the receipt
    // verifies, the signature verifies, and the gate still says no.
    let r = verify_with_issuer_policy("mismatch", r#"{"equals":"did:x509:0:sha256:someoneelse"}"#);
    assert_eq!(
        r.code, 2,
        "an issuer mismatch is a policy failure, not a crypto failure: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("[FAIL] statementIssuer"),
        "the failing assertion must be named: {}",
        r.stdout
    );
}

#[test]
fn an_issuer_prefix_pins_the_authority_without_pinning_the_eku() {
    // The reason `startsWith` earns its place: the did:x509 form puts the CA
    // fingerprint before the EKU, so a prefix survives an EKU change that an
    // `equals` pin would reject.
    let r = verify_with_issuer_policy(
        "prefix",
        r#"{"startsWith":"did:x509:0:sha256:1UncIxT3oW5JalFUkbJzvJwJjkCgcNYe8WAocPDEAtg"}"#,
    );
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("[pass] statementIssuer"), "{}", r.stdout);
}

#[test]
fn an_issuer_prefix_that_starts_elsewhere_is_refused() {
    // There is no `contains` mode precisely so that an attacker-chosen identity
    // embedding the pinned string does not pass.
    let r = verify_with_issuer_policy(
        "impostor",
        &format!(r#"{{"startsWith":"not-{FIXTURE_ISSUER}"}}"#),
    );
    assert_eq!(r.code, 2, "{}", r.stdout);
}

#[test]
fn a_vacuous_subject_match_is_refused_before_anything_is_verified() {
    // `startsWith: ""` accepts every subject. Refusing it at parse time is
    // what keeps it from appearing in the report as a rule that passed.
    let r = verify_with_subject_policy("vacuous", r#"{"startsWith":""}"#);
    assert_eq!(r.code, 4, "a rule that cannot reject is a usage error");
    assert!(
        !r.stdout.starts_with("PASS"),
        "a refused policy must never print a pass: {}",
        r.stdout
    );
}

// --- protectedHeaders --------------------------------------------------

/// Run a policy whose only assertion is a `protectedHeaders` list.
fn verify_with_header_policy(name: &str, list: &str) -> Run {
    let dir = std::env::temp_dir().join(format!("scitt-verifier-headers-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"policyId":"headers","policyVersion":"1","assertions":{{"receiptCount":1,"protectedHeaders":{list}}}}}"#
        ),
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
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[test]
fn a_protected_header_can_be_pinned_by_integer_label() {
    let r = verify_with_header_policy(
        "cty",
        r#"[{"path":[3],"text":{"equals":"application/cose"}}]"#,
    );
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("[pass] protectedHeaders"),
        "the assertion must be shown as having run: {}",
        r.stdout
    );
}

/// The real MST statement nests its CWT claims at label 15, so this walks two
/// levels into material the receipt covers.
#[test]
fn a_path_reaches_a_claim_nested_inside_the_cwt_header() {
    let r = verify_with_header_policy(
        "nested",
        r#"[{"path":[15,2],"text":{"equals":"unknown.intent"}}]"#,
    );
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
}

/// `x5t` is `[hashAlg, hashValue]`, so reaching the algorithm means indexing
/// an array. The node's type decides that the segment is an index, not a label.
#[test]
fn an_integer_segment_indexes_the_x5t_array() {
    let r = verify_with_header_policy("x5t", r#"[{"path":[34,0],"int":{"equals":-16}}]"#);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
}

#[test]
fn a_header_the_statement_does_not_carry_cannot_be_evaluated() {
    let r = verify_with_header_policy("absent", r#"[{"path":[-65537],"text":{"equals":"x"}}]"#);
    assert_eq!(r.code, 3, "absent is not a pass and not a failure");
    assert!(
        !r.stdout.starts_with("PASS"),
        "an unevaluable rule must never print a pass: {}",
        r.stdout
    );
}

#[test]
fn a_header_of_the_wrong_cbor_type_fails_and_names_both_types() {
    // Label 33 is the x5chain, an array of four certificates.
    let r = verify_with_header_policy("mistyped", r#"[{"path":[33],"text":{"equals":"x"}}]"#);
    assert_eq!(r.code, 2, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("expected a text string") && r.stdout.contains("array of 4"),
        "the reason should name what was expected and what was found: {}",
        r.stdout
    );
}

#[test]
fn a_header_that_does_not_match_fails_while_the_statement_still_verifies() {
    let r = verify_with_header_policy(
        "mismatch",
        r#"[{"path":[3],"text":{"equals":"application/json"}}]"#,
    );
    assert_eq!(r.code, 2, "the statement is genuine; the policy said no");
    assert!(
        r.stdout.contains("PolicyAssertionFailed") && r.stdout.contains("protectedHeaders"),
        "the failure must be attributed to the policy, not to the cryptography: {}",
        r.stdout
    );
}

/// The forward-compatibility guard, end to end. A policy written against a
/// build that has quantifiers must fail loudly here rather than silently
/// hunting for a header literally labelled `*`.
#[test]
fn an_array_wildcard_path_is_refused_before_anything_is_verified() {
    let r = verify_with_header_policy(
        "wildcard",
        r#"[{"path":["external-signatures","*",1],"int":{"equals":-257}}]"#,
    );
    assert_eq!(
        r.code, 4,
        "a path this build cannot honour is a usage error"
    );
    assert!(
        !r.stdout.starts_with("PASS"),
        "a refused policy must never print a pass: {}",
        r.stdout
    );
}

#[test]
fn a_header_assertion_with_no_matcher_is_refused() {
    let r = verify_with_header_policy("no-matcher", r#"[{"path":[3]}]"#);
    assert_eq!(r.code, 4, "an untyped match is a usage error");
}

/// `inspect` is the documented way to discover what a policy can assert on, so
/// it has to print the label a `protectedHeaders` path needs. The name alone
/// sends the author to an IANA registry.
#[test]
fn inspect_prints_the_policy_path_for_each_protected_header() {
    let statement = corpus(&["fixtures", "hash-envelope.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    for expected in ["alg [1]", "payload hash alg [258]", "preimage cty [259]"] {
        assert!(
            r.stdout.contains(expected),
            "inspect must print {expected}, so the path can be read off: {}",
            r.stdout
        );
    }
}

/// A CWT claim is two segments deep. Printing only the inner label would leave
/// the author to guess the nesting, which is the easiest part to get wrong.
#[test]
fn inspect_prints_the_full_path_for_a_nested_cwt_claim() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    assert!(
        r.stdout.contains("sub [15, 2]") && r.stdout.contains("iss [15, 1]"),
        "a nested claim must show its whole path: {}",
        r.stdout
    );
}

/// `protectedHeaders` resolves against the protected bucket only. Printing the
/// same bracketed syntax over unprotected headers would offer a path that
/// always resolves to nothing.
#[test]
fn inspect_offers_no_policy_path_for_unprotected_headers() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    let unprotected = r
        .stdout
        .split("Unprotected headers")
        .nth(1)
        .expect("the fixture has an unprotected bucket")
        .split("\n\n")
        .next()
        .expect("the bucket ends at a blank line");
    assert!(
        unprotected.contains("receipts"),
        "the fixture keeps its receipt unprotected: {unprotected}"
    );
    assert!(
        !unprotected.contains('['),
        "no path may be advertised for a header policy cannot reach: {unprotected}"
    );
}

/// The end-to-end claim: a path copied out of `inspect` evaluates.
#[test]
fn a_path_read_from_inspect_can_be_pasted_into_a_policy() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    let line = r
        .stdout
        .lines()
        .find(|l| l.trim_start().starts_with("content type ["))
        .expect("the MST statement declares a content type");
    let path = &line[line.find('[').unwrap()..=line.find(']').unwrap()];
    assert_eq!(path, "[3]", "read straight off the inspect line");

    let r = verify_with_header_policy(
        "pasted",
        &format!(r#"[{{"path":{path},"text":{{"equals":"application/cose"}}}}]"#),
    );
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("[pass] protectedHeaders"),
        "the path printed by inspect must resolve when pasted verbatim: {}",
        r.stdout
    );
}

/// A header this build does not interpret still has to be legible. Naming its
/// shape — "array of 1" — proves it is there and says nothing an author can
/// write a rule against, which sent them to a separate CBOR decoder. The
/// members carry the `path` a policy would use, so the next step is a copy.
#[test]
fn inspect_descends_into_an_uninterpreted_cbor_header() {
    let statement = corpus(&["fixtures", "cbor-header.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    for expected in [
        r#"["external-signature"]"#,
        r#"["external-signature", 0]"#,
        r#"["external-signature", 0, 1]"#,
        r#"["external-signature", 0, -1]"#,
    ] {
        assert!(
            r.stdout.contains(expected),
            "every addressable member must print its path; missing {expected}: {}",
            r.stdout
        );
    }
}

/// The same end-to-end claim as the flat case, one level deeper. Nesting is
/// where an author is most likely to guess the path wrong, so the printed
/// form has to be the form the engine accepts — not merely similar to it.
#[test]
fn a_nested_path_read_from_inspect_can_be_pasted_into_a_policy() {
    let statement = corpus(&["fixtures", "cbor-header.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    let line = r
        .stdout
        .lines()
        .find(|l| {
            l.trim_start()
                .starts_with(r#"["external-signature", 0, 1]"#)
        })
        .expect("the fixture carries a nested CBOR header");
    let path = &line[line.find('[').unwrap()..=line.find(']').unwrap()];
    assert_eq!(path, r#"["external-signature", 0, 1]"#);

    let dir = std::env::temp_dir().join("scitt-verifier-nested-path");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"policyId":"nested","policyVersion":"1","assertions":{{"receiptCount":1,
               "protectedHeaders":[{{"path":{path},"int":{{"equals":-257}}}}]}}}}"#
        ),
    )
    .unwrap();

    let keys = corpus(&["fixtures", "musa-mst-aug-scitt-keys.cbor"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy.display().to_string(),
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("[pass] protectedHeaders"),
        "a nested path printed by inspect must resolve verbatim: {}",
        r.stdout
    );
}

/// The name `inspect` prints is the name a policy accepts. Without this the
/// two tables could drift apart in a build that still passes its unit tests,
/// and the advertised route — read the report, write the rule — would fail for
/// one algorithm, which is the hardest kind of gap to notice.
#[test]
fn an_algorithm_name_read_from_inspect_can_be_pasted_into_a_policy() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    let line = r
        .stdout
        .lines()
        .find(|l| l.trim_start().starts_with("alg ["))
        .expect("the MST statement declares an algorithm");
    let name = line
        .rsplit_once("] ")
        .expect("alg renders as 'name (value)'")
        .1
        .split_whitespace()
        .next()
        .expect("a name precedes the parenthesised value");
    assert_eq!(name, "PS256", "read straight off the inspect line");

    let r = verify_with_header_policy(
        "pasted-alg",
        &format!(r#"[{{"path":[1],"alg":{{"equals":"{name}"}}}}]"#),
    );
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("PS256 (-37) must be PS256"),
        "the report names both sides so a refusal needs no registry: {}",
        r.stdout
    );
}

/// A mistyped identifier is a different, valid policy; a mistyped name is not a
/// policy at all. This is the whole reason the matcher exists, so it is pinned
/// end to end rather than only at the parser.
#[test]
fn an_unknown_algorithm_name_stops_before_anything_is_verified() {
    let r = verify_with_header_policy("typo", r#"[{"path":[1],"alg":{"equals":"PS257"}}]"#);
    assert_eq!(
        r.code, 4,
        "a policy that cannot match must be a usage error, not a verdict: {}\n{}",
        r.stdout, r.stderr
    );
    let out = format!("{}{}", r.stdout, r.stderr);
    assert!(out.contains("PS257"), "name the offending value: {out}");
    assert!(
        out.contains("PS256"),
        "list what is accepted, or the author is left guessing: {out}"
    );
}

/// The label tells an author where a header is; the numeric value tells them
/// what to write. `alg` renders as a name, so without this the author has to
/// find `ES256 = -7` in a registry to complete the rule.
#[test]
fn inspect_prints_the_numeric_value_of_an_algorithm() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    assert!(
        r.stdout.contains("PS256 (-37)"),
        "alg must show the value a policy matches on: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("SHA-256 (-16)"),
        "x5t's algorithm is addressable at [34, 0], so it needs its value too: {}",
        r.stdout
    );
}

/// The RFC 9995 payload hash algorithm decides how an artifact gets hashed, and
/// is the likeliest hash-envelope header to appear in a policy.
#[test]
fn inspect_prints_the_numeric_value_of_the_payload_hash_algorithm() {
    let statement = corpus(&["fixtures", "hash-envelope.cose"]);
    let r = run(&["inspect", "--statement", &statement]);
    assert!(
        r.stdout.contains("payload hash alg [258]   SHA-256 (-16)"),
        "both halves of the rule must be readable off one line: {}",
        r.stdout
    );
}

/// Verify the CBOR-header fixture, whose protected header carries a real
/// detached RS256 signature over its payload, against `assertions`.
fn verify_cbor_header_fixture(name: &str, assertions: &str) -> Run {
    let dir = std::env::temp_dir().join(format!("scitt-verifier-external-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(r#"{{"policyId":"external","policyVersion":"1","assertions":{assertions}}}"#),
    )
    .unwrap();

    let statement = corpus(&["fixtures", "cbor-header.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-aug-scitt-keys.cbor"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy.display().to_string(),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[test]
fn a_detached_signature_in_a_protected_header_can_be_verified() {
    let r = verify_cbor_header_fixture(
        "pass",
        r#"{"externalSignatures":[{"path":["external-signature",0],"signedOver":"payload",
            "signerSubjectContains":"Example Component Supplier"}]}"#,
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.stdout.contains("[pass] externalSignatures"),
        "{}",
        r.stdout
    );
    // A pass here must not read as an endorsement of the named signer: no
    // chain was validated, so the subject is a string its own author chose.
    assert!(
        r.stdout.contains("ExternalSignerChainNotValidated"),
        "a verified external signature must declare that its chain was not validated: {}",
        r.stdout
    );
}

#[test]
fn a_detached_signature_by_the_wrong_signer_fails() {
    let r = verify_cbor_header_fixture(
        "wrong-signer",
        r#"{"externalSignatures":[{"path":["external-signature",0],"signedOver":"payload",
            "signerSubjectContains":"Some Other Supplier"}]}"#,
    );
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert!(
        r.stdout.contains("does not contain 'Some Other Supplier'"),
        "{}",
        r.stdout
    );
}

/// An absent descriptor is not a forged one. The distinction has to survive
/// all the way to the exit code, or a pipeline cannot tell "this supplier did
/// not sign" from "this supplier's signature is fake".
#[test]
fn an_absent_detached_signature_cannot_be_evaluated() {
    let r = verify_cbor_header_fixture(
        "absent",
        r#"{"externalSignatures":[{"path":["no-such-header",0],"signedOver":"payload"}]}"#,
    );
    assert_eq!(r.code, 3, "{}", r.stdout);
    assert!(
        r.stdout.contains("[CANNOT EVALUATE] externalSignatures"),
        "{}",
        r.stdout
    );
}

/// What the signature covers is the policy author's declaration, never the
/// tool's guess. A policy that omits it, or names a convention this build does
/// not implement, is refused before any crypto runs.
#[test]
fn a_detached_signature_needs_an_explicit_signed_over() {
    let missing = verify_cbor_header_fixture(
        "no-signed-over",
        r#"{"externalSignatures":[{"path":["external-signature",0]}]}"#,
    );
    assert_eq!(missing.code, 4, "{}", missing.stdout);

    let unknown = verify_cbor_header_fixture(
        "unknown-signed-over",
        r#"{"externalSignatures":[{"path":["external-signature",0],"signedOver":"claimDigest"}]}"#,
    );
    assert_eq!(unknown.code, 4, "{}", unknown.stdout);
}

/// Verify the nested-COSE_Sign1 fixture against `assertions`.
fn verify_nested_fixture(name: &str, assertions: &str) -> Run {
    let dir = std::env::temp_dir().join(format!("scitt-verifier-nested-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        format!(r#"{{"policyId":"nested","policyVersion":"1","assertions":{assertions}}}"#),
    )
    .unwrap();

    let statement = corpus(&["fixtures", "nested-sign1.cose"]);
    let keys = corpus(&["fixtures", "musa-mst-aug-scitt-keys.cbor"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy.display().to_string(),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[test]
fn a_nested_cose_sign1_can_be_verified() {
    let r = verify_nested_fixture(
        "pass",
        r#"{"externalSignatures":[{"path":["external-statement"],"signedOver":"coseSign1",
            "signerSubjectContains":"Example Component Supplier"}]}"#,
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.stdout.contains("[pass] externalSignatures"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("ExternalSignerChainNotValidated"),
        "{}",
        r.stdout
    );
}

/// RS256 is the algorithm on essentially every supplier signature, and the
/// upstream COSE helper this crate uses for the envelope cannot map it — it
/// returns the same error for "unsupported" as for "invalid". Reading a
/// nested COSE_Sign1 through that helper reported every real RS256 signature
/// as a forgery. This test is the regression guard: it passes only if the
/// nested path builds its own Sig_structure.
#[test]
fn a_nested_rs256_signature_is_not_reported_as_a_forgery() {
    let r = verify_nested_fixture(
        "rs256",
        r#"{"externalSignatures":[{"path":["external-statement"],"signedOver":"coseSign1"}]}"#,
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        !r.stdout.contains("does not verify"),
        "an RS256 signature this build can compute must not be reported as invalid: {}",
        r.stdout
    );
}

/// Naming the wrong convention must not read as a forgery either. The two
/// shapes are different structures, and saying "this is not a COSE_Sign1" is
/// the only honest answer.
#[test]
fn naming_the_wrong_convention_cannot_be_evaluated() {
    let r = verify_nested_fixture(
        "wrong-convention",
        r#"{"externalSignatures":[{"path":["external-statement"],"signedOver":"payload"}]}"#,
    );
    assert_eq!(r.code, 3, "{}", r.stdout);
    assert!(
        r.stdout.contains("[CANNOT EVALUATE] externalSignatures"),
        "{}",
        r.stdout
    );
}
