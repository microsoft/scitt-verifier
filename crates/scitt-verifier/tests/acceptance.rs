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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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

fn has_line(output: &str, expected: &str) -> bool {
    output.lines().any(|line| line == expected)
}

fn transcript(output: &str) -> &str {
    output.split("\nDetails\n").next().unwrap_or(output)
}

fn has_progress_finding(output: &str, state: &str, check: &str) -> bool {
    transcript(output).lines().any(|line| {
        let line = line.trim_start();
        line.starts_with(state) && line[state.len()..].split_whitespace().next() == Some(check)
    })
}

fn has_pass_verdict(output: &str) -> bool {
    output
        .lines()
        .any(|line| line.starts_with("PASS ") && line.contains("-transparent"))
}

#[test]
fn a_genuine_statement_without_an_artifact_is_only_statement_transparent() {
    // The distinction this test defends: a run that never looked at an
    // artifact must not print the same word as one that did.
    let r = verify(&[]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.starts_with("Verifying ") && r.stdout.contains("[1/3] Read inputs\n"),
        "text verification must report work as it happens: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains('\u{1b}'),
        "redirected text output must not contain terminal color codes: {}",
        r.stdout
    );
    assert!(
        has_line(&r.stdout, "PASS statement-transparent"),
        "the transcript must end in the scoped decision: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("artifact binding was not requested"),
        "an unbound pass must say so: {}",
        r.stdout
    );
    assert!(
        transcript(&r.stdout)
            .contains("PASS Signature valid; chain consistent with its embedded root")
            && transcript(&r.stdout).contains("ArtifactBindingNotRequested"),
        "statement facts and omitted checks must precede the completed report: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("signing certificate subject:")
            && !r.stdout.contains("claim digest")
            && !r.stdout.contains("receipt key id"),
        "compact successes must not dump raw evidence identities and hashes: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("\n\nPASS statement-transparent\n")
            && !r.stdout.contains("Statement signature:")
            && !r.stdout.contains("Receipt inclusion:")
            && r.stdout.lines().count() <= 36,
        "the scoped result must be visually separated as the final verdict block: {}",
        r.stdout
    );
    assert!(
        !has_line(&r.stdout, "Details"),
        "default text output must not repeat the completed evidence report: {}",
        r.stdout
    );
}

#[test]
fn verbose_text_retains_the_completed_evidence_report() {
    let r = verify(&["--verbose"]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        has_line(&r.stdout, "Details"),
        "verbose output must include the completed evidence report: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("[pass] issuer"),
        "verbose output must retain per-assertion evidence: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("signing certificate subject:")
            && r.stdout.contains("statement issuer:")
            && r.stdout.contains("registered at UTC"),
        "detailed identity and timestamp labels remain available: {}",
        r.stdout
    );
}

#[test]
fn json_stdout_contains_only_the_final_record() {
    let r = verify(&["--format", "json"]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    let value: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("progress must not contaminate JSON stdout");
    assert_eq!(value["appraisal"]["verdict"], "statement-transparent");
    assert!(!r.stdout.contains("Read inputs"));
}

#[test]
fn a_tampered_payload_exits_one() {
    let statement = corpus(&["fixtures", "payload-tampered.cose"]);
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
        has_line(&r.stdout, "PASS statement-transparent"),
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
        transcript(&r.stdout)
            .contains("the ledger's signature over the Merkle root did not verify"),
        "receipt diagnostics must be emitted while the statement stage runs: {}",
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
    let keys = corpus(&["fixtures", "other-service-scitt-keys.cbor"]);
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
    assert!(
        transcript(&r.stdout).contains("ReceiptKeyUnknown"),
        "the deciding diagnostic must appear in the assessment summary: {}",
        r.stdout
    );
    // Severity has to survive into the transcript. Printed as a notice it
    // would sit among the trust limitations, and a reader scanning for what
    // stopped the run would find nothing that looked like a failure.
    assert!(
        has_progress_finding(&r.stdout, "FAIL", "ReceiptKeyUnknown"),
        "a diagnostic that decided the verdict must not render as a notice: {}",
        r.stdout
    );
}

#[test]
fn a_policy_that_rejects_the_issuer_exits_two() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
    assert!(has_line(&r.stdout, "STOP policy-failed"));
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
        ("transparent-statement.cose", 5401),
        ("tampered-statement.cose", 5401),
        ("appended-receipt.cose", 5989),
        ("payload-tampered.cose", 5401),
        ("mst-test-scitt-keys.cbor", 175),
        ("other-service-scitt-keys.cbor", 523),
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
        has_line(&r.stdout, "PASS artifact-transparent"),
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
    let r = verify(&["--issuer", "example-ledger.confidential-ledger.azure.com"]);
    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(r.stderr.contains("unknown option"), "{}", r.stderr);
}

#[test]
fn a_missing_policy_exits_four() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
    // Which chain gap applies depends on what the run could establish; that a
    // chain caveat is declared at all does not. Asserting the family rather
    // than one member keeps this test about the commitment — a green run still
    // says what it did not establish — instead of about today's wording.
    assert!(
        gaps.iter().any(|g| matches!(
            g["code"].as_str(),
            Some(
                "NoCertificateChain"
                    | "CertificateChainNotValidated"
                    | "CertificateChainNotAnchoredExternally"
                    | "CertificateChainUnsupported"
            )
        )),
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
    let stale = corpus(&["fixtures", "other-service-scitt-keys.cbor"]);
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
    let keys = corpus(&["fixtures", "other-service-scitt-keys.cbor"]);
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
        !has_line(&r.stdout, "PASS artifact-transparent")
            && !has_line(&r.stdout, "PASS statement-transparent"),
        "an unevaluable binding must not produce an overall pass: {}",
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
        has_progress_finding(&r.stdout, "PASS", "statementSubject"),
        "the assertion must be shown as having run: {}",
        r.stdout
    );
    assert!(
        transcript(&r.stdout).lines().any(|line| {
            line.contains("statementSubject") && line.trim_start().starts_with("PASS")
        }),
        "the policy assertion must be emitted in the live transcript: {}",
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
        has_progress_finding(&r.stdout, "FAIL", "statementSubject"),
        "the failing assertion must be named: {}",
        r.stdout
    );
}

/// The real `iss` claim in the corpus statement. A `did:x509` binds the CA
/// fingerprint and the EKU, and the transparency service authenticates it at
/// registration, so a receipt over this claim means the service checked the
/// signer was entitled to the identity.
///
/// The fingerprint is the SHA-256 of the corpus issuing CA, so it changes
/// whenever `corpus/tools/generate_fixtures.py` mints a new chain. The
/// regenerator prints the value to paste here.
const FIXTURE_ISSUER: &str =
    "did:x509:0:sha256:12_fzPuLgftjDn11g05T4lOItyjNHc7akSntxDcX3xw::eku:1.3.6.1.4.1.311.97.1.3.1";

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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
        has_progress_finding(&r.stdout, "PASS", "statementIssuer"),
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
        has_progress_finding(&r.stdout, "FAIL", "statementIssuer"),
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
        r#"{"startsWith":"did:x509:0:sha256:12_fzPuLgftjDn11g05T4lOItyjNHc7akSntxDcX3xw"}"#,
    );
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        has_progress_finding(&r.stdout, "PASS", "statementIssuer"),
        "{}",
        r.stdout
    );
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
        !has_pass_verdict(&r.stdout),
        "a refused policy must never print a pass: {}",
        r.stdout
    );
}

// --- protectedHeaders --------------------------------------------------

/// Run a policy whose only assertion is a `protectedHeaders` list.
fn verify_with_header_policy(name: &str, list: &str) -> Run {
    verify_with_header_policy_options(name, list, &[])
}

fn verify_with_header_policy_options(name: &str, list: &str, extra: &[&str]) -> Run {
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
    let policy_path = policy.display().to_string();
    let mut args = vec![
        "verify",
        "--statement",
        &statement,
        "--scitt-keys",
        &keys,
        "--policy",
        &policy_path,
    ];
    args.extend_from_slice(extra);
    let r = run(&args);
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
        has_progress_finding(&r.stdout, "PASS", "protectedHeaders"),
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
        !has_pass_verdict(&r.stdout),
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
        !has_pass_verdict(&r.stdout),
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
        has_progress_finding(&r.stdout, "PASS", "protectedHeaders"),
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

    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
        has_progress_finding(&r.stdout, "PASS", "protectedHeaders"),
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

    let r = verify_with_header_policy_options(
        "pasted-alg",
        &format!(r#"[{{"path":[1],"alg":{{"equals":"{name}"}}}}]"#),
        &["--verbose"],
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
        has_progress_finding(&r.stdout, "PASS", "externalSignatures"),
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
        has_progress_finding(&r.stdout, "CANNOT EVALUATE", "externalSignatures"),
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
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
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
        has_progress_finding(&r.stdout, "PASS", "externalSignatures"),
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
        has_progress_finding(&r.stdout, "CANNOT EVALUATE", "externalSignatures"),
        "{}",
        r.stdout
    );
}

// ---------------------------------------------------------------------------
// Online key acquisition.
//
// Every test here is network-free by construction, and that is the point
// rather than a convenience: each one pins a case where the tool must decide
// *not* to send anything. A test that needed a live service to prove a request
// was never made would be proving the opposite of what it claims.
//
// The paths that do reach a service are covered by the ignored live tests in
// the scitt-network crate, where a real endpoint is named explicitly.
// ---------------------------------------------------------------------------

/// A run that names no ledger and no key set has not been told how to
/// establish trust at all.
#[test]
fn verify_requires_either_a_key_set_or_online() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let policy = corpus(&["policies", "fixture-mst.json"]);
    let r = run(&["verify", "--statement", &statement, "--policy", &policy]);
    assert_eq!(r.code, 4, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stderr.contains("--scitt-keys") && r.stderr.contains("--online"),
        "the error must name both ways out: {}",
        r.stderr
    );
}

/// Passing both is a contradiction, and guessing which one was meant is how a
/// run ends up verifying against material the operator did not choose.
#[test]
fn a_key_set_and_online_together_are_refused() {
    let r = verify(&["--online"]);
    assert_eq!(r.code, 4, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
}

#[test]
fn ledger_without_online_is_refused() {
    let r = verify(&[
        "--ledger",
        "mst-test-scitt-verifier.confidential-ledger.azure.com",
    ]);
    assert_eq!(r.code, 4, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
}

#[test]
fn save_trust_without_online_is_refused() {
    let r = verify(&["--save-trust", "unused"]);
    assert_eq!(r.code, 4, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
}

/// The central guarantee: the policy, not the statement, decides where this
/// process connects. A policy with no allowlist has not authorised anything,
/// so there is nothing to fall back to and nothing to infer from the receipt.
#[test]
fn online_without_an_issuer_allowlist_refuses_before_reaching_the_network() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let policy = corpus(&["policies", "minimal.json"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--policy",
        &policy,
        "--online",
    ]);
    assert_eq!(r.code, 4, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("AcquisitionNotConfigured"),
        "the operator must be told the policy is the missing piece: {}",
        r.stdout
    );
    // A run that contacted nothing must not describe itself as holding keys it
    // never obtained. The refusal is the whole point of this path, and a trust
    // line reading "acquired from the transparency service" would contradict it
    // three lines below the diagnostic.
    assert!(
        !r.stdout
            .contains("key set acquired from the transparency service"),
        "an empty-handed run claimed to have acquired a key set: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("none — no key set was obtained"),
        "the trust line must say nothing was obtained: {}",
        r.stdout
    );
}

/// `--ledger` narrows the allowlist and can never extend it. Without this, the
/// flag would be a way to bypass the policy from the command line, and the
/// allowlist would only bind operators who did not know about it.
#[test]
fn an_explicit_ledger_outside_the_allowlist_is_refused() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let policy = corpus(&["policies", "fixture-mst.json"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--policy",
        &policy,
        "--online",
        "--ledger",
        "attacker.confidential-ledger.azure.com",
    ]);
    assert_eq!(r.code, 4, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("not in the policy"),
        "the refusal must say why: {}",
        r.stdout
    );
}

/// A receipt naming a service nobody allowlisted must not cause a request.
///
/// Receipts live in the statement's unprotected bucket, so anyone holding the
/// file can append one. If an appended receipt could choose a destination, a
/// verifier run would be an outbound request under an attacker's control.
#[test]
fn a_receipt_naming_an_unlisted_service_causes_no_request() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    // Two allowlisted services, neither of which the fixture's receipt names,
    // so selection has a real choice to make and correctly makes none.
    let policy = corpus(&["policies", "example-dr-pair.json"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--policy",
        &policy,
        "--online",
    ]);
    assert_eq!(
        r.code, 3,
        "an unlisted issuer is not a bad artifact, it is an unanswerable question: \
         stdout:\n{}\nstderr:\n{}",
        r.stdout, r.stderr
    );
    assert!(
        r.stdout.contains("NoLedgerSelected"),
        "the record must say nothing was selected: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("not looked up") || r.stdout.contains("not attempted"),
        "the receipt must read as never consulted, not as an unknown key: {}",
        r.stdout
    );
}

/// An allowlist entry this build cannot bootstrap is a configuration fault,
/// knowable without sending anything. Reporting it as an outage would tell the
/// operator to retry something that can never succeed.
#[test]
fn an_unsupported_provider_is_a_configuration_fault_not_an_outage() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let policy = corpus(&["policies", "online-unsupported-provider.json"]);
    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--policy",
        &policy,
        "--online",
    ]);
    assert_eq!(r.code, 4, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        !r.stdout.contains("retry"),
        "nothing here is worth retrying: {}",
        r.stdout
    );
}

/// A statement this tool cannot read is not a reason to contact anyone. Before
/// this was checked up front, an unparseable statement produced no candidate
/// issuers, which a single-entry allowlist ignored — so the run fetched keys it
/// could never use, and only then failed on the same bytes.
#[test]
fn an_unreadable_statement_never_triggers_acquisition() {
    let dir = std::env::temp_dir().join("scitt-verifier-unreadable-statement");
    std::fs::create_dir_all(&dir).unwrap();
    let statement = dir.join("not-a-statement.cose");
    std::fs::write(&statement, b"this is not COSE").unwrap();
    let statement = statement.display().to_string();
    let policy = corpus(&["policies", "online-unsupported-provider.json"]);

    let r = run(&[
        "verify",
        "--statement",
        &statement,
        "--policy",
        &policy,
        "--online",
        "--format",
        "json",
    ]);

    assert!(
        !r.stdout.contains("\"acquisition\""),
        "selection ran on a statement that could not be parsed: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("unsupportedProvider"),
        "the run reached provider routing instead of stopping at the statement: {}",
        r.stdout
    );
}

/// The offline record must not grow an acquisition block. A consumer keying on
/// its presence has to be able to tell a fetch from no fetch.
#[test]
fn an_offline_run_records_no_acquisition() {
    let r = verify(&["--format", "json"]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);
    assert!(
        !r.stdout.contains("\"acquisition\""),
        "an offline run must not claim to have acquired anything: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("\"scittKeys\""),
        "an offline run must still record the key set it used: {}",
        r.stdout
    );
}

/// Help has to state the default plainly. A user who cannot tell from the help
/// whether the tool makes a request cannot audit it without reading the source.
#[test]
fn help_says_verification_is_offline_unless_asked() {
    let r = run(&["--help"]);
    assert_eq!(r.code, 0);
    assert!(
        r.stdout.contains("offline unless --online is passed"),
        "the default must be stated, not implied: {}",
        r.stdout
    );
}

#[test]
fn a_payload_claim_is_not_read_from_a_statement_that_declares_another_type() {
    // The corpus fixture declares `application/cose`. A payload is read
    // because its issuer signed a claim that it is JSON, never because the
    // bytes might happen to parse — so this must abstain rather than pass,
    // and must not report the claim merely absent.
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let keys = corpus(&["fixtures", "mst-test-scitt-keys.cbor"]);
    let policy = corpus(&["policies", "payload-claims.json"]);
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
    assert!(
        has_progress_finding(&r.stdout, "CANNOT EVALUATE", "payloadJson"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("not JSON"), "{}", r.stdout);
}

#[test]
fn inspect_does_not_list_payload_claims_for_a_payload_declared_another_type() {
    // The listing exists so an author can paste a `path` into a policy.
    // Printing one for a payload `payloadJson` will refuse to read would
    // advertise a rule that can only ever abstain.
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let r = run(&["inspect", "--statement", &statement, "--verbose"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Payload"), "{}", r.stdout);
    assert!(!r.stdout.contains("\n  json\n"), "{}", r.stdout);
}

/// A malformed `--decode` command line is a usage error, not a verdict.
///
/// The two exit codes mean different things to a pipeline: 4 says the operator
/// mistyped something and nothing was examined, 3 says the tool looked and
/// could not answer. Collapsing a typo into 3 would make a broken command line
/// indistinguishable from a statement that genuinely lacks the claim, and the
/// operator would go looking at the artifact instead of at their own script.
#[test]
fn a_decode_command_line_that_cannot_be_understood_exits_as_a_usage_error() {
    let statement = corpus(&["fixtures", "cbor-header.cose"]);

    // An encoding, but nothing to apply it to.
    let r = run(&[
        "inspect",
        "--statement",
        &statement,
        "--decode-as",
        "base64",
    ]);
    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(r.stderr.contains("no --decode"), "{}", r.stderr);

    // An output file, but nothing to write to it.
    let r = run(&[
        "inspect",
        "--statement",
        &statement,
        "--decode-out",
        "x.bin",
    ]);
    assert_eq!(r.code, 4, "{}", r.stderr);

    // A path that is not a path.
    let r = run(&["inspect", "--statement", &statement, "--decode", "[bad"]);
    assert_eq!(r.code, 4, "{}", r.stderr);
}

/// A claim that cannot be decoded must say which claim, and why.
///
/// `inspect` prints the statement whatever happens, because the reader asked
/// to see it; the decode failure rides alongside on stderr. The failure mode
/// this guards is a bare non-zero exit that leaves an operator unable to tell
/// a misspelled path from a producer who stopped emitting the field.
#[test]
fn a_claim_that_cannot_be_decoded_is_named_and_explained() {
    let statement = corpus(&["fixtures", "cbor-header.cose"]);

    // No such claim. The report is still printed.
    let r = run(&["inspect", "--statement", &statement, "--decode", "['nope']"]);
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(r.stderr.contains("['nope']"), "{}", r.stderr);
    assert!(r.stderr.contains("no such claim"), "{}", r.stderr);
    assert!(r.stdout.contains("Payload"), "{}", r.stdout);

    // A real claim carrying characters that are not in the alphabet at all.
    let r = run(&[
        "inspect",
        "--statement",
        &statement,
        "--decode",
        "['digest']",
    ]);
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(r.stderr.contains("['digest']"), "{}", r.stderr);

    // A real claim whose characters are all legal but whose length is not.
    // Refusing this is the point: a decoder that padded it would invent bytes
    // and then publish a digest over them.
    let r = run(&[
        "inspect",
        "--statement",
        &statement,
        "--decode",
        "['artifact']",
        "--decode-as",
        "base64url",
    ]);
    assert_eq!(r.code, 3, "{}", r.stderr);
}

/// `--decode-out` must never be allowed to consume the statement.
///
/// The statement is read into memory before the write, so overwriting it would
/// not fail — it would exit 0, having replaced the evidence with the document
/// that was inside it. An operator who typed the same filename twice would be
/// left with no statement and a report saying everything was fine.
#[test]
fn decode_out_refuses_to_overwrite_the_statement_it_read() {
    let dir = std::env::temp_dir().join("scitt-verifier-decode-out");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let statement = dir.join("s.cose");
    let original = std::fs::read(corpus(&["fixtures", "cbor-header.cose"])).unwrap();
    std::fs::write(&statement, &original).unwrap();

    let path = statement.display().to_string();
    let r = run(&[
        "inspect",
        "--statement",
        &path,
        "--decode",
        "['artifact']",
        "--decode-out",
        &path,
    ]);

    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(r.stderr.contains("overwrite"), "{}", r.stderr);
    assert_eq!(
        std::fs::read(&statement).unwrap(),
        original,
        "the statement must be byte-identical after a refused write"
    );
}

/// The success path, driven through the binary.
///
/// Unit tests cover the decoder and the renderer separately, so both can pass
/// while the argument plumbing between them is broken: a flag parsed into the
/// wrong field, `Decoded` never reaching a renderer, `--decode-out` writing
/// the preview instead of the bytes. Only running the binary catches that.
///
/// No corpus fixture carries a base64-bearing claim, and minting one is a full
/// corpus regeneration. So the statement is built here instead. That is sound
/// precisely because `inspect` authenticates nothing — it parses and describes,
/// and a well-formed COSE_Sign1 with a dummy signature is a legitimate input to
/// it. Nothing in it refers to anything that exists.
///
/// The payload publishes the digest of its own decoded claim, in the shape
/// real producers use, so the assertion is the document's own answer rather
/// than a constant invented here.
#[test]
fn decode_reports_the_digest_the_payload_publishes_for_itself() {
    const DECODED: &[u8] = b"package policy\n";
    const SHA256: &str = "89d09cb5c2f579afa733a1f68ae0dd5ff13e59efa75b870c64ca9fd62e9ec139";
    let payload =
        format!("{{\"policy-base64\":\"cGFja2FnZSBwb2xpY3kK\",\"policy-sha256\":\"{SHA256}\"}}");

    let dir = std::env::temp_dir().join("scitt-verifier-decode-success");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let statement = dir.join("s.cose");
    std::fs::write(&statement, json_payload_sign1(payload.as_bytes())).unwrap();

    let path = statement.display().to_string();
    let out = dir.join("policy.rego");
    let out_arg = out.display().to_string();

    // JSON: the decoded object must be a root-level sibling of the payload,
    // and must agree with the digest the payload itself carries.
    let r = run(&[
        "inspect",
        "--statement",
        &path,
        "--format",
        "json",
        "--verbose",
        "--decode",
        "['policy-base64']",
        "--decode-out",
        &out_arg,
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}\nstderr:\n{}", r.stdout, r.stderr);

    let doc: serde_json::Value = serde_json::from_str(&r.stdout).expect("valid JSON");
    let decoded = doc.get("decoded").expect("a root-level decoded object");
    let published = doc
        .pointer("/payload/json/policy-sha256")
        .and_then(|v| v.as_str())
        .expect("the payload publishes its own digest");

    assert_eq!(decoded["sha256"].as_str(), Some(published));
    assert_eq!(decoded["sha256"].as_str(), Some(SHA256));
    assert_eq!(decoded["bytes"].as_u64(), Some(DECODED.len() as u64));
    assert_eq!(decoded["encoding"].as_str(), Some("base64"));
    assert_eq!(decoded["path"].as_str(), Some("['policy-base64']"));
    assert_eq!(decoded["utf8"].as_bool(), Some(true));
    assert_eq!(decoded["previewTruncated"].as_bool(), Some(false));
    // Decoding is not verification, and the field that says so must survive
    // into the document a consumer reads.
    assert_eq!(decoded["authenticated"].as_bool(), Some(false));
    assert!(doc
        .get("payload")
        .is_some_and(|p| p.get("decoded").is_none()));

    // --decode-out writes the exact bytes, not the rendering.
    assert_eq!(std::fs::read(&out).unwrap(), DECODED);

    // Text: the same digest reaches the other renderer.
    let r = run(&[
        "inspect",
        "--statement",
        &path,
        "--decode",
        "['policy-base64']",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains(SHA256), "{}", r.stdout);
    assert!(r.stdout.contains("package policy"), "{}", r.stdout);
    assert!(r.stdout.contains("not verified"), "{}", r.stdout);
}

/// Build a tagged COSE_Sign1 carrying `payload` as declared JSON.
///
/// Written by hand rather than with a CBOR library so the test suite does not
/// gain a dependency in order to describe twenty bytes of header. The
/// signature is zeroes: `inspect` never checks one, and a real signature here
/// would imply this fixture says something about provenance, which it does not.
fn json_payload_sign1(payload: &[u8]) -> Vec<u8> {
    // {1: -7, 3: "application/json"} — alg ES256, content type.
    let mut protected = vec![0xa2, 0x01, 0x26, 0x03, 0x70];
    protected.extend_from_slice(b"application/json");

    let mut out = vec![0xd2, 0x84];
    push_bstr(&mut out, &protected);
    out.push(0xa0); // no unprotected headers
    push_bstr(&mut out, payload);
    push_bstr(&mut out, &[0u8; 64]);
    out
}

/// Append a CBOR byte string, choosing the shortest length encoding.
fn push_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    let n = bytes.len();
    match n {
        0..=23 => out.push(0x40 | n as u8),
        24..=255 => out.extend_from_slice(&[0x58, n as u8]),
        256..=65535 => {
            out.push(0x59);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => panic!("fixture payload is larger than this helper encodes"),
    }
    out.extend_from_slice(bytes);
}

/// The refusal must survive an output that only *aliases* the statement.
///
/// Comparing directory and file name cannot see a symlink: the two names
/// differ and only the target is shared, so the write would land on the
/// statement despite the guard. Resolving both paths when they exist is what
/// closes that, and this is the case that proves it.
#[test]
fn decode_out_refuses_an_output_that_is_a_symlink_to_the_statement() {
    let dir = std::env::temp_dir().join("scitt-verifier-decode-symlink");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let statement = dir.join("s.cose");
    let original = std::fs::read(corpus(&["fixtures", "cbor-header.cose"])).unwrap();
    std::fs::write(&statement, &original).unwrap();

    let alias = dir.join("alias.bin");
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&statement, &alias).is_ok();
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&statement, &alias).is_ok();
    if !made {
        // Creating a symlink needs a privilege this runner may not hold. The
        // guard is still exercised by the plain-path and case-alias tests, so
        // skipping is better than asserting on a link that was never created.
        return;
    }

    let r = run(&[
        "inspect",
        "--statement",
        &statement.display().to_string(),
        "--decode",
        "['artifact']",
        "--decode-out",
        &alias.display().to_string(),
    ]);

    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(r.stderr.contains("overwrite"), "{}", r.stderr);
    assert_eq!(
        std::fs::read(&statement).unwrap(),
        original,
        "the statement must survive a write aimed at a symlink to it"
    );
}

/// The same guard, against an alias that needs no special privilege.
///
/// The symlink case above is skipped on a Windows runner without the
/// privilege to create one, which would leave the resolving path untested on
/// the platform where it is hardest to reason about. A differently-cased name
/// is the same file there, and comparing file names as strings does not see
/// it, so this exercises the same fix and always runs.
#[cfg(windows)]
#[test]
fn decode_out_refuses_an_output_that_differs_from_the_statement_only_by_case() {
    let dir = std::env::temp_dir().join("scitt-verifier-decode-case");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let statement = dir.join("s.cose");
    let original = std::fs::read(corpus(&["fixtures", "cbor-header.cose"])).unwrap();
    std::fs::write(&statement, &original).unwrap();

    let r = run(&[
        "inspect",
        "--statement",
        &statement.display().to_string(),
        "--decode",
        "['artifact']",
        "--decode-out",
        &dir.join("S.COSE").display().to_string(),
    ]);

    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(r.stderr.contains("overwrite"), "{}", r.stderr);
    assert_eq!(std::fs::read(&statement).unwrap(), original);
}

/// A payload offering two values for one claim has no answer to report.
///
/// `payloadJson` already refuses a document with duplicate keys as ambiguous,
/// and `--decode` now shares that parser rather than `serde_json::from_slice`,
/// which silently takes the last value. There is no acceptance test here
/// because no fixture carries a duplicate key and minting one is a corpus
/// regeneration; the shared parser's own tests cover the refusal.
///
/// Only a payload the statement declares to be JSON has claims to address.
///
/// This is the same rule `payloadJson` follows. Reading claims out of a
/// payload whose content type says it is something else would let a decode
/// succeed against bytes the producer never described that way.
#[test]
fn decode_refuses_a_payload_the_statement_did_not_declare_as_json() {
    let statement = corpus(&["fixtures", "transparent-statement.cose"]);
    let r = run(&["inspect", "--statement", &statement, "--decode", "['x']"]);
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(r.stderr.contains("not JSON"), "{}", r.stderr);
}

/// `--trusted-roots` must be answerable "no".
///
/// The failure this defends against is silent: before the chain was actually
/// anchored, supplying roots the statement does not lead to still exited 0.
/// An operator who names the CAs they accept has asked a question, and a
/// pipeline that green-lights the answer "not one of yours" is worse than one
/// that never asked.
#[test]
fn trusted_roots_that_the_chain_does_not_reach_make_the_run_untrusted() {
    let dir = std::env::temp_dir().join("scitt-verifier-trusted-roots");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let chain = fixture_chain();

    // The chain's own root, which must be accepted.
    let real = dir.join("real-root.pem");
    std::fs::write(&real, pem(chain.last().unwrap())).unwrap();

    // A certificate from the same chain that is not its root. Real bytes, and
    // genuinely the wrong anchor.
    let wrong = dir.join("wrong-root.pem");
    std::fs::write(&wrong, pem(&chain[0])).unwrap();

    let accepted = verify(&["--trusted-roots", &real.display().to_string()]);
    assert_eq!(
        accepted.code, 0,
        "the chain's own root must anchor it:\n{}",
        accepted.stdout
    );
    assert!(
        !accepted
            .stdout
            .contains("CertificateChainNotAnchoredExternally"),
        "a supplied root must retire the not-anchored gap:\n{}",
        accepted.stdout
    );

    let refused = verify(&["--trusted-roots", &wrong.display().to_string()]);
    assert_eq!(
        refused.code, 1,
        "a chain that reaches none of the supplied roots is untrusted, not a gap:\n{}",
        refused.stdout
    );
    assert!(
        refused.stdout.contains("CertificateChainInvalid"),
        "the refusal must say why:\n{}",
        refused.stdout
    );

    // A block that base64-decodes to something that is not a certificate. This
    // exited 0 before the roots file was parsed rather than merely decoded:
    // the strong flag was accepted and the weak check silently run.
    let garbage = dir.join("not-a-certificate.pem");
    std::fs::write(
        &garbage,
        "-----BEGIN CERTIFICATE-----\nAQIDBAUGBwgJCgsMDQ4PEA==\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let broken = verify(&["--trusted-roots", &garbage.display().to_string()]);
    assert_eq!(
        broken.code, 4,
        "an unusable roots file is a broken invocation, never a quiet downgrade:\n{}",
        broken.stdout
    );
}

/// The certificates the corpus statement actually carries, leaf first.
fn fixture_chain() -> Vec<Vec<u8>> {
    let bytes = std::fs::read(corpus(&["fixtures", "transparent-statement.cose"])).unwrap();
    let statement = scitt_receipt::Sign1::parse(&bytes).expect("fixture must parse");
    let chain = statement.x5chain();
    assert!(chain.len() > 1, "fixture must carry a chain to anchor");
    chain
}

fn pem(der: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for block in der.chunks(3) {
        let b = [
            block[0],
            *block.get(1).unwrap_or(&0),
            *block.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= block.len() {
                encoded.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 0x3f] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    let wrapped: Vec<String> = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        wrapped.join("\n")
    )
}
