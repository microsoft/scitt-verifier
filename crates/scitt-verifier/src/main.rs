//! `scitt-verifier` — an offline gate for SCITT transparent statements.
//!
//! Reads bytes, produces a verdict and a verification record, and exits with a
//! code a pipeline can branch on. Nothing here reaches the network: the trust
//! material is an input, so a verification that succeeds on a laptop succeeds
//! identically on an air-gapped build agent three months later.

mod cli;
mod inspect_json;
mod outcome;
mod record;
mod report;

use cli::{BindingMode, Command, Format, VerifyArgs};
use outcome::{
    Assessment, Binding, BindingResult, Category, CheckState, Checks, Diagnostic, Gap, Severity,
    Trust, Verdict,
};
use scitt_policy::{Outcome as AssertionOutcome, Policy, PolicyDecision};
use scitt_receipt::{verify_statement, LedgerKeySet, Sign1, StatementFacts};
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let command = match cli::parse(&args) {
        Ok(c) => c,
        // The one place that cannot honour --format: the flag itself did not
        // parse, so there is no format to honour. Documented in docs/output.md.
        Err(message) => {
            eprintln!("error: {message}\n");
            eprintln!("{}", cli::USAGE);
            return ExitCode::from(Verdict::UsageError.exit_code());
        }
    };

    match command {
        Command::Help => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("scitt-verifier {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Inspect(args) => ExitCode::from(run_inspect(&args)),
        Command::Verify(args) => ExitCode::from(run_verify(&args).exit_code()),
    }
}

/// Describe a statement without judging it.
///
/// Useful before a policy exists: you cannot write a rule about an issuer you
/// have not seen. `inspect` makes no trust decision, so it never returns 1 or
/// 2. It distinguishes two failures that are genuinely different: input we
/// could not read (exit 4, the operator's problem) and input we could read but
/// not decode (exit 3, a real finding about the file).
fn run_inspect(args: &cli::InspectArgs) -> u8 {
    let path = &args.statement;
    let bytes = match read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return Verdict::UsageError.exit_code();
        }
    };
    let statement = match Sign1::parse(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: {} is not a decodable COSE_Sign1: {e}",
                path.display()
            );
            return Verdict::CannotEvaluate.exit_code();
        }
    };

    match args.format {
        Format::Json => {
            let document = inspect_json::document(&statement, args.verbose);
            match serde_json::to_string_pretty(&document) {
                Ok(text) => {
                    println!("{text}");
                    0
                }
                Err(e) => {
                    eprintln!("error: could not render the inspect document: {e}");
                    Verdict::CannotEvaluate.exit_code()
                }
            }
        }
        Format::Text => match report::inspect(&statement, args.verbose) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                Verdict::CannotEvaluate.exit_code()
            }
        },
    }
}
fn run_verify(args: &VerifyArgs) -> Verdict {
    let now = args.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });

    let assessment = evaluate(args, now);
    emit(args, assessment, now)
}

/// Run the checks. Never prints, never writes, never exits.
///
/// Keeping this free of side effects is what makes the "always emit evidence"
/// guarantee cheap: there is exactly one return type, so there is exactly one
/// place that has to know how to serialise a partial result.
fn evaluate(args: &VerifyArgs, now: i64) -> Assessment {
    let trust = Trust::unsigned_key_set(args.issuer.clone());

    let statement_bytes = match read(&args.statement) {
        Ok(b) => b,
        Err(e) => {
            return Assessment::incomplete(
                Verdict::UsageError,
                trust,
                Diagnostic::error(
                    "StatementUnreadable",
                    Category::Input,
                    e,
                    "Check the --statement path and that the file was produced by the build.",
                ),
                gaps(args, None, None),
            )
        }
    };
    let key_bytes =
        match read(&args.scitt_keys) {
            Ok(b) => b,
            Err(e) => return Assessment::incomplete(
                Verdict::UsageError,
                trust,
                Diagnostic::error(
                    "TrustMaterialUnreadable",
                    Category::Input,
                    e,
                    "Check the --scitt-keys path. See docs/trust-material.md to obtain a key set.",
                ),
                gaps(args, None, None),
            ),
        };
    let policy_bytes = match read(&args.policy) {
        Ok(b) => b,
        Err(e) => {
            return Assessment::incomplete(
                Verdict::UsageError,
                trust,
                Diagnostic::error(
                    "PolicyUnreadable",
                    Category::Input,
                    e,
                    "Check the --policy path.",
                ),
                gaps(args, None, None),
            )
        }
    };

    let policy = match Policy::from_json(&policy_bytes) {
        Ok(p) => p,
        Err(e) => {
            return Assessment::incomplete(
                Verdict::UsageError,
                trust,
                Diagnostic::error(
                    "PolicyMalformed",
                    Category::Input,
                    e,
                    "Fix the policy document. A policy this tool cannot parse is a policy nobody is enforcing.",
                ),
                gaps(args, None, None),
            )
        }
    };

    let key_set = match LedgerKeySet::from_cose_key_set(&key_bytes, args.issuer.clone()) {
        Ok(k) => k,
        // Unusable trust material is not evidence that the artifact is bad.
        // Exit 3, not 1.
        Err(e) => {
            return Assessment::incomplete(
                Verdict::CannotEvaluate,
                trust,
                Diagnostic::error(
                    "TrustMaterialUnusable",
                    Category::Trust,
                    e.to_string(),
                    "Re-fetch the key set with tools/scitt-keys.py fetch.",
                ),
                gaps(args, None, None),
            )
        }
    };

    let facts = match verify_statement(&statement_bytes, &key_set) {
        Ok(f) => f,
        Err(e) => {
            let (verdict, diagnostic) = classify_core_error(&e);
            return Assessment::incomplete(verdict, trust, diagnostic, gaps(args, None, None));
        }
    };

    let binding = match check_binding(args, &statement_bytes) {
        Ok(b) => b,
        Err(e) => {
            let mut a = Assessment::incomplete(
                Verdict::UsageError,
                trust,
                Diagnostic::error(
                    "ArtifactUnreadable",
                    Category::Input,
                    e.clone(),
                    "Check the --artifact path.",
                ),
                gaps(args, Some(&facts), None),
            );
            // The statement checks did run, so report them rather than
            // pretending the whole run established nothing.
            a.checks.statement_signature = signature_state(&facts);
            a.checks.receipt_inclusion = receipt_state(&facts);
            // The operator *did* ask for a binding; we could not find out.
            // That is cannot-evaluate, not not-checked — reporting it as the
            // latter would claim nobody asked.
            a.checks.artifact_binding = CheckState::CannotEvaluate;
            a.binding = BindingResult {
                outcome: Binding::CannotCompare,
                detail: format!("artifact binding was requested but could not be checked: {e}"),
            };
            a.facts = Some(facts);
            return a;
        }
    };

    let decision = policy.evaluate(&facts, now);

    let checks = Checks {
        statement_signature: signature_state(&facts),
        receipt_inclusion: receipt_state(&facts),
        artifact_binding: binding.state(),
        policy: policy_state(&decision),
    };

    let verdict = decide(&facts, &binding, &decision, args.binding_mode);
    let mut diagnostics = diagnose(&facts, &binding, &decision);
    if verdict == Verdict::StatementTransparent {
        // A pass, but a narrower one than most readers assume. Recorded as a
        // diagnostic so a pipeline can gate on it without parsing prose.
        diagnostics.push(Diagnostic::warning(
            "ArtifactBindingNotRequested",
            Category::Binding,
            "the statement is transparent, but no artifact binding was requested, \
             so this run does not establish which artifact it describes",
            "Pass --artifact and --binding-mode payload-bytes to make a claim about the deployed bytes.",
        ));
    }
    let primary = choose_primary(verdict, &diagnostics);

    Assessment {
        verdict,
        primary,
        diagnostics,
        checks,
        not_checked: gaps(args, Some(&facts), Some(&decision)),
        trust,
        facts: Some(facts),
        decision: Some(decision),
        binding,
    }
}

/// Write the record and any facts projection, then print the result. One place,
/// every path.
///
/// Takes the assessment by value because a failed write has to change it.
/// Printing a document that says `artifact-transparent` while exiting 4 would
/// hand a consumer two contradictory answers from the same run.
fn emit(args: &VerifyArgs, mut assessment: Assessment, now: i64) -> Verdict {
    let mut failures = Vec::new();

    if let Some(path) = &args.result {
        if let Err(d) = write_json(
            path,
            "verification record",
            &record::build(args, &assessment, now),
        ) {
            failures.push(d);
        }
    }
    if let Some(path) = &args.facts {
        if let Err(d) = write_json(
            path,
            "facts document",
            &record::facts(args, &assessment, now),
        ) {
            failures.push(d);
        }
    }

    if !failures.is_empty() {
        // A pass whose audit trail vanished is not a pass a gate should act on.
        // Failures keep their own, more important, verdict and diagnostic.
        if assessment.verdict.is_pass() {
            assessment.verdict = Verdict::UsageError;
            assessment.primary = Some(failures[0].clone());
        }
        assessment.diagnostics.extend(failures);
    }

    // Built after the write outcome is known, so stdout agrees with the exit
    // code even when the file could not be written.
    match args.format {
        Format::Json => println!("{:#}", record::build(args, &assessment, now)),
        Format::Text => report::verify(&assessment),
    }

    assessment.verdict
}

fn write_json(path: &Path, what: &str, document: &serde_json::Value) -> Result<(), Diagnostic> {
    std::fs::write(path, format!("{document:#}\n")).map_err(|e| {
        eprintln!("error: could not write {what} to {}: {e}", path.display());
        Diagnostic::error(
            "RecordWriteFailed",
            Category::Internal,
            format!("could not write {what} to {}: {e}", path.display()),
            "Check that the output directory exists and is writable.",
        )
    })
}

fn signature_state(facts: &StatementFacts) -> CheckState {
    match facts.signature_valid {
        Some(true) => CheckState::Pass,
        Some(false) => CheckState::Fail,
        None => CheckState::CannotEvaluate,
    }
}

/// Whether the statement's transparency was established.
///
/// A receipt that failed is deliberately *not* a `Fail` here. Receipts arrive
/// in the unprotected header, which no signature covers, so their presence is
/// not attributable to the issuer, the transparency service, or anyone else.
/// Treating a broken one as a failed check would let whoever handed us the
/// file decide the answer. See RFC 9943 s7.1: a Relying Party need only trust
/// "at least one Issuer of a Receipt", and MAY verify a single acceptable
/// Receipt and disregard the rest.
fn receipt_state(facts: &StatementFacts) -> CheckState {
    if facts.any_receipt_verified() {
        return CheckState::Pass;
    }
    // No receipts, none we could resolve a key for, or none that verified.
    // Either way the transparency question is open, not answered in the
    // negative.
    CheckState::CannotEvaluate
}

fn policy_state(decision: &PolicyDecision) -> CheckState {
    if decision.failed() {
        CheckState::Fail
    } else if decision.unevaluable() {
        CheckState::CannotEvaluate
    } else if decision.satisfied() {
        CheckState::Pass
    } else {
        CheckState::CannotEvaluate
    }
}

/// Turn facts into a verdict.
///
/// Precedence is deliberate: cryptographic failure outranks everything, then
/// inability to evaluate, then policy. A run that both failed a signature and
/// failed a policy rule is reported as untrusted, because that is the finding
/// that matters.
///
/// `Untrusted` is reserved for the two findings that indict the bytes in front
/// of us: the statement's own signature, and a binding mismatch. A broken
/// receipt indicts neither. Receipts live in the unprotected header, so anyone
/// who handles the file can add one without holding a key; letting that decide
/// the verdict would hand every courier a veto over the gate.
fn decide(
    facts: &StatementFacts,
    binding: &BindingResult,
    decision: &PolicyDecision,
    mode: BindingMode,
) -> Verdict {
    if facts.signature_valid == Some(false) || binding.outcome == Binding::Mismatch {
        return Verdict::Untrusted;
    }

    // No verified receipt means the statement is, at best, merely signed.
    // That can never be a pass, whatever the policy says. Note this is the
    // only receipt-derived gate: transparency is a positive proof, and a proof
    // that holds cannot be retracted by appending noise beside it.
    if !facts.any_receipt_verified() {
        return Verdict::CannotEvaluate;
    }
    if facts.signature_valid.is_none() {
        return Verdict::CannotEvaluate;
    }

    if decision.failed() {
        return Verdict::PolicyFailed;
    }
    if decision.unevaluable() {
        return Verdict::CannotEvaluate;
    }
    if !decision.satisfied() {
        return Verdict::CannotEvaluate;
    }

    // Everything held. Which success this is depends entirely on whether the
    // operator asked us to look at an artifact — a question the tool must
    // never answer on their behalf.
    match (mode, binding.outcome) {
        (BindingMode::PayloadBytes, Binding::Bound) => Verdict::ArtifactTransparent,
        // A requested comparison that could not be made is not a success of
        // either kind. Falling through to `statement-transparent` here would
        // quietly downgrade the operator's request into a claim about the
        // statement alone.
        (BindingMode::PayloadBytes, Binding::CannotCompare) => Verdict::CannotEvaluate,
        _ => Verdict::StatementTransparent,
    }
}

/// Every problem worth naming, in no particular order.
fn diagnose(
    facts: &StatementFacts,
    binding: &BindingResult,
    decision: &PolicyDecision,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();

    if facts.signature_valid == Some(false) {
        out.push(Diagnostic::error(
            "StatementSignatureInvalid",
            Category::Crypto,
            "the statement's own signature did not verify",
            "Treat this artifact as untrusted. Do not deploy it.",
        ));
    }
    if facts.signature_valid.is_none() {
        out.push(Diagnostic::error(
            "StatementSignatureNotEvaluated",
            Category::Unsupported,
            "the statement signature could not be evaluated",
            "Check the algorithm and certificate chain with `scitt-verifier inspect`.",
        ));
    }

    for (i, r) in facts.receipts.iter().enumerate() {
        let n = i + 1;
        // These are warnings, not errors, however alarming they read. Neither
        // says anything about the artifact: a receipt that fails to verify is
        // indistinguishable from one an attacker appended, because appending
        // one requires no key. What it does say is that this receipt carried
        // no weight in the verdict.
        if r.root_signature_valid == Some(false) {
            out.push(Diagnostic::warning(
                "ReceiptRootSignatureInvalid",
                Category::Crypto,
                format!("receipt {n}: the Merkle root signature did not verify"),
                "This receipt proves nothing and was disregarded; the verdict rests on the receipts that did verify. If you expected it to count, re-fetch the transparent statement from the transparency service.",
            ));
        }
        if r.bound_to_statement == Some(false) {
            out.push(Diagnostic::warning(
                "ReceiptNotBoundToStatement",
                Category::Crypto,
                format!("receipt {n}: the inclusion proof is for a different statement"),
                "This receipt describes another statement and was disregarded; the verdict rests on the receipts that did verify. If you expected it to count, confirm you fetched the receipt issued for this statement.",
            ));
        }
        match r.key_lookup {
            Some(scitt_receipt::KeyLookup::UnknownKid) => out.push(Diagnostic::error(
                "ReceiptKeyUnknown",
                Category::Trust,
                format!(
                    "receipt {n}: no key in the supplied set matches kid {}",
                    r.kid.as_deref().unwrap_or("(none)")
                ),
                "Refresh the committed SCITT key set: tools/scitt-keys.py fetch.",
            )),
            Some(scitt_receipt::KeyLookup::IssuerMismatch) => out.push(Diagnostic::error(
                "ReceiptIssuerNotInScope",
                Category::Trust,
                format!("receipt {n}: the key set is scoped to a different issuer"),
                "Check --issuer against the transparency service that registered this statement.",
            )),
            Some(scitt_receipt::KeyLookup::Revoked) => out.push(Diagnostic::error(
                "ReceiptKeyRevoked",
                Category::Trust,
                format!("receipt {n}: the signing key is marked revoked"),
                "Do not accept this receipt. Escalate to the transparency service operator.",
            )),
            _ => {}
        }
    }

    if facts.receipts.is_empty() {
        out.push(Diagnostic::error(
            "NoReceipt",
            Category::Trust,
            "the statement carries no receipt, so it is signed but not transparent",
            "Register the statement with a transparency service before deploying it.",
        ));
    } else if !facts.any_receipt_verified() {
        out.push(Diagnostic::error(
            "NoVerifiedReceipt",
            Category::Trust,
            "no receipt on this statement could be fully verified",
            "Refresh the SCITT trust material, then re-run.",
        ));
    }

    match binding.outcome {
        Binding::Mismatch => out.push(Diagnostic::error(
            "ArtifactBindingMismatch",
            Category::Binding,
            binding.detail.clone(),
            "The registered statement does not describe this artifact. Do not deploy it.",
        )),
        Binding::CannotCompare => out.push(Diagnostic::error(
            "ArtifactBindingUnevaluable",
            Category::Binding,
            binding.detail.clone(),
            "This run does not establish which artifact the statement describes. \
             A detached statement needs a binding mode that compares digests.",
        )),
        Binding::Bound | Binding::NotRequested => {}
    }

    for r in &decision.results {
        match r.outcome {
            AssertionOutcome::Fail => out.push(Diagnostic::error(
                "PolicyAssertionFailed",
                Category::Policy,
                format!("policy assertion '{}' failed: {}", r.name, r.detail),
                "Review the relying-party policy or the signer identity.",
            )),
            AssertionOutcome::CannotEvaluate => out.push(Diagnostic::error(
                "PolicyAssertionUnevaluable",
                Category::Policy,
                format!(
                    "policy assertion '{}' could not be evaluated: {}",
                    r.name, r.detail
                ),
                "The statement does not carry the claim this assertion needs.",
            )),
            AssertionOutcome::Pass => {}
        }
    }

    // A policy can parse, be non-empty, and still evaluate to nothing — a
    // document whose only assertion is `requireKidBoundToKey: false`, for
    // instance. That is never a pass, so it must be a named failure rather
    // than a silent exit 3.
    if decision.results.is_empty() {
        out.push(Diagnostic::error(
            "PolicyProducedNoAssertions",
            Category::Policy,
            format!(
                "policy {} v{} parsed but evaluated no assertions, so it made no decision",
                decision.policy_id, decision.policy_version
            ),
            "Add at least one assertion that applies to this statement. See docs/policy.md.",
        ));
    }

    out
}

/// The one diagnostic that explains the exit code.
///
/// Without this a caller must scan several arrays to work out what stopped the
/// deployment, and will usually report the first thing they find rather than
/// the thing that decided the verdict.
///
/// A non-pass verdict always gets one. A red gate with no stated reason is
/// worse than no gate, because the operator has nowhere to start.
fn choose_primary(verdict: Verdict, diagnostics: &[Diagnostic]) -> Option<Diagnostic> {
    if verdict.is_pass() {
        return None;
    }
    let wanted: &[Category] = match verdict {
        Verdict::Untrusted => &[Category::Crypto, Category::Binding],
        Verdict::PolicyFailed => &[Category::Policy],
        Verdict::CannotEvaluate => &[Category::Trust, Category::Unsupported, Category::Policy],
        _ => &[Category::Input, Category::Internal],
    };
    for category in wanted {
        if let Some(d) = diagnostics
            .iter()
            .find(|d| d.category == *category && d.severity == Severity::Error)
        {
            return Some(d.clone());
        }
    }
    if let Some(d) = diagnostics
        .iter()
        .find(|d| d.severity == Severity::Error)
        .cloned()
    {
        return Some(d);
    }
    // Backstop, so that "every failure names its cause" is structural rather
    // than a property of whichever diagnostics happen to have been generated.
    Some(Diagnostic::error(
        "UnexplainedFailure",
        Category::Internal,
        format!(
            "the run produced verdict '{}' without naming a cause; this is a bug in scitt-verifier",
            verdict.as_str()
        ),
        "Please report this with the evidence record at https://github.com/microsoft/scitt-verifier/issues.",
    ))
}

fn classify_core_error(e: &scitt_receipt::Error) -> (Verdict, Diagnostic) {
    use scitt_receipt::Error::*;
    match e {
        // "I do not implement this" is never evidence of compromise.
        UnsupportedVds(_) | UnsupportedAlgorithm(_) => (
            Verdict::CannotEvaluate,
            Diagnostic::error(
                "UnsupportedFeature",
                Category::Unsupported,
                e.to_string(),
                "This build cannot check this statement. Do not read the exit code as a finding about the artifact.",
            ),
        ),
        TrustMaterial(_) => (
            Verdict::CannotEvaluate,
            Diagnostic::error(
                "TrustMaterialUnusable",
                Category::Trust,
                e.to_string(),
                "Re-fetch the key set with tools/scitt-keys.py fetch.",
            ),
        ),
        UnknownKid(_) => (
            Verdict::CannotEvaluate,
            Diagnostic::error(
                "ReceiptKeyUnknown",
                Category::Trust,
                e.to_string(),
                "Refresh the committed SCITT key set: tools/scitt-keys.py fetch.",
            ),
        ),
        IssuerMismatch { .. } => (
            Verdict::CannotEvaluate,
            Diagnostic::error(
                "ReceiptIssuerNotInScope",
                Category::Trust,
                e.to_string(),
                "Check --issuer against the transparency service that registered this statement.",
            ),
        ),
        Crypto(_) => (
            Verdict::CannotEvaluate,
            Diagnostic::error(
                "CryptoBackendError",
                Category::Unsupported,
                e.to_string(),
                "This is a limitation of the tool, not a finding about the artifact.",
            ),
        ),
        // A truncated download is not evidence of compromise, so this is exit
        // 3 rather than 1 — but it is still never a pass. See docs/output.md
        // for why this boundary sits here.
        Malformed(_) | Structure(_) => (
            Verdict::CannotEvaluate,
            Diagnostic::error(
                "StatementMalformed",
                Category::Input,
                e.to_string(),
                "Re-download the statement. If it is still malformed, the producer emitted an invalid file.",
            ),
        ),
    }
}

/// What this run did *not* establish.
///
/// Reported unconditionally, including on success. A green result that quietly
/// skipped the artifact binding is more dangerous than a red one, because
/// nobody goes looking for the caveat.
fn gaps(
    args: &VerifyArgs,
    facts: Option<&StatementFacts>,
    decision: Option<&PolicyDecision>,
) -> Vec<Gap> {
    let mut gaps = Vec::new();

    if args.binding_mode == BindingMode::None {
        gaps.push(Gap::new(
            "ArtifactBindingNotRequested",
            Category::Binding,
            "No artifact binding was requested, so this run does not establish which artifact \
             the statement describes.",
            "the verdict covers the statement only, not the thing being deployed",
        ));
    }

    if args.issuer.is_none() {
        gaps.push(Gap::new(
            "IssuerScopeNotPinned",
            Category::Trust,
            "The key set was not scoped to an issuer (--issuer), so a receipt from a different \
             transparency service using a known kid would not be rejected on issuer grounds.",
            "receipt validity does not establish which service issued it",
        ));
    }

    // The statement signature is checked against the key in its own certificate.
    // Chain validation to a trusted root is a separate question this release
    // does not answer, and saying so is the whole point of this section.
    match facts.map(|f| f.certificate_chain_len) {
        Some(0) => gaps.push(Gap::new(
            "NoCertificateChain",
            Category::SignerIdentity,
            "The statement carried no certificate chain.",
            "the signer's identity rests entirely on policy assertions about CWT claims",
        )),
        Some(_) => gaps.push(Gap::new(
            "CertificateChainNotValidated",
            Category::SignerIdentity,
            "The signing certificate chain was not validated to a trusted root; the statement \
             signature was checked against the leaf certificate embedded in the statement itself.",
            "signature validity does not establish CA trust",
        )),
        None => {}
    }

    gaps.push(Gap::new(
        "RevocationNotChecked",
        Category::SignerIdentity,
        "Certificate revocation was not checked (this tool runs offline).",
        "a revoked signing certificate would still verify here",
    ));

    match decision {
        Some(d) => {
            for r in &d.results {
                if r.outcome == AssertionOutcome::CannotEvaluate {
                    gaps.push(Gap::new(
                        "PolicyAssertionUnevaluable",
                        Category::Policy,
                        format!(
                            "Policy assertion '{}' could not be evaluated: {}",
                            r.name, r.detail
                        ),
                        "this rule neither passed nor failed; it was skipped",
                    ));
                }
            }
        }
        None => gaps.push(Gap::new(
            "PolicyNotEvaluated",
            Category::Policy,
            "No policy was evaluated.",
            "no relying-party decision was made about these facts",
        )),
    }

    gaps
}

fn check_binding(args: &VerifyArgs, statement_bytes: &[u8]) -> Result<BindingResult, String> {
    let Some(artifact_path) = &args.artifact else {
        return Ok(BindingResult::not_requested());
    };

    let artifact = read(artifact_path)?;
    let statement = Sign1::parse(statement_bytes).map_err(|e| e.to_string())?;

    match args.binding_mode {
        BindingMode::None => Ok(BindingResult::not_requested()),
        BindingMode::PayloadBytes => {
            let Some(payload) = statement.payload.as_deref() else {
                // A detached payload is not a mismatch. There is nothing to
                // compare, so `payload-bytes` cannot answer the question —
                // reporting Some(false) here accused the operator of shipping
                // a tampered artifact when the real problem is that this
                // binding mode does not apply to a detached statement.
                return Ok(BindingResult {
                    outcome: Binding::CannotCompare,
                    detail: "the statement payload is detached, so binding-mode payload-bytes \
                             has nothing to compare the artifact against"
                        .into(),
                });
            };
            let bound = payload == artifact.as_slice();
            Ok(BindingResult {
                outcome: if bound {
                    Binding::Bound
                } else {
                    Binding::Mismatch
                },
                detail: if bound {
                    format!(
                        "the statement payload is byte-identical to {} ({} bytes)",
                        artifact_path.display(),
                        artifact.len()
                    )
                } else {
                    format!(
                        "the statement payload ({} bytes, sha256 {}) does not equal {} ({} bytes, sha256 {})",
                        payload.len(),
                        scitt_receipt::sha256_hex(payload),
                        artifact_path.display(),
                        artifact.len(),
                        scitt_receipt::sha256_hex(&artifact),
                    )
                },
            })
        }
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))
}
