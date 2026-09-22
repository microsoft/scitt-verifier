//! `scitt-verifier` — an offline gate for SCITT transparent statements.
//!
//! Reads bytes, produces a verdict and a verification record, and exits with a
//! code a pipeline can branch on. Nothing here reaches the network: the trust
//! material is an input, so a verification that succeeds on a laptop succeeds
//! identically on an air-gapped build agent three months later.

mod cli;
mod decode;
mod inspect_json;
mod online;
mod outcome;
mod record;
mod report;

use cli::{BindingMode, Command, Format, TrustSource, VerifyArgs};
use outcome::{
    Acquisition, Assessment, Binding, BindingResult, Category, CheckState, Checks, Diagnostic, Gap,
    Severity, Trust, Verdict,
};
use scitt_policy::{Outcome as AssertionOutcome, Policy, PolicyDecision};
use scitt_receipt::binding::{
    Binding as CoreBinding, BindingMode as CoreBindingMode, BindingReason as CoreBindingReason,
};
use scitt_receipt::{
    chain::Outcome as ChainOutcome, verify_statement_with, LedgerKeySet, Sign1, StatementFacts,
    VerifyOptions,
};
use std::path::{Path, PathBuf};
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

    // Checked before the file is even read. Writing the decoded bytes over
    // the statement would destroy the evidence in order to report on it, and
    // because the read happens first it would not fail — it would exit 0
    // beside a COSE file replaced by the policy that was inside it. The same
    // guard protects the record and facts documents elsewhere in this file.
    if let Some(out) = &args.decode_out {
        if same_file(out, path) {
            eprintln!(
                "error: --decode-out would overwrite the statement at {}; name a different file",
                path.display()
            );
            return Verdict::UsageError.exit_code();
        }
    }

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

    // Decoded before either renderer runs, so text and JSON report the same
    // outcome, and so a failure to decode is reported as a failure rather
    // than as a section quietly missing from the output.
    let decoded = match &args.decode {
        Some(request) => match decode::decode(&statement, request, args.verbose) {
            Ok(decoded) => Some(decoded),
            Err(why) => {
                // The rest of the inspection is still printed: the statement
                // was readable, and a reader who asked for one field should
                // not lose the report that would tell them why it is not
                // there. The exit code carries the failure instead.
                match args.format {
                    Format::Json => {
                        let document = inspect_json::document(&statement, args.verbose, None);
                        if let Ok(text) = serde_json::to_string_pretty(&document) {
                            println!("{text}");
                        }
                    }
                    Format::Text => {
                        let _ = report::inspect(&statement, args.verbose, None);
                    }
                }
                eprintln!("error: {why}");
                return Verdict::CannotEvaluate.exit_code();
            }
        },
        None => None,
    };

    if let (Some(decoded), Some(out)) = (&decoded, &args.decode_out) {
        // The exact bytes, with nothing added or normalised on the way out.
        // A failed write is fatal: the caller asked for these bytes in order
        // to do something with them, and an exit code of 0 beside a file that
        // is absent or half-written would be believed.
        if let Err(e) = std::fs::write(out, &decoded.bytes) {
            eprintln!("error: could not write {}: {e}", out.display());
            return Verdict::CannotEvaluate.exit_code();
        }
    }

    match args.format {
        Format::Json => {
            let document = inspect_json::document(&statement, args.verbose, decoded.as_ref());
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
        Format::Text => match report::inspect(&statement, args.verbose, decoded.as_ref()) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                Verdict::CannotEvaluate.exit_code()
            }
        },
    }
}
fn run_verify(args: &VerifyArgs) -> Verdict {
    let now = args.now.unwrap_or_else(wall_clock);

    let assessment = evaluate(args, now);
    emit(args, assessment, now)
}

/// The real clock, in Unix seconds.
///
/// Kept separate from the `now` threaded through evaluation because the two
/// answer different questions. `now` is "at what moment should this statement
/// be judged", which `--now` may legitimately move in order to reproduce a
/// past decision. Anything recording when this process actually did something
/// must use this instead: writing `--now` into a provenance field would state
/// that a fetch happened at a time it did not.
fn wall_clock() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Run the checks. Never prints, never writes, never exits.
///
/// Keeping this free of side effects is what makes the "always emit evidence"
/// guarantee cheap: there is exactly one return type, so there is exactly one
/// place that has to know how to serialise a partial result.
fn evaluate(args: &VerifyArgs, now: i64) -> Assessment {
    let trust = Trust::unsigned_key_set();

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

    // Chain validation always runs; `--trusted-roots` only decides whether the
    // anchor is one the operator chose or the one the statement brought with
    // it. Making the check itself conditional would mean the common case
    // reports nothing at all about a chain that is sitting right there.
    let options = match verify_options(args) {
        Ok(o) => o,
        Err(d) => {
            return Assessment::incomplete(Verdict::UsageError, trust, d, gaps(args, None, None))
        }
    };

    // Trust material is resolved after the policy because the policy is what
    // decides where it may come from. Reading it earlier would mean the online
    // path had to either re-order itself or fetch before knowing what is
    // allowed, and only one of those is safe.
    let resolved = match resolve_trust(args, &policy, &statement_bytes, &options) {
        Ok(r) => r,
        Err(a) => return *a,
    };
    let trust = resolved.trust;
    let facts = resolved.facts;
    let acquisition_diagnostics = resolved.diagnostics;

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
            a.diagnostics.extend(acquisition_diagnostics);
            a.acquisition = resolved.acquisition;
            return a;
        }
    };

    let decision = policy.evaluate(&facts, now);

    let checks = Checks {
        statement_signature: signature_state(&facts),
        receipt_inclusion: receipt_state(&facts),
        artifact_binding: binding.state(),
        policy: policy_state(&decision),
        adapter: Vec::new(),
    };

    let verdict = decide(
        &facts,
        &binding,
        &decision,
        args.binding_mode,
        args.trusted_roots.is_some(),
    );
    // Acquisition diagnostics come first because they explain absences the
    // later ones only describe. "The key could not be fetched" is the cause;
    // "no receipt verified" is the consequence, and a reader handed the
    // consequence alone will go looking in the wrong place.
    let mut diagnostics = acquisition_diagnostics;
    diagnostics.extend(diagnose(
        &facts,
        &binding,
        &decision,
        args.trusted_roots.is_some(),
    ));
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
        acquisition: resolved.acquisition,
    }
}

/// Trust material, however it was obtained, plus what obtaining it revealed.
struct Resolved {
    facts: StatementFacts,
    trust: Trust,
    /// Anything the operator needs to know about how the material was got.
    /// Acquisition failures land here rather than being folded into the
    /// verdict, so a fetch that did not happen stays visible as a fetch that
    /// did not happen.
    diagnostics: Vec<Diagnostic>,
    /// Present only in online mode, for the record's provenance block.
    acquisition: Option<Acquisition>,
}

/// Obtain the signing keys and verify the statement against them.
///
/// Both paths end in the same place — a `StatementFacts` produced by the core
/// verifier — so the verdict logic downstream cannot tell how the keys arrived
/// and cannot grow a second opinion about it.
fn resolve_trust(
    args: &VerifyArgs,
    policy: &Policy,
    statement_bytes: &[u8],
    options: &VerifyOptions,
) -> Result<Resolved, Box<Assessment>> {
    match &args.trust {
        TrustSource::Local(path) => resolve_local(args, path, statement_bytes, options),
        TrustSource::Online { ledger } => {
            resolve_online(args, policy, statement_bytes, ledger.as_deref(), options)
        }
    }
}

/// Build the core verifier's options from the command line.
///
/// Errors here are usage errors, not verdicts: a roots file the operator
/// pointed at and this tool cannot read is a broken invocation, and quietly
/// continuing without it would run the weaker check under the stronger flag.
fn verify_options(args: &VerifyArgs) -> Result<VerifyOptions, Diagnostic> {
    let mut chain = scitt_receipt::chain::Options::default();

    if let Some(path) = &args.trusted_roots {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Diagnostic::error(
                "TrustedRootsUnreadable",
                Category::Input,
                format!("could not read {}: {e}", path.display()),
                "Check the --trusted-roots path. It must be a PEM file of CA certificates.",
            )
        })?;
        chain.trusted_roots = scitt_receipt::chain::parse_pem_certificates(&text).map_err(|e| {
            Diagnostic::error(
                "TrustedRootsUnusable",
                Category::Input,
                format!("could not parse {}: {e}", path.display()),
                "Supply a PEM file containing only CERTIFICATE blocks.",
            )
        })?;
    }

    Ok(VerifyOptions { chain: Some(chain) })
}

fn resolve_local(
    args: &VerifyArgs,
    path: &Path,
    statement_bytes: &[u8],
    options: &VerifyOptions,
) -> Result<Resolved, Box<Assessment>> {
    let trust = Trust::unsigned_key_set();

    let key_bytes =
        match read(path) {
            Ok(b) => b,
            Err(e) => return Err(Box::new(Assessment::incomplete(
                Verdict::UsageError,
                trust,
                Diagnostic::error(
                    "TrustMaterialUnreadable",
                    Category::Input,
                    e,
                    "Check the --scitt-keys path. See docs/trust-material.md to obtain a key set.",
                ),
                gaps(args, None, None),
            ))),
        };

    let key_set = match LedgerKeySet::from_cose_key_set(&key_bytes) {
        Ok(k) => k,
        // Unusable trust material is not evidence that the artifact is bad.
        // Exit 3, not 1.
        Err(e) => {
            return Err(Box::new(Assessment::incomplete(
                Verdict::CannotEvaluate,
                trust,
                Diagnostic::error(
                    "TrustMaterialUnusable",
                    Category::Trust,
                    e.to_string(),
                    "Re-fetch the key set with tools/scitt-keys.py fetch.",
                ),
                gaps(args, None, None),
            )))
        }
    };

    match verify_statement_with(statement_bytes, &key_set, options) {
        Ok(facts) => Ok(Resolved {
            facts,
            trust,
            diagnostics: Vec::new(),
            acquisition: None,
        }),
        Err(e) => {
            let (verdict, diagnostic) = classify_core_error(&e);
            Err(Box::new(Assessment::incomplete(
                verdict,
                trust,
                diagnostic,
                gaps(args, None, None),
            )))
        }
    }
}

fn resolve_online(
    args: &VerifyArgs,
    policy: &Policy,
    statement_bytes: &[u8],
    ledger: Option<&str>,
    options: &VerifyOptions,
) -> Result<Resolved, Box<Assessment>> {
    // Parsed before anything is selected, so a statement this tool cannot read
    // never causes a request. Without this the failure is silent: discovery
    // turns an unparseable statement into "no candidate issuers", which a
    // single-entry allowlist then ignores, and the run fetches keys it has no
    // use for before failing on the same bytes a moment later.
    if let Err(e) = Sign1::parse(statement_bytes) {
        let (verdict, diagnostic) = classify_core_error(&e);
        return Err(Box::new(Assessment::incomplete(
            verdict,
            Trust::no_key_set(),
            diagnostic,
            gaps(args, None, None),
        )));
    }

    // Selection runs first and completely. Nothing below this point can widen
    // what it chose, and nothing above it has touched the network.
    let candidates = online::candidate_issuers(statement_bytes);
    let selected =
        match online::select(policy, &candidates, ledger) {
            online::Selection::Ready(list) => list,
            // A misconfigured run is the operator's to fix, and saying anything
            // about the artifact on the strength of it would be inventing a result.
            online::Selection::Refused(why) => return Err(Box::new(Assessment::incomplete(
                Verdict::UsageError,
                Trust::no_key_set(),
                Diagnostic::error(
                    "AcquisitionNotConfigured",
                    Category::Input,
                    why,
                    "Set assertions.issuer in the policy to the transparency services you accept.",
                ),
                gaps(args, None, None),
            ))),
            // Nothing to ask. This is not an error: it is a statement whose
            // receipts point somewhere this policy does not accept. The normal
            // verdict path turns that into cannot-evaluate, which is what it is.
            online::Selection::Nothing(why) => {
                let trust = Trust::no_key_set();
                let facts = verify_or_fail(args, statement_bytes, &[], trust.clone(), options)?;
                return Ok(Resolved {
                    facts,
                    trust,
                    diagnostics: vec![Diagnostic::warning(
                        "NoLedgerSelected",
                        Category::Trust,
                        why.clone(),
                        "Add the service the receipt names to assertions.issuer if you accept it.",
                    )],
                    acquisition: Some(Acquisition {
                        selected: Vec::new(),
                        acquired: Vec::new(),
                        failed: Vec::new(),
                        not_attempted: Some(why),
                    }),
                });
            }
        };

    // The real clock, never `--now`: this records when the fetch happened, and
    // `--now` answers a different question entirely.
    let (acquired, failed) = online::partition(scitt_acquire::acquire_all(&selected, wall_clock()));

    // The mode describes what this run actually holds, not what it set out to
    // do. Every fetch failing leaves it with nothing, and that is what it says.
    let trust = if acquired.is_empty() {
        Trust::no_key_set()
    } else {
        Trust::acquired_key_set()
    };

    // A failure to fetch is reported as exactly that. It never becomes a
    // silent fallback to some other key, and it never becomes a finding about
    // the artifact, because not knowing is not the same as knowing something
    // bad.
    let diagnostics = failed
        .iter()
        .map(|f| {
            Diagnostic::error(
                acquisition_code(f.error.diagnostic),
                if f.error.diagnostic.is_configuration() {
                    Category::Input
                } else {
                    Category::Trust
                },
                format!("{}: {}", f.provenance.issuer, f.error.detail),
                f.error.diagnostic.action(),
            )
        })
        // A key set with two entries under one identifier still verifies, so
        // this is a warning and not a refusal: the material is usable and the
        // service is reachable. It is said out loud because for those
        // identifiers the key a receipt is checked against is decided by the
        // order of entries in the served set, which is not something the
        // relying party chose.
        .chain(acquired.iter().flat_map(|a| {
            let kids = &a.provenance.ambiguous_kids;
            (!kids.is_empty()).then(|| {
                Diagnostic::warning(
                    "AcquisitionAmbiguousKid",
                    Category::Trust,
                    format!(
                        "{} served more than one key under {}. \
                         Receipts naming those identifiers are checked against whichever \
                         matching key appears first in the served set.",
                        a.issuer,
                        kids.join(", ")
                    ),
                    "Ask the transparency service operator to publish distinct key identifiers, \
                     or pin the key set with --scitt-keys after inspecting it.",
                )
            })
        }))
        .collect();

    let acquisition = Acquisition {
        selected,
        acquired,
        failed,
        not_attempted: None,
    };

    // Carried onto the failure too. Requests were made and their outcomes are
    // evidence in their own right; dropping them because a later step failed
    // would leave a record that does not mention the network activity this run
    // performed, and would leave --save-trust with nothing to write after a
    // successful fetch.
    let facts = verify_or_fail(
        args,
        statement_bytes,
        &acquisition.acquired,
        trust.clone(),
        options,
    )
    .map_err(|mut a| {
        a.acquisition = Some(acquisition.clone());
        a
    })?;

    Ok(Resolved {
        facts,
        trust,
        diagnostics,
        acquisition: Some(acquisition),
    })
}

/// Map an acquisition fault onto a diagnostic code in this tool's namespace.
///
/// The crate's own codes are carried verbatim in the record's acquisition
/// block, where they sit alongside the rest of the provenance. This mapping
/// exists so the `diagnostics` list keeps one naming convention throughout: a
/// pipeline matching on `code` should not have to know that some codes came
/// from a different crate.
fn acquisition_code(d: scitt_acquire::Diagnostic) -> &'static str {
    use scitt_acquire::Diagnostic as D;
    match d {
        D::InvalidIssuer => "AcquisitionInvalidIssuer",
        D::UnsupportedProvider => "AcquisitionUnsupportedProvider",
        D::Transport => "AcquisitionTransport",
        D::TlsAuthentication => "AcquisitionTlsAuthentication",
        D::ResponseTooLarge => "AcquisitionResponseTooLarge",
        D::MalformedIdentity => "AcquisitionMalformedIdentity",
        D::MalformedKeySet => "AcquisitionMalformedKeySet",
        D::ServiceKeyMismatch => "AcquisitionServiceKeyMismatch",
        D::DeadlineExceeded => "AcquisitionDeadlineExceeded",
        D::UnsupportedPlatform => "AcquisitionUnsupportedPlatform",
    }
}

fn verify_or_fail(
    args: &VerifyArgs,
    statement_bytes: &[u8],
    acquired: &[scitt_acquire::Acquired],
    trust: Trust,
    options: &VerifyOptions,
) -> Result<StatementFacts, Box<Assessment>> {
    online::verify_scoped(statement_bytes, acquired, options).map_err(|e| {
        let (verdict, diagnostic) = classify_core_error(&e);
        Box::new(Assessment::incomplete(
            verdict,
            trust,
            diagnostic,
            gaps(args, None, None),
        ))
    })
}

/// Write the acquired trust material so a later run can replay it offline.
///
/// The files written are the bytes exactly as served, not a re-encoding. A
/// re-encoded key set would verify the same statements today and could stop
/// doing so after any change to this tool's serialiser, which would make the
/// snapshot useless for the one job it has.
///
/// Refuses to overwrite. A directory that already holds a snapshot is one
/// somebody may already be replaying, and silently replacing its contents is
/// how a pipeline ends up verifying against keys nobody chose. Naming the
/// collision is always recoverable; overwriting it is not.
fn save_trust(dir: &Path, assessment: &Assessment) -> Result<Vec<PathBuf>, Diagnostic> {
    let fail = |msg: String| {
        Diagnostic::error(
            "TrustMaterialNotSaved",
            Category::Input,
            msg,
            "Choose a directory that does not already hold a snapshot, or remove the existing one.",
        )
    };

    let Some(acquisition) = &assessment.acquisition else {
        return Err(fail(
            "--save-trust has nothing to write: this run did not acquire any trust material. \
             It is only meaningful with --online."
                .into(),
        ));
    };

    std::fs::create_dir_all(dir)
        .map_err(|e| fail(format!("could not create {}: {e}", dir.display())))?;

    let mut manifest = Vec::new();
    let mut written = Vec::new();
    for a in &acquisition.acquired {
        // The issuer is a validated hostname by the time it reaches here, so
        // it cannot contain a separator or traverse upwards. Checked rather
        // than assumed, because this is the one place an issuer becomes a path.
        debug_assert!(scitt_acquire::validate_host(&a.issuer).is_ok());
        let keys = dir.join(format!("{}.keys.cbor", a.issuer));
        let cert = dir.join(format!("{}.service-cert.der", a.issuer));

        for path in [&keys, &cert] {
            if path.exists() {
                return Err(fail(format!(
                    "{} already exists; refusing to overwrite trust material",
                    path.display()
                )));
            }
        }

        std::fs::write(&keys, &a.keyset_bytes)
            .map_err(|e| fail(format!("could not write {}: {e}", keys.display())))?;
        std::fs::write(&cert, &a.service_cert_der)
            .map_err(|e| fail(format!("could not write {}: {e}", cert.display())))?;
        written.push(keys.clone());
        written.push(cert.clone());

        manifest.push(serde_json::json!({
            "issuer": a.issuer,
            "keys": keys.file_name().and_then(|n| n.to_str()),
            "serviceCert": cert.file_name().and_then(|n| n.to_str()),
            "keysetSha256": a.provenance.keyset_sha256,
            "serviceCertSha256": a.provenance.service_cert_sha256,
            "serviceKeyKid": a.provenance.service_key_kid,
            "identityUrl": a.provenance.identity_url,
            "keysetUrl": a.provenance.keyset_url,
            "acquiredAt": a.provenance.acquired_at,
        }));
    }

    let manifest_path = dir.join("manifest.json");
    if manifest_path.exists() {
        return Err(fail(format!(
            "{} already exists; refusing to overwrite trust material",
            manifest_path.display()
        )));
    }
    let doc = serde_json::json!({
        "format": "scitt-verifier/trust-snapshot/v0",
        // Says plainly what replaying this does and does not get you. A
        // snapshot is a record of what a service served at a moment, so
        // replaying it reproduces that moment and nothing fresher.
        "note": "Bytes as served, for offline replay with --scitt-keys. Replaying reproduces \
                 the keys held at acquisition time; it does not re-check the service.",
        "ledgers": manifest,
    });
    std::fs::write(&manifest_path, format!("{doc:#}\n"))
        .map_err(|e| fail(format!("could not write {}: {e}", manifest_path.display())))?;
    written.push(manifest_path);

    Ok(written)
}

/// Whether two paths name the same file, including when one does not exist yet.
///
/// `canonicalize` cannot be used directly: the record path is typically about
/// to be created, and canonicalising a missing file fails. Resolving the parent
/// directory and comparing file names gets the cases that matter here — a
/// relative path, a trailing `.`, a `..` through a real directory, a symlinked
/// directory — without claiming to be a general-purpose answer.
///
/// When the parent itself cannot be resolved the path is compared as written,
/// which can miss a match. That is safe for the reason it happens: a parent the
/// filesystem cannot resolve is a parent that cannot be written to either, so
/// the write this guard would have refused fails on its own and reports a real
/// I/O error. Note that `..` through a directory that does not exist resolves
/// on Windows, which collapses it lexically, and does not on Unix, where the
/// kernel walks it.
fn same_file(a: &Path, b: &Path) -> bool {
    // When both paths already exist, resolve them completely first. This is
    // what catches an output that is a *symlink* to the input: the two names
    // differ and only the target is shared, so comparing directory and file
    // name cannot see it, and the write would destroy the statement despite
    // the guard. Hard links are still not detected — two directory entries
    // that were always equals, which canonicalising cannot collapse — so this
    // narrows the hole rather than closing it.
    if let (Ok(a), Ok(b)) = (a.canonicalize(), b.canonicalize()) {
        return a == b;
    }

    fn key(p: &Path) -> Option<(PathBuf, std::ffi::OsString)> {
        let parent = p.parent().filter(|d| !d.as_os_str().is_empty());
        let parent = parent.unwrap_or_else(|| Path::new("."));
        let parent = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        Some((parent, p.file_name()?.to_os_string()))
    }
    match (key(a), key(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Write the record and any facts projection, then print the result. One place,
/// every path.
///
/// Takes the assessment by value because a failed write has to change it.
/// Printing a document that says `artifact-transparent` while exiting 4 would
/// hand a consumer two contradictory answers from the same run.
///
/// The write order is load-bearing, not incidental. Only the record carries an
/// `appraisal`, so only the record can be made wrong by a later demotion. The
/// facts document is a projection of the observation blocks alone — what was
/// seen, never what was concluded — so nothing that happens after it lands can
/// falsify it, and it is safe to commit before the outcome is known. The record
/// is written last, once every other write outcome has been folded in.
///
/// Reversed, the two files disagree: a successful `--result` followed by a
/// failed `--facts` leaves `"pass": true, "exitCode": 0` on disk for a run that
/// exits 4. Stdout would be correct and the file would be wrong, which is the
/// worse way round — the terminal scrolls away, the audit record is kept.
fn emit(args: &VerifyArgs, mut assessment: Assessment, now: i64) -> Verdict {
    // First, because it is the only output that is evidence in its own right
    // rather than a description of a conclusion. The key sets and certificates
    // written here are what a later run replays, and they are true whatever
    // this run decides. Writing them before the record also means a failure to
    // write them can still demote the record, which would be impossible the
    // other way around.
    let mut trust_files: Vec<PathBuf> = Vec::new();
    if let Some(dir) = &args.save_trust {
        match save_trust(dir, &assessment) {
            Ok(written) => trust_files = written,
            Err(d) => demote(&mut assessment, d),
        }
    }
    // A record is a description of a conclusion; trust material is evidence.
    // Letting the former land on the latter would destroy the bytes a later
    // offline run replays, and — because the record write itself succeeds —
    // would do it on a run that still exits 0. Refusing is the only outcome
    // that leaves the snapshot intact.
    let collides = |path: &Path| -> Option<Diagnostic> {
        let hit = trust_files.iter().find(|w| same_file(w, path))?;
        Some(Diagnostic::error(
            "OutputPathCollision",
            Category::Input,
            format!(
                "{} is trust material written by --save-trust this run; refusing to overwrite it",
                hit.display()
            ),
            "Write the record or facts document somewhere outside the --save-trust directory, \
             or under a different file name.",
        ))
    };
    if let Some(path) = &args.facts {
        if let Some(d) = collides(path) {
            demote(&mut assessment, d);
        } else if let Err(d) = write_json(
            path,
            "facts document",
            &record::facts(args, &assessment, now),
        ) {
            demote(&mut assessment, d);
        }
    }
    if let Some(path) = &args.result {
        if let Some(d) = collides(path) {
            demote(&mut assessment, d);
        } else if let Err(d) = write_json(
            path,
            "verification record",
            &record::build(args, &assessment, now),
        ) {
            // No stale file to worry about here: the write that failed is the
            // one that would have carried the now-superseded verdict.
            demote(&mut assessment, d);
        }
    }

    // Built after every write outcome is known, so stdout agrees with the exit
    // code and with the record on disk.
    match args.format {
        Format::Json => println!("{:#}", record::build(args, &assessment, now)),
        Format::Text => report::verify(&assessment),
    }

    assessment.verdict
}

/// A pass whose audit trail vanished is not a pass a gate should act on.
///
/// Only a pass is demoted: a run that already failed keeps its own, more
/// important, verdict and primary diagnostic, and takes the write failure as an
/// additional one.
fn demote(assessment: &mut Assessment, failure: Diagnostic) {
    if assessment.verdict.is_pass() {
        assessment.verdict = Verdict::UsageError;
        assessment.primary = Some(failure.clone());
    }
    assessment.diagnostics.push(failure);
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
    anchoring_requested: bool,
) -> Verdict {
    if facts.signature_valid == Some(false) || binding.outcome == Binding::Mismatch {
        return Verdict::Untrusted;
    }

    // A chain that does not hold indicts the bytes in front of us, so it lands
    // with the signature rather than with the gaps. `x5chain` is a protected
    // header the Issuer signed: certificates that do not actually chain, or
    // that do not lead to a root the operator supplied, are a claim about
    // identity the statement made and cannot support. Exiting 0 here would let
    // `--trusted-roots` be answered "no" in silence.
    if matches!(facts.chain_outcome, Some(ChainOutcome::Invalid(_))) {
        return Verdict::Untrusted;
    }

    // Asked but unanswerable. An operator who passed `--trusted-roots` posed a
    // question; a build that cannot check ECDSA, or a chain missing its root,
    // leaves it unanswered, and an unanswered question must not exit 0.
    //
    // Deliberately conditional on `anchoring_requested`. Chain validation runs
    // on every statement, so treating every unsupported chain as fatal would
    // turn a check nobody asked for into a new way for existing pipelines to
    // break — and "I did not look" is still not evidence of compromise.
    // Without the flag this stays a declared gap; with it, it is exit 3.
    if anchoring_requested && !matches!(facts.chain_outcome, Some(ChainOutcome::Valid(_))) {
        return Verdict::CannotEvaluate;
    }

    // No verified receipt means the statement is, at best, merely signed.
    // That can never be a pass, whatever the policy says. Note this is the
    // only receipt-derived gate: transparency is a positive proof, and a proof
    // that holds cannot be retracted by appending noise beside it. An operator
    // who needs the stricter "exactly one receipt arrived" rule declares it in
    // policy, where it reads as their expectation rather than as this tool
    // refusing a shape RFC 9943 s7.1 permits.
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
    //
    // Matched on the *outcome* rather than on each mode by name. Enumerating
    // modes here meant that adding one silently opted it out of the
    // `CannotCompare` guard below and handed it a pass.
    match (mode, binding.outcome) {
        (BindingMode::None, _) | (_, Binding::NotRequested) => Verdict::StatementTransparent,
        (_, Binding::Bound) => Verdict::ArtifactTransparent,
        // A requested comparison that could not be made is not a success of
        // either kind. Falling through to `statement-transparent` here would
        // quietly downgrade the operator's request into a claim about the
        // statement alone.
        (_, Binding::CannotCompare) => Verdict::CannotEvaluate,
        (_, Binding::Mismatch) => Verdict::Untrusted,
    }
}

/// Every problem worth naming, in no particular order.
fn diagnose(
    facts: &StatementFacts,
    binding: &BindingResult,
    decision: &PolicyDecision,
    anchoring_requested: bool,
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
    if let Some(ChainOutcome::Invalid(reason)) = &facts.chain_outcome {
        out.push(Diagnostic::error(
            "CertificateChainInvalid",
            Category::SignerIdentity,
            format!("the signing certificate chain did not validate: {reason}"),
            "Treat this artifact as untrusted. If you passed --trusted-roots, confirm the statement really was signed under one of them.",
        ));
    }
    // Only when the operator asked. Without `--trusted-roots` an unexaminable
    // chain is a declared gap, not a failure, and raising it to an error here
    // would put a red diagnostic on runs that legitimately pass.
    if anchoring_requested && !matches!(facts.chain_outcome, Some(ChainOutcome::Valid(_))) {
        let reason = match &facts.chain_outcome {
            Some(ChainOutcome::Unsupported(r)) | Some(ChainOutcome::Insufficient(r)) => r.clone(),
            _ => "the chain was not evaluated".to_string(),
        };
        out.push(Diagnostic::error(
            "CertificateChainNotAnchored",
            Category::Unsupported,
            format!("--trusted-roots was supplied, but the chain could not be anchored: {reason}"),
            "This run cannot tell you whether the signer is one you trust. Do not read the result as if it could.",
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
        Verdict::Untrusted => &[
            Category::Crypto,
            Category::Binding,
            Category::SignerIdentity,
        ],
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

    // The statement signature is checked against the key in its own certificate.
    // Whether the chain around it was validated — and to whose root — decides
    // which of these gaps applies; reporting the same caveat regardless would
    // erase the difference between a checked chain and an unchecked one.
    match (
        facts.map(|f| f.certificate_chain_len),
        facts.and_then(|f| f.chain_outcome.as_ref()),
    ) {
        (Some(0), _) => gaps.push(Gap::new(
            "NoCertificateChain",
            Category::SignerIdentity,
            "The statement carried no certificate chain.",
            "the signer's identity rests entirely on policy assertions about CWT claims",
        )),
        // Anchored in a root the operator supplied: nothing left to caveat.
        (Some(_), Some(ChainOutcome::Valid(details))) if details.anchored_externally => {}
        // Anchored in the chain's own root. The path is internally consistent,
        // which is not the same as trusted, and collapsing the two would invite
        // the reader to believe a self-signed forgery.
        (Some(_), Some(ChainOutcome::Valid(_))) => gaps.push(Gap::new(
            "CertificateChainNotAnchoredExternally",
            Category::SignerIdentity,
            "The signing certificate chain validated only against the root carried inside the \
             statement itself, because no trusted roots were supplied.",
            "an attacker who mints their own root would produce an equally consistent chain",
        )),
        // An invalid chain is a finding, not a gap; it is reported as a problem.
        (Some(_), Some(ChainOutcome::Invalid(_))) => {}
        (Some(_), Some(ChainOutcome::Insufficient(reason))) => gaps.push(Gap::new(
            "CertificateChainNotValidated",
            Category::SignerIdentity,
            format!("The signing certificate chain was not validated: {reason}"),
            "signature validity does not establish CA trust",
        )),
        (Some(_), Some(ChainOutcome::Unsupported(reason))) => gaps.push(Gap::new(
            "CertificateChainUnsupported",
            Category::Unsupported,
            format!("This build cannot validate the signing certificate chain: {reason}"),
            "the chain is unexamined, not known-good; a newer build may be able to check it",
        )),
        (Some(_), None) => gaps.push(Gap::new(
            "CertificateChainNotValidated",
            Category::SignerIdentity,
            "The signing certificate chain was not validated to a trusted root; the statement \
             signature was checked against the leaf certificate embedded in the statement itself.",
            "signature validity does not establish CA trust",
        )),
        (None, _) => {}
    }

    gaps.push(Gap::new(
        "RevocationNotChecked",
        Category::SignerIdentity,
        "Certificate revocation was not checked (this tool runs offline).",
        "a revoked signing certificate would still verify here",
    ));

    match decision {
        Some(d) => {
            // A passing external-signature check proves possession of a private
            // key, and nothing about whose key it is: the certificate that
            // carried it was not validated to any root. Saying so here keeps
            // the report from reading as an endorsement of the named signer.
            if d.results
                .iter()
                .any(|r| r.name == "externalSignatures" && r.outcome == AssertionOutcome::Pass)
            {
                gaps.push(Gap::new(
                    "ExternalSignerChainNotValidated",
                    Category::SignerIdentity,
                    "A detached signature in the protected header verified against the \
                     certificate carried alongside it, but that certificate chain was not \
                     validated to a trusted root.",
                    "the external signature proves possession of a key, not the identity of its \
                     holder",
                ));
            }

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

    // `none` never reaches the core, which has no such mode. Modelling "no
    // binding was requested" as a mode invites a caller to ask for a
    // comparison and receive a pass for one nobody performed.
    let mode = match args.binding_mode {
        BindingMode::None => return Ok(BindingResult::not_requested()),
        BindingMode::PayloadBytes => CoreBindingMode::PayloadBytes,
        BindingMode::PayloadDigest => CoreBindingMode::PayloadDigest,
    };

    let artifact = read(artifact_path)?;
    let statement = Sign1::parse(statement_bytes).map_err(|e| e.to_string())?;

    // The comparison lives in scitt-receipt so this tool and every other
    // embedder — the WASM build, and whatever Ledger Explorer becomes — cannot
    // reach different conclusions about the same two files. A browser that
    // compared bytes its own way would eventually disagree here, and the
    // disagreement would surface as a release that should have been stopped.
    let report = scitt_receipt::bind(&statement, &artifact, mode);

    // The finding is the core's; the remedy is ours. A browser cannot act on
    // advice to pass a command-line flag, so the core declines to offer one
    // and each caller appends what its own user can actually do.
    let mut detail = report.reason.describe(&artifact_path.display().to_string());
    match report.reason {
        CoreBindingReason::HashEnvelopeNeedsDigestMode => {
            detail.push_str("; re-run with --binding-mode payload-digest");
        }
        CoreBindingReason::NotAHashEnvelope => {
            detail.push_str("; re-run with --binding-mode payload-bytes");
        }
        _ => {}
    }

    Ok(BindingResult {
        outcome: match report.outcome {
            CoreBinding::Bound => Binding::Bound,
            CoreBinding::Mismatch => Binding::Mismatch,
            CoreBinding::CannotCompare => Binding::CannotCompare,
        },
        detail,
    })
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))
}

#[cfg(test)]
mod path_tests {
    use super::same_file;
    use std::path::Path;

    /// The collision that motivated this: a record written into the snapshot
    /// directory under a name the snapshot itself uses. Spelling the directory
    /// differently must not be a way past the guard.
    #[test]
    fn the_same_file_spelled_differently_is_still_the_same_file() {
        let dir = std::env::temp_dir().join("scitt-verifier-same-file");
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let written = dir.join("manifest.json");

        assert!(same_file(&written, &dir.join(".").join("manifest.json")));
        // `..` is resolved by the filesystem, so this holds only for a
        // directory that exists. A path traversing one that does not is left
        // as written rather than guessed at.
        assert!(same_file(&written, &sub.join("..").join("manifest.json")));
    }

    #[test]
    fn different_names_in_one_directory_do_not_collide() {
        let dir = std::env::temp_dir().join("scitt-verifier-same-file");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!same_file(
            &dir.join("manifest.json"),
            &dir.join("result.json")
        ));
    }

    /// A path with no file name cannot name a file, so it cannot be one of the
    /// files this run wrote. Answering "false" is the fail-closed direction
    /// here: the caller then attempts the write and reports a real I/O error.
    #[test]
    fn a_directory_is_not_a_written_file() {
        assert!(!same_file(Path::new("/tmp"), Path::new("/")));
    }
}
