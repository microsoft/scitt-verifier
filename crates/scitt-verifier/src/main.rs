//! `scitt-verifier` — an offline gate for SCITT transparent statements.
//!
//! Reads bytes, produces a verdict and an evidence record, and exits with a
//! code a pipeline can branch on. Nothing here reaches the network: the trust
//! material is an input, so a verification that succeeds on a laptop succeeds
//! identically on an air-gapped build agent three months later.

mod cli;
mod evidence;
mod report;

use cli::{BindingMode, Command, Format, VerifyArgs};
use evidence::BindingResult;
use scitt_policy::Policy;
use scitt_receipt::{verify_statement, LedgerKeySet, Sign1, StatementFacts};
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// The answer, and what a caller should do about it.
///
/// `CannotEvaluate` exists because the honest answer to some questions is "I
/// don't know", and a tool that collapses that into either pass or fail is
/// lying in one direction or the other. It is a non-zero exit, so a pipeline
/// that treats non-zero as "stop" is safe by default, but it is distinguishable
/// for teams who want to warn instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Untrusted,
    PolicyFailed,
    CannotEvaluate,
    UsageError,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Untrusted => "untrusted",
            Verdict::PolicyFailed => "policyFailed",
            Verdict::CannotEvaluate => "cannotEvaluate",
            Verdict::UsageError => "usageError",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Verified => 0,
            Verdict::Untrusted => 1,
            Verdict::PolicyFailed => 2,
            Verdict::CannotEvaluate => 3,
            Verdict::UsageError => 4,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let command = match cli::parse(&args) {
        Ok(c) => c,
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
        Command::Inspect { statement } => match run_inspect(&statement) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::from(Verdict::UsageError.exit_code())
            }
        },
        Command::Verify(args) => ExitCode::from(run_verify(&args).exit_code()),
    }
}

/// Describe a statement without judging it.
///
/// Useful before a policy exists: you cannot write a rule about an issuer you
/// have not seen. `inspect` never verifies anything and never exits non-zero on
/// content, only on unreadable input — so it can never be mistaken for a gate.
fn run_inspect(path: &Path) -> Result<(), String> {
    let bytes = read(path)?;
    let statement = Sign1::parse(&bytes).map_err(|e| e.to_string())?;
    report::inspect(&statement).map_err(|e| e.to_string())
}

fn run_verify(args: &VerifyArgs) -> Verdict {
    let now = args.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });

    let statement_bytes = match read(&args.statement) {
        Ok(b) => b,
        Err(e) => return fail_usage(&e),
    };
    let key_bytes = match read(&args.scitt_keys) {
        Ok(b) => b,
        Err(e) => return fail_usage(&e),
    };
    let policy_bytes = match read(&args.policy) {
        Ok(b) => b,
        Err(e) => return fail_usage(&e),
    };

    let policy = match Policy::from_json(&policy_bytes) {
        Ok(p) => p,
        Err(e) => return fail_usage(&e),
    };

    let key_set = match LedgerKeySet::from_cose_key_set(&key_bytes, args.issuer.clone()) {
        Ok(k) => k,
        // Unusable trust material is not evidence that the artifact is bad.
        // Exit 3, not 1.
        Err(e) => {
            eprintln!("error: {e}");
            return Verdict::CannotEvaluate;
        }
    };

    let facts = match verify_statement(&statement_bytes, &key_set) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return classify_core_error(&e);
        }
    };

    let binding = match check_binding(args, &statement_bytes) {
        Ok(b) => b,
        Err(e) => return fail_usage(&e),
    };

    let decision = policy.evaluate(&facts, now);
    let verdict = decide(&facts, &binding, &decision);

    let record = evidence::build(args, &facts, Some(&decision), &binding, verdict, now);

    if let Some(path) = &args.evidence {
        if let Err(e) = std::fs::write(path, format!("{record:#}\n")) {
            // The verdict stands; the caller just loses the audit record, and
            // needs to know that before archiving nothing.
            eprintln!("error: could not write evidence to {}: {e}", path.display());
            return Verdict::UsageError;
        }
    }

    match args.format {
        Format::Json => println!("{record:#}"),
        Format::Text => report::verify(&facts, &decision, &binding, verdict),
    }

    verdict
}

/// Turn facts into a verdict.
///
/// Precedence is deliberate: cryptographic failure outranks everything, then
/// inability to evaluate, then policy. A run that both failed a signature and
/// failed a policy rule is reported as untrusted, because that is the finding
/// that matters.
fn decide(
    facts: &StatementFacts,
    binding: &BindingResult,
    decision: &scitt_policy::PolicyDecision,
) -> Verdict {
    if facts.signature_valid == Some(false) || binding.bound == Some(false) {
        return Verdict::Untrusted;
    }
    if facts
        .receipts
        .iter()
        .any(|r| r.root_signature_valid == Some(false) || r.bound_to_statement == Some(false))
    {
        return Verdict::Untrusted;
    }

    // No verified receipt means the statement is, at best, merely signed.
    // That can never be a pass, whatever the policy says.
    if !facts.receipts.iter().any(|r| r.fully_verified()) {
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
    if decision.satisfied() {
        return Verdict::Verified;
    }
    Verdict::CannotEvaluate
}

fn classify_core_error(e: &scitt_receipt::Error) -> Verdict {
    use scitt_receipt::Error::*;
    match e {
        // "I do not implement this" is never evidence of compromise.
        UnsupportedVds(_)
        | UnsupportedAlgorithm(_)
        | TrustMaterial(_)
        | UnknownKid(_)
        | IssuerMismatch { .. }
        | Crypto(_) => Verdict::CannotEvaluate,
        // Malformed input, on the other hand, is something a gate should stop on.
        Malformed(_) | Structure(_) => Verdict::Untrusted,
    }
}

fn check_binding(args: &VerifyArgs, statement_bytes: &[u8]) -> Result<BindingResult, String> {
    let Some(artifact_path) = &args.artifact else {
        return Ok(BindingResult {
            bound: None,
            detail: "no artifact binding was requested".into(),
        });
    };

    let artifact = read(artifact_path)?;
    let statement = Sign1::parse(statement_bytes).map_err(|e| e.to_string())?;

    match args.binding_mode {
        BindingMode::None => Ok(BindingResult {
            bound: None,
            detail: "no artifact binding was requested".into(),
        }),
        BindingMode::PayloadBytes => {
            let Some(payload) = statement.payload.as_deref() else {
                return Ok(BindingResult {
                    bound: Some(false),
                    detail: "the statement payload is detached, so it cannot equal the artifact"
                        .into(),
                });
            };
            let bound = payload == artifact.as_slice();
            Ok(BindingResult {
                bound: Some(bound),
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

fn fail_usage(message: &str) -> Verdict {
    eprintln!("error: {message}");
    Verdict::UsageError
}
