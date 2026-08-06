//! Command-line argument parsing.
//!
//! Hand-written rather than derived from a crate, for two reasons. The binary
//! ships into CI images where size is a running cost, and — more importantly —
//! this parser refuses anything it does not recognise. A gate that silently
//! ignores `--require-two-receipts` because it was renamed last release is a
//! gate that reports success for a check nobody ran.

use std::path::PathBuf;

pub const USAGE: &str = r#"scitt-verifier — verify SCITT transparent statements offline

USAGE:
    scitt-verifier verify  --statement <FILE> --scitt-keys <FILE> --policy <FILE> [OPTIONS]
    scitt-verifier inspect --statement <FILE>
    scitt-verifier --version | --help

VERIFY OPTIONS:
    --statement <FILE>       Transparent statement (COSE_Sign1).           [required]
    --scitt-keys <FILE>      Transparency service signing keys (COSE_KeySet). [required]
    --policy <FILE>          Relying-party policy document (JSON).         [required]
    --issuer <URL>           Scope the key set to one issuer. Recommended.
    --artifact <FILE>        The artifact the statement should describe.
    --binding-mode <MODE>    none | payload-bytes                          [default: none]
    --format <FORMAT>        text | json                                   [default: text]
    --evidence <FILE>        Write the machine-readable evidence record here.
    --now <UNIX_SECONDS>     Override the clock, for reproducible runs.

EXIT CODES:
    0  verified, and the policy is satisfied
    1  cryptographic or binding failure — do not trust this artifact
    2  verified, but the policy was not satisfied
    3  could not be evaluated — missing trust material or unsupported feature
    4  usage or input error

Exit 3 is not a pass. It means the tool could not answer the question.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    /// No claim is made about which artifact the statement describes.
    None,
    /// The statement's payload is the artifact, byte for byte.
    PayloadBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone)]
pub enum Command {
    Verify(Box<VerifyArgs>),
    Inspect { statement: PathBuf },
    Help,
    Version,
}

#[derive(Debug, Clone)]
pub struct VerifyArgs {
    pub statement: PathBuf,
    pub scitt_keys: PathBuf,
    pub policy: PathBuf,
    pub issuer: Option<String>,
    pub artifact: Option<PathBuf>,
    pub binding_mode: BindingMode,
    pub format: Format,
    pub evidence: Option<PathBuf>,
    pub now: Option<i64>,
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    let mut it = args.iter();
    let Some(first) = it.next() else {
        return Ok(Command::Help);
    };

    match first.as_str() {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" => return Ok(Command::Version),
        "inspect" => return parse_inspect(it),
        "verify" => {}
        other => {
            return Err(format!(
                "unknown command '{other}'; expected 'verify' or 'inspect'"
            ))
        }
    }

    let mut statement = None;
    let mut scitt_keys = None;
    let mut policy = None;
    let mut issuer = None;
    let mut artifact = None;
    let mut binding_mode = None;
    let mut format = Format::Text;
    let mut evidence = None;
    let mut now = None;

    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--statement" => statement = Some(PathBuf::from(value(&mut it, flag)?)),
            "--scitt-keys" => scitt_keys = Some(PathBuf::from(value(&mut it, flag)?)),
            "--policy" => policy = Some(PathBuf::from(value(&mut it, flag)?)),
            "--issuer" => issuer = Some(value(&mut it, flag)?),
            "--artifact" => artifact = Some(PathBuf::from(value(&mut it, flag)?)),
            "--evidence" => evidence = Some(PathBuf::from(value(&mut it, flag)?)),
            "--binding-mode" => {
                let raw = value(&mut it, flag)?;
                binding_mode = Some(match raw.as_str() {
                    "none" => BindingMode::None,
                    "payload-bytes" => BindingMode::PayloadBytes,
                    // Named explicitly so the error says "not yet" rather than
                    // "unknown". A user who asks for hash-envelope binding is
                    // asking the right question; we just cannot answer it yet.
                    "payload-digest" => return Err(
                        "binding mode 'payload-digest' (COSE Hash Envelope) is not implemented \
                             in this release. Refusing rather than reporting an unchecked binding."
                            .into(),
                    ),
                    other => {
                        return Err(format!(
                            "unknown binding mode '{other}'; expected 'none' or 'payload-bytes'"
                        ))
                    }
                });
            }
            "--format" => {
                format = match value(&mut it, flag)?.as_str() {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    other => {
                        return Err(format!("unknown format '{other}'; expected text or json"))
                    }
                }
            }
            "--now" => {
                let raw = value(&mut it, flag)?;
                now = Some(
                    raw.parse::<i64>()
                        .map_err(|_| format!("--now must be a Unix timestamp, got '{raw}'"))?,
                );
            }
            "--help" | "-h" => return Ok(Command::Help),
            other => {
                return Err(format!(
                    "unknown option '{other}'. This build refuses options it does not \
                     implement, so that a policy written for another version cannot appear to pass."
                ))
            }
        }
    }

    let statement = statement.ok_or("--statement is required")?;
    let scitt_keys = scitt_keys.ok_or(
        "--scitt-keys is required; without the transparency service's signing keys no receipt can be checked",
    )?;
    // There is no default policy. A default would be this tool making a trust
    // decision on the relying party's behalf.
    let policy = policy.ok_or(
        "--policy is required; verification produces facts, and a policy is what turns facts into a decision",
    )?;

    let binding_mode = binding_mode.unwrap_or(BindingMode::None);
    if artifact.is_some() && binding_mode == BindingMode::None {
        return Err(
            "--artifact was supplied but --binding-mode is 'none', so the artifact would be \
             ignored. Pass --binding-mode payload-bytes, or drop --artifact."
                .into(),
        );
    }
    if artifact.is_none() && binding_mode != BindingMode::None {
        return Err("--binding-mode requires --artifact".into());
    }

    Ok(Command::Verify(Box::new(VerifyArgs {
        statement,
        scitt_keys,
        policy,
        issuer,
        artifact,
        binding_mode,
        format,
        evidence,
        now,
    })))
}

fn parse_inspect<'a>(mut it: impl Iterator<Item = &'a String>) -> Result<Command, String> {
    let mut statement = None;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--statement" => {
                statement = Some(PathBuf::from(
                    it.next().ok_or("--statement requires a value")?,
                ))
            }
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(format!("unknown option '{other}' for inspect")),
        }
    }
    Ok(Command::Inspect {
        statement: statement.ok_or("--statement is required")?,
    })
}

fn value<'a>(it: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<String, String> {
    it.next()
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unknown_options_are_refused() {
        let err = parse(&args(&["verify", "--statement", "a", "--turbo"])).unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn policy_is_mandatory() {
        let err = parse(&args(&["verify", "--statement", "a", "--scitt-keys", "b"])).unwrap_err();
        assert!(err.contains("--policy is required"), "{err}");
    }

    #[test]
    fn unimplemented_binding_mode_is_refused_not_ignored() {
        let err = parse(&args(&[
            "verify",
            "--statement",
            "a",
            "--scitt-keys",
            "b",
            "--policy",
            "c",
            "--artifact",
            "d",
            "--binding-mode",
            "payload-digest",
        ]))
        .unwrap_err();
        assert!(err.contains("not implemented"), "{err}");
    }

    #[test]
    fn an_artifact_that_would_be_ignored_is_an_error() {
        let err = parse(&args(&[
            "verify",
            "--statement",
            "a",
            "--scitt-keys",
            "b",
            "--policy",
            "c",
            "--artifact",
            "d",
        ]))
        .unwrap_err();
        assert!(
            err.contains("would be \n             ignored") || err.contains("ignored"),
            "{err}"
        );
    }

    #[test]
    fn a_complete_verify_invocation_parses() {
        let cmd = parse(&args(&[
            "verify",
            "--statement",
            "s.cose",
            "--scitt-keys",
            "k.cbor",
            "--policy",
            "p.json",
            "--binding-mode",
            "payload-bytes",
            "--artifact",
            "a.bin",
            "--format",
            "json",
        ]))
        .unwrap();
        match cmd {
            Command::Verify(v) => {
                assert_eq!(v.binding_mode, BindingMode::PayloadBytes);
                assert_eq!(v.format, Format::Json);
            }
            other => panic!("expected verify, got {other:?}"),
        }
    }
}
