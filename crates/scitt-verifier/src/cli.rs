//! Command-line argument parsing.
//!
//! Hand-written rather than derived from a crate, for two reasons. The binary
//! ships into CI images where size is a running cost, and — more importantly —
//! this parser refuses anything it does not recognise. A gate that silently
//! ignores `--require-two-receipts` because it was renamed last release is a
//! gate that reports success for a check nobody ran.

use std::path::PathBuf;

pub const USAGE: &str = r#"scitt-verifier — verify SCITT transparent statements

USAGE:
    scitt-verifier verify  --statement <FILE> --scitt-keys <FILE> --policy <FILE> [OPTIONS]
    scitt-verifier verify  --statement <FILE> --online --policy <FILE> [OPTIONS]
    scitt-verifier inspect --statement <FILE> [--verbose] [--format <FORMAT>]
    scitt-verifier --version | --help

INSPECT OPTIONS:
    --statement <FILE>       Transparent statement (COSE_Sign1).           [required]
    --verbose, -v            Add the certificate chain, per-receipt headers,
                             the decoded inclusion proof, and untruncated
                             payload claims. Without it, large blobs are
                             summarised; the JSON
                             marks each one "elided": true so a consumer can
                             tell a summary from the real thing.
    --format <FORMAT>        text | json                                   [default: text]
    --decode <PATH>          Decode one encoded payload claim, named by the
                             path inspect prints beside it, e.g.
                             --decode "['security-policy-base64']".
                             Reports the byte count and the SHA-256 of the
                             exact decoded bytes, plus a bounded preview.
                             Producers publish that digest alongside the
                             field, so the two are directly comparable.
    --decode-as <ENCODING>   base64 | base64url                          [default: base64]
                             Never inferred from the value: the two alphabets
                             disagree over four characters, and a guess would
                             hash bytes nobody asked for.
    --decode-out <FILE>      Write the exact decoded bytes to FILE. Nothing is
                             normalised on the way out; this is the byte-for-byte
                             extraction a digest comparison needs.

inspect reports what the file says. It verifies nothing — use `verify` to
make a decision. Its JSON carries "verified": false for the same reason.

A payload the statement declares to be JSON is listed claim by claim, each
beside the `path` a payloadJson policy rule uses to reach it.

To extract a payload whole, read it out of the JSON:
    inspect --statement s.cose --format json --verbose | jq -r .payload.json
Binary payloads appear as .payload.hex.

VERIFY OPTIONS:
    --statement <FILE>       Transparent statement (COSE_Sign1).           [required]
    --scitt-keys <FILE>      Transparency service signing keys (COSE_KeySet).
                             One of --scitt-keys or --online is required.
    --online                 Acquire the signing keys from a ledger the policy
                             allowlists, over an authenticated connection.
                             One of --scitt-keys or --online is required.
    --ledger <HOST>          Acquire from this ledger only. It must appear in
                             the policy's assertions.issuer allowlist: this
                             narrows what the policy already accepts and can
                             never add to it.                        [--online only]
    --save-trust <DIR>       Write the acquired key sets, service certificates,
                             and a provenance manifest here, for audit and for
                             replay with --scitt-keys.               [--online only]
    --policy <FILE>          Relying-party policy document (JSON).         [required]
    --trusted-roots <FILE>   PEM file of CA certificates the signing chain must
                             lead to. Without it the chain is still validated,
                             but only against the root the statement carries —
                             internally consistent, not externally trusted.
    --artifact <FILE>        The artifact the statement should describe.
    --binding-mode <MODE>    none | payload-bytes | payload-digest         [default: none]
    --format <FORMAT>        text | json                                   [default: text]
    --result <FILE>          Write the verification record to a file. This is
                             byte-for-byte the same document --format json
                             prints to stdout; the flag chooses the sink, not
                             the content. Use both to gate on stdout and keep
                             an audit trail.
    --facts <FILE>           Write the observations only — no verdict, no policy.
                             A different document, not a different sink.
                             For systems that make their own decision.
    --now <UNIX_SECONDS>     Override the clock, for reproducible runs. This
                             changes how the statement is judged, never the
                             recorded time of an acquisition that did happen.

Verification is offline unless --online is passed. Without it this build makes
no network request, including when a receipt names a key it does not hold.

--online acquires keys only from issuers the policy already allowlists. The
statement cannot introduce a ledger: a receipt naming one nobody allowlisted is
reported as not selected, and no request is made for it.

A live fetch establishes who served the keys. It does not establish that a key
is unrevoked, that the set is current, or anything about the statement's signer.

EXIT CODES:
    0  transparent, and the policy is satisfied
    1  cryptographic or binding failure — do not trust this artifact
    2  transparent, but the policy was not satisfied
    3  could not be evaluated — missing trust material or unsupported feature
    4  usage or input error

VERDICTS (exit 0 is two different claims — see docs/output.md):
    artifact-transparent   the artifact you supplied is the one that was registered
    statement-transparent  the statement is transparent, but no artifact was checked

Exit 3 is not a pass. It means the tool could not answer the question.
"#;

/// Help for the ledger-evidence binding mode, when this build has it.
///
/// Gated so an adapter-less build never advertises a mode it cannot run.
/// Printing it unconditionally would send an operator to write a policy
/// section and capture a bundle for a binary that would then refuse both.
#[cfg(feature = "adapter-mst-ledger")]
pub const ADAPTER_USAGE: &str = r#"
LEDGER EVIDENCE (mst-ledger adapter):
    --binding-mode live-evidence
                             Collect the ledger's attestation evidence now and
                             appraise it. Requires --adapter and --online.
    --binding-mode saved-evidence
                             Appraise a previously captured bundle instead.
                             Requires --adapter and --evidence.
    --adapter <NAME>         mst-ledger
    --evidence <DIR>         A bundle captured from the ledger, containing
                             snapshot.json and the per-node evidence it names.
    --save-evidence <DIR>    With live-evidence, write what was collected so the
                             run can be replayed offline later.

Answers one question: does the execution policy embedded in this statement
equal the policy the ledger's attested nodes are enforcing?

The ledger under appraisal is the one named by `ledger.host` in the policy —
which is usually *not* the transparency service that issued the receipt. A
production transparency service notarises builds for many deployments; the
statement describes one of them. Evidence from anywhere else is refused rather
than appraised.

The target ledger, its trust inputs and the acceptance requirements come from
the policy document — never from the command line. A flag can be edited in a
pipeline definition to point at a ledger that would happily attest to its own
policy; a committed policy file gets reviewed.

Prefer live-evidence. A saved bundle carries the service certificate that
identity binding is checked against, so the subject of the appraisal also
supplies its own anchor: a bundle collected from somebody else's ledger is
internally consistent and passes. A live run takes that certificate from the
public identity service instead, so a substituted ledger cannot substitute the
anchor with it.

Neither mode establishes freshness or connection binding, which are reported
NOT EVALUATED and will stay that way: CCF offers no challenge-response
attestation, and the endpoint load-balances per connection. A live run reports
when it observed the nodes; a saved one reports when someone else did.

    resource-transparent   the statement is transparent, and the appraised
                           nodes enforce the policy it embeds
"#;

/// Nothing to add: this build has no adapter.
#[cfg(not(feature = "adapter-mst-ledger"))]
pub const ADAPTER_USAGE: &str = "";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    /// No claim is made about which artifact the statement describes.
    None,
    /// The statement's payload is the artifact, byte for byte.
    PayloadBytes,
    /// The statement is a COSE Hash Envelope (RFC 9995): its payload is a
    /// digest of the artifact, produced with the algorithm named in the
    /// protected header.
    PayloadDigest,
    /// Appraise saved attestation evidence against the statement.
    ///
    /// A separate mode rather than a flag on the others, so the weaker claim
    /// cannot be reached by accident. Replaying a recorded bundle is an
    /// appraisal of evidence, not an observation of a live service, and the
    /// two must not share a spelling: a pipeline that meant to check a running
    /// ledger would otherwise pass while checking a file that was captured
    /// months ago.
    SavedEvidence,
    /// Collect the ledger's attestation evidence now, and appraise it.
    ///
    /// Distinct from `SavedEvidence` because the anchor differs, not because
    /// the checks do. Here the service certificate comes from the public
    /// identity service, so the ledger cannot supply the thing it is being
    /// checked against.
    LiveEvidence,
}

impl BindingMode {
    /// Whether this mode runs a resource adapter rather than an artifact check.
    pub fn is_evidence(self) -> bool {
        matches!(self, BindingMode::SavedEvidence | BindingMode::LiveEvidence)
    }
}

/// Which adapter supplies the resource appraisal.
///
/// Named on the command line even though there is one of them, because the
/// adapter decides what the evidence *means*, and a run's record has to say
/// which set of rules produced its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adapter {
    /// Azure Confidential Ledger nodes attested with SEV-SNP.
    MstLedger,
}

impl Adapter {
    pub fn as_str(self) -> &'static str {
        match self {
            Adapter::MstLedger => "mst-ledger",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone)]
pub enum Command {
    Verify(Box<VerifyArgs>),
    Inspect(InspectArgs),
    Help,
    Version,
}

/// Arguments for `inspect`.
///
/// `inspect` has no key set and no policy, and it never will. Its contract is
/// that it reports what a file says without deciding whether any of it is true.
#[derive(Debug, Clone)]
pub struct InspectArgs {
    pub statement: PathBuf,
    /// Add the certificate chain, per-receipt detail, and proof shape.
    pub verbose: bool,
    /// Text for people, JSON for tooling.
    ///
    /// The JSON document carries `"verified": false` in its body rather than
    /// relying on the reader remembering which command produced it. A file on
    /// disk has no command line attached to it.
    pub format: Format,
    /// Which payload claim to decode, if the caller named one.
    ///
    /// `None` is the ordinary case. Nothing is decoded unless it was asked
    /// for, because scanning a payload for values that look encoded would
    /// decode fields the producer never said were encoded.
    pub decode: Option<crate::decode::Request>,
    /// Where to write the exact decoded bytes, if anywhere.
    pub decode_out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustSource {
    /// A key set the operator already holds.
    Local(PathBuf),
    /// Acquire keys from an allowlisted ledger over an authenticated connection.
    ///
    /// `ledger` narrows the policy's allowlist to a single issuer. It cannot
    /// widen it: an operator who names a ledger the policy does not accept has
    /// contradicted themselves, and this build refuses rather than picking one
    /// of the two answers.
    Online { ledger: Option<String> },
}

/// One of these, never both and never neither.
///
/// Modelled as a sum type rather than two `Option` fields because "which trust
/// material was used" is the single most consequential fact about a run, and a
/// shape that can represent "both" or "neither" is a shape where some later
/// branch has to decide what those mean.
#[derive(Debug, Clone)]
pub struct VerifyArgs {
    pub statement: PathBuf,
    pub trust: TrustSource,
    pub policy: PathBuf,
    pub artifact: Option<PathBuf>,
    pub binding_mode: BindingMode,
    /// The adapter to appraise resource evidence with, if any.
    pub adapter: Option<Adapter>,
    /// The saved evidence bundle to appraise.
    pub evidence: Option<PathBuf>,
    /// Where to write evidence collected from a live ledger, if asked for.
    ///
    /// Live-only, for the same reason `--save-keys` is online-only: there is
    /// nothing this run collected to save when it appraised a bundle someone
    /// else recorded, and accepting the flag anyway would imply it had.
    pub save_evidence: Option<PathBuf>,
    pub format: Format,
    pub result: Option<PathBuf>,
    /// Where to write the observations-only projection, if asked for.
    ///
    /// There is deliberately no way to produce this without a full
    /// verification. Facts about a statement nobody authenticated are worth
    /// nothing, and a keyless extraction path is how unauthenticated claims
    /// find their way into an admission policy.
    pub facts: Option<PathBuf>,
    /// Where to preserve acquired trust material, if asked for.
    ///
    /// Online-only: there is nothing to save when the operator supplied the
    /// keys themselves, and accepting the flag anyway would imply this run
    /// produced something it did not.
    pub save_trust: Option<PathBuf>,
    /// PEM file of roots the signing certificate chain must lead to.
    ///
    /// The chain is validated either way. What this changes is the anchor:
    /// with it, the path must terminate at a certificate from this file, and
    /// failing to do so is a verdict rather than a caveat. Without it the
    /// anchor is the root the statement itself carried, which establishes
    /// internal consistency and is reported as a gap rather than as trust —
    /// a self-signed forgery is internally consistent too.
    pub trusted_roots: Option<PathBuf>,
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
    let mut online = false;
    let mut ledger = None;
    let mut save_trust = None;
    let mut policy = None;
    let mut artifact = None;
    let mut binding_mode = None;
    let mut adapter = None;
    let mut evidence = None;
    let mut save_evidence = None;
    let mut format = Format::Text;
    let mut result = None;
    let mut facts = None;
    let mut trusted_roots = None;
    let mut now = None;

    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--statement" => statement = Some(PathBuf::from(value(&mut it, flag)?)),
            "--scitt-keys" => scitt_keys = Some(PathBuf::from(value(&mut it, flag)?)),
            "--online" => online = true,
            "--ledger" => ledger = Some(value(&mut it, flag)?.clone()),
            "--save-trust" => save_trust = Some(PathBuf::from(value(&mut it, flag)?)),
            "--policy" => policy = Some(PathBuf::from(value(&mut it, flag)?)),
            "--artifact" => artifact = Some(PathBuf::from(value(&mut it, flag)?)),
            "--result" => result = Some(PathBuf::from(value(&mut it, flag)?)),
            "--facts" => facts = Some(PathBuf::from(value(&mut it, flag)?)),
            "--trusted-roots" => trusted_roots = Some(PathBuf::from(value(&mut it, flag)?)),
            "--binding-mode" => {
                let raw = value(&mut it, flag)?;
                binding_mode = Some(match raw.as_str() {
                    "none" => BindingMode::None,
                    "payload-bytes" => BindingMode::PayloadBytes,
                    "payload-digest" => BindingMode::PayloadDigest,
                    "saved-evidence" => BindingMode::SavedEvidence,
                    "live-evidence" => BindingMode::LiveEvidence,
                    other => {
                        return Err(format!(
                            "unknown binding mode '{other}'; expected 'none', 'payload-bytes', \
                             'payload-digest', 'saved-evidence' or 'live-evidence'"
                        ))
                    }
                });
            }
            "--adapter" => {
                let raw = value(&mut it, flag)?;
                adapter = Some(match raw.as_str() {
                    "mst-ledger" => Adapter::MstLedger,
                    other => {
                        return Err(format!("unknown adapter '{other}'; expected 'mst-ledger'"))
                    }
                });
            }
            "--evidence" => evidence = Some(PathBuf::from(value(&mut it, flag)?)),
            "--save-evidence" => save_evidence = Some(PathBuf::from(value(&mut it, flag)?)),
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

    // Exactly one source of trust material. Accepting both would leave the
    // question of which one a receipt was actually checked against to be
    // answered by whichever branch ran first, and that is not a thing a reader
    // of the record could recover afterwards.
    // Online-only flags are rejected in an offline run rather than ignored.
    // Accepting one silently would report success for a mode nobody selected.
    if !online {
        if ledger.is_some() {
            return Err(
                "--ledger selects which allowlisted ledger to acquire keys from, so it only \
                 means something with --online."
                    .into(),
            );
        }
        if save_trust.is_some() {
            return Err(
                "--save-trust preserves material acquired by --online; an offline run has \
                 nothing to preserve that the operator does not already have."
                    .into(),
            );
        }
    }

    let trust = match (scitt_keys, online) {
        (Some(_), true) => {
            return Err(
                "--scitt-keys and --online both supply trust material; pass exactly one. \
                 Use --scitt-keys to verify against keys you already hold, or --online to \
                 acquire them from a ledger the policy allowlists."
                    .into(),
            )
        }
        (None, false) => {
            return Err(
                "no trust material: pass --scitt-keys <FILE> to use keys you already hold, \
                 or --online to acquire them from a ledger the policy allowlists. Without \
                 either, no receipt can be checked."
                    .into(),
            )
        }
        (Some(path), false) => TrustSource::Local(path),
        (None, true) => TrustSource::Online { ledger },
    };

    // There is no default policy. A default would be this tool making a trust
    // decision on the relying party's behalf.
    let policy = policy.ok_or(
        "--policy is required; verification produces facts, and a policy is what turns facts into a decision",
    )?;

    let binding_mode = binding_mode.unwrap_or(BindingMode::None);
    let artifact_mode = matches!(
        binding_mode,
        BindingMode::PayloadBytes | BindingMode::PayloadDigest
    );

    if artifact.is_some() && binding_mode == BindingMode::None {
        return Err(
            "--artifact was supplied but --binding-mode is 'none', so the artifact would be \
             ignored. Pass --binding-mode payload-bytes or payload-digest, or drop --artifact."
                .into(),
        );
    }
    if artifact.is_none() && artifact_mode {
        return Err("--binding-mode requires --artifact".into());
    }
    // Refused rather than silently ignoring one of them. The two modes answer
    // different questions, and a run that quietly dropped the artifact check
    // would report on the ledger while an operator believed it had also
    // checked what they were deploying.
    if artifact.is_some() && binding_mode.is_evidence() {
        return Err(
            "--binding-mode saved-evidence and live-evidence appraise ledger evidence and make \
             no claim about an artifact, so --artifact would be ignored. Run the artifact \
             binding as a separate invocation."
                .into(),
        );
    }

    // Each evidence flag is useless without the others, and a partial set must
    // not look like a configured run.
    if binding_mode.is_evidence() {
        if adapter.is_none() {
            return Err(
                "an evidence binding mode requires --adapter; the adapter decides what the \
                 evidence means, and a result has to record which rules produced it"
                    .into(),
            );
        }
    } else if adapter.is_some() {
        return Err(
            "--adapter was supplied but --binding-mode is not an evidence mode, so no \
             evidence would be appraised"
                .into(),
        );
    }

    if binding_mode == BindingMode::SavedEvidence && evidence.is_none() {
        return Err("--binding-mode saved-evidence requires --evidence <DIR>".into());
    }
    if binding_mode != BindingMode::SavedEvidence && evidence.is_some() {
        return Err(
            "--evidence supplies a recorded bundle, which only means something with \
             --binding-mode saved-evidence. A live run collects its own evidence, and \
             appraising a bundle instead would answer a different question."
                .into(),
        );
    }

    // Live collection is a network operation, and this tool has exactly one
    // way to say a run may reach the network. Inferring one from the binding
    // mode would let an offline-looking command line make requests.
    if binding_mode == BindingMode::LiveEvidence && !matches!(trust, TrustSource::Online { .. }) {
        return Err(
            "--binding-mode live-evidence collects evidence from the ledger, so it requires \
             --online. An offline run cannot observe a service; use --binding-mode \
             saved-evidence with a bundle captured earlier."
                .into(),
        );
    }
    if save_evidence.is_some() && binding_mode != BindingMode::LiveEvidence {
        return Err(
            "--save-evidence preserves evidence this run collected, so it only means \
             something with --binding-mode live-evidence."
                .into(),
        );
    }

    Ok(Command::Verify(Box::new(VerifyArgs {
        statement,
        trust,
        policy,
        artifact,
        binding_mode,
        adapter,
        evidence,
        save_evidence,
        format,
        result,
        facts,
        save_trust,
        trusted_roots,
        now,
    })))
}

fn parse_inspect<'a>(mut it: impl Iterator<Item = &'a String>) -> Result<Command, String> {
    let mut statement = None;
    let mut verbose = false;
    let mut format = Format::Text;
    let mut decode_path = None;
    let mut decode_as = None;
    let mut decode_out = None;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--statement" => {
                statement = Some(PathBuf::from(
                    it.next().ok_or("--statement requires a value")?,
                ))
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
            "--verbose" | "-v" => verbose = true,
            "--decode" => {
                let raw = value(&mut it, flag)?;
                decode_path =
                    Some(scitt_policy::parse_path(&raw).map_err(|why| format!("--decode: {why}"))?);
            }
            "--decode-as" => {
                decode_as = Some(scitt_receipt::base64::Alphabet::parse(
                    value(&mut it, flag)?.as_str(),
                )?);
            }
            "--decode-out" => decode_out = Some(PathBuf::from(value(&mut it, flag)?)),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(format!("unknown option '{other}' for inspect")),
        }
    }

    // Refused rather than ignored. An encoding or an output file with nothing
    // to decode is almost always a `--decode` that was dropped from the
    // command line, and silently proceeding would report a successful
    // inspection for an extraction that never happened.
    if decode_path.is_none() {
        if decode_as.is_some() {
            return Err("--decode-as names an encoding, but no --decode selected a claim".into());
        }
        if decode_out.is_some() {
            return Err("--decode-out names a file, but no --decode selected a claim".into());
        }
    }

    Ok(Command::Inspect(InspectArgs {
        statement: statement.ok_or("--statement is required")?,
        verbose,
        format,
        decode: decode_path.map(|path| crate::decode::Request {
            path,
            alphabet: decode_as.unwrap_or(scitt_receipt::base64::Alphabet::Standard),
        }),
        decode_out,
    }))
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

    /// Collecting evidence is a network operation, and only one flag may
    /// authorise one. A binding mode that implied network access would let an
    /// offline-looking command line make requests.
    #[test]
    fn live_evidence_requires_online() {
        let err = parse(&args(&[
            "verify",
            "--statement",
            "a",
            "--scitt-keys",
            "k",
            "--policy",
            "p",
            "--binding-mode",
            "live-evidence",
            "--adapter",
            "mst-ledger",
        ]))
        .unwrap_err();
        assert!(err.contains("requires --online"), "{err}");
    }

    /// A live run collects its own evidence. Handing it a bundle as well would
    /// leave which one was appraised to whichever branch ran first.
    #[test]
    fn a_live_run_refuses_a_recorded_bundle() {
        let err = parse(&args(&[
            "verify",
            "--statement",
            "a",
            "--online",
            "--policy",
            "p",
            "--binding-mode",
            "live-evidence",
            "--adapter",
            "mst-ledger",
            "--evidence",
            "dir",
        ]))
        .unwrap_err();
        assert!(err.contains("--binding-mode saved-evidence"), "{err}");
    }

    /// `--save-evidence` preserves what this run collected. With nothing
    /// collected it would name a file that was never going to exist.
    #[test]
    fn save_evidence_without_a_live_run_is_refused() {
        let err = parse(&args(&[
            "verify",
            "--statement",
            "a",
            "--scitt-keys",
            "k",
            "--policy",
            "p",
            "--binding-mode",
            "saved-evidence",
            "--adapter",
            "mst-ledger",
            "--evidence",
            "dir",
            "--save-evidence",
            "out",
        ]))
        .unwrap_err();
        assert!(err.contains("--save-evidence"), "{err}");
    }

    #[test]
    fn a_live_run_parses() {
        let parsed = parse(&args(&[
            "verify",
            "--statement",
            "a",
            "--online",
            "--policy",
            "p",
            "--binding-mode",
            "live-evidence",
            "--adapter",
            "mst-ledger",
            "--save-evidence",
            "out",
        ]))
        .expect("parses");
        let Command::Verify(v) = parsed else {
            panic!("expected verify")
        };
        assert_eq!(v.binding_mode, BindingMode::LiveEvidence);
        assert_eq!(v.save_evidence, Some(PathBuf::from("out")));
        assert!(v.evidence.is_none());
    }

    /// A flag the parser does not know must fail, not be ignored. A gate that
    /// silently drops an option reports success for a check nobody ran.
    #[test]
    fn an_unknown_inspect_flag_is_refused() {
        let err = parse(&args(&["inspect", "--statement", "a", "--payload", "b"])).unwrap_err();
        assert!(err.contains("--payload"), "{err}");
    }

    /// Every advertised mode must parse. A mode named in `--help` that the
    /// parser rejects sends the operator looking for a bug in their pipeline.
    #[test]
    fn every_advertised_binding_mode_parses() {
        for (text, expected) in [
            ("payload-bytes", BindingMode::PayloadBytes),
            ("payload-digest", BindingMode::PayloadDigest),
        ] {
            let parsed = parse(&args(&[
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
                text,
            ]))
            .unwrap_or_else(|e| panic!("{text} must parse: {e}"));
            let Command::Verify(v) = parsed else {
                panic!("expected a verify command");
            };
            assert_eq!(v.binding_mode, expected);
            assert!(
                USAGE.contains(text),
                "{text} parses but is not documented in --help"
            );
        }
    }

    /// An unknown mode must be refused rather than quietly treated as `none`,
    /// which would report a binding nobody performed as one nobody asked for.
    #[test]
    fn an_unknown_binding_mode_is_refused() {
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
            "payload-sha256",
        ]))
        .unwrap_err();
        assert!(err.contains("payload-sha256"), "{err}");
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
