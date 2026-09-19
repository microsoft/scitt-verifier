//! Certificate chain validation.
//!
//! A `did:x509` fingerprint match means nothing on its own. It says a
//! certificate with those bytes appears in the chain the *statement itself
//! carries* — which the statement's author chose. What turns that into
//! evidence is proving the leaf really was issued under that certificate:
//! signatures link each certificate to its issuer, and the path ends at an
//! anchor. Only then does pinning the CA constrain who could have signed.
//!
//! So this module is the half of [`crate::didx509`] that makes the other half
//! worth checking, and neither should be reported as trust without the other.
//!
//! ## Time
//!
//! The reference implementation MST delegates to (`didx509cpp.h`) resolves
//! with `ignore_time = true`. CCF's changelog gives the reason: registration
//! "establishes a point-in-time endorsement, not ongoing validity". A
//! statement signed legitimately in 2023 should not start failing in 2026
//! because a certificate expired on schedule — the ledger already witnessed
//! it. Expiry after the fact is not evidence of forgery.
//!
//! Matching that default is not the same as ignoring time, because the
//! underlying policy has no "skip validity" switch. Instead this module picks
//! the *earliest instant at which the whole path is simultaneously valid* —
//! `max(notBefore)` — and validates there. Structure is then checked without
//! the answer depending on when the verifier happened to run.
//!
//! That choice also surfaces something a skipped check would hide: if
//! `max(notBefore)` falls after `min(notAfter)`, no such instant exists, so
//! the certificates never formed a usable path at any time. That is a genuine
//! defect, not an expiry, and is reported as one.
//!
//! Callers wanting the stricter question — "was this valid when it was
//! signed?" — opt in with [`Options::require_valid_at`], which is where the
//! receipt's `iat` belongs.

use crate::der::{self, Validity};
use crate::error::{Error, Result};
use tav_crypto::{CertificateBackend, CryptoBackend};

type Cert = <tav_crypto::Crypto as CertificateBackend>::Certificate;

/// Extensions the RFC 5280 policy refuses to evaluate rather than process,
/// paired with whether a non-critical occurrence is refused too.
///
/// Mirrors the `assert_skipped_extension_not_present` calls in TAV's
/// `x509_policy`. Four of the five are refused even when non-critical, which
/// is stricter than RFC 5280 requires: a non-critical `nameConstraints` is
/// legal and may be ignored by a verifier. Listing them here keeps a chain
/// that is merely beyond this build from being reported as one that failed.
const SKIPPED_EXTENSION_OIDS: &[(&str, bool)] = &[
    ("2.5.29.32", false), // certificatePolicies, refused only when critical
    ("2.5.29.33", true),  // policyMappings
    ("2.5.29.30", true),  // nameConstraints
    ("2.5.29.36", true),  // policyConstraints
    ("2.5.29.54", true),  // inhibitAnyPolicy
];

/// Critical extensions the RFC 5280 policy knows how to process.
///
/// Mirrors `HANDLED_CRITICAL_EXTENSIONS` in TAV's `x509_policy`. A certificate
/// marking anything else critical is refused there, which is correct RFC 5280
/// behaviour but says nothing about whether the chain is genuine.
const HANDLED_CRITICAL_EXTENSION_OIDS: &[&str] = &[
    "2.5.29.19", // basicConstraints
    "2.5.29.15", // keyUsage
];

/// How to validate a chain.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Roots to anchor to. Empty means "use the chain's own self-signed root",
    /// which is what MST does.
    ///
    /// Supplying roots changes the question from "is this internally
    /// consistent?" to "does this lead somewhere I already trust?", and only
    /// the second constrains an attacker who can mint certificates.
    pub trusted_roots: Vec<Vec<u8>>,
    /// Additionally require every certificate to be valid at this Unix time.
    ///
    /// Opt-in; see the module comment.
    pub require_valid_at: Option<i64>,
}

/// What validation established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A path from the leaf to the anchor verified.
    Valid(Details),
    /// A path was attempted and did not hold.
    Invalid(String),
    /// The material needed to reach a verdict was not present.
    ///
    /// Distinct from [`Self::Invalid`] deliberately. A statement carrying no
    /// chain has not failed validation, and reporting it as a failure would
    /// claim an examination that never happened. It is the caller's policy,
    /// not this function, that decides whether missing evidence is fatal.
    Insufficient(String),
    /// The material was present, but this build cannot check it.
    ///
    /// Separate from [`Self::Insufficient`] because the two have different
    /// remedies and deserve different exit codes: missing input might be
    /// supplied on the next run, whereas an unsupported algorithm will fail
    /// identically forever until the tool itself changes. Telling a caller to
    /// "supply the root" when the real problem is that nothing here can verify
    /// ECDSA would send them after a fix that cannot work.
    Unsupported(String),
}

/// What a successful validation established, for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Details {
    /// SHA-256 of the anchor certificate, for pinning with a policy.
    pub root_sha256: [u8; 32],
    /// Whether the anchor came from `trusted_roots` rather than the statement.
    ///
    /// Load-bearing for reporting: a chain anchored in its own embedded root
    /// is internally consistent but not externally trusted, and a report that
    /// blurs the two invites the reader to over-believe it.
    pub anchored_externally: bool,
    /// Unix time the path was validated at.
    pub validated_at: i64,
    /// Number of certificates on the path, anchor included.
    pub path_len: usize,
    /// Latest `notBefore` across the certificates that actually formed the
    /// path, anchor included.
    pub path_not_before: i64,
    /// Earliest `notAfter` across the same certificates.
    ///
    /// Together with [`Self::path_not_before`] this is the window during which
    /// the whole selected path was simultaneously live. It is recorded here,
    /// rather than recomputed from the transported `x5chain`, because the two
    /// differ whenever the anchor was supplied externally — and a check that
    /// silently used the statement's own copy would answer a question about a
    /// path that was never the one validated.
    pub path_not_after: i64,
}

impl Details {
    /// Whether every certificate on the validated path was live at `unix_time`.
    pub fn valid_at(&self, unix_time: i64) -> bool {
        unix_time >= self.path_not_before && unix_time <= self.path_not_after
    }
}

impl Outcome {
    pub fn valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }
}

/// Which certificates form the path, once an anchor has been chosen.
struct Selection {
    /// Index into `trusted_roots`, or `None` when the anchor is the chain's
    /// own last certificate.
    root_index: Option<usize>,
    /// Indices into `chain`, leaf-first, of the certificates between the leaf
    /// and the anchor.
    intermediates: Vec<usize>,
}

/// Validate a certificate chain given leaf-first, as `x5chain` supplies it.
pub fn validate(chain: &[Vec<u8>], options: &Options) -> Result<Outcome> {
    match chain.len() {
        0 => {
            return Ok(Outcome::Insufficient(
                "the statement carries no certificate chain, so no path could be built".into(),
            ))
        }
        // A lone certificate cannot be checked against anything unless a root
        // is supplied to check it against.
        1 if options.trusted_roots.is_empty() => {
            return Ok(Outcome::Insufficient(
                "the statement carries only a leaf certificate and no trusted roots were \
                 supplied, so there is nothing to validate it against"
                    .into(),
            ))
        }
        _ => {}
    }

    let parsed = parse_all(chain)?;
    let roots = parse_roots(&options.trusted_roots)?;

    let candidates = match anchor_candidates(chain, &parsed, &roots, options)? {
        Ok(candidates) => candidates,
        Err(outcome) => return Ok(outcome),
    };

    // Every plausible anchor is tried before the chain is called invalid.
    // During a CA rotation two roots can share a subject name and differ in
    // key, so a name match is a shortlist entry rather than an answer.
    // Stopping at the first one would make the verdict depend on the order
    // certificates happen to appear in the operator's bundle.
    let mut failure: Option<Outcome> = None;
    let mut capability_gap: Option<Outcome> = None;

    for selection in candidates {
        match attempt(chain, &parsed, &roots, options, &selection)? {
            valid @ Outcome::Valid(_) => return Ok(valid),
            unsupported @ Outcome::Unsupported(_) => {
                capability_gap.get_or_insert(unsupported);
            }
            other => {
                failure.get_or_insert(other);
            }
        }
    }

    // "One candidate could not be examined at all" outranks "another candidate
    // did not verify". Reporting only the second would present a partial
    // examination as a complete one, and the difference decides whether the
    // caller is being told the tool fell short or the signer did.
    Ok(capability_gap
        .or(failure)
        .unwrap_or_else(|| Outcome::Invalid("no trust anchor candidate produced a path".into())))
}

/// Try one candidate anchor end to end.
fn attempt(
    chain: &[Vec<u8>],
    parsed: &[Cert],
    roots: &[Cert],
    options: &Options,
    selection: &Selection,
) -> Result<Outcome> {
    let top = chain.len() - 1;
    let (anchor, anchor_der): (&Cert, &[u8]) = match selection.root_index {
        Some(i) => (&roots[i], options.trusted_roots[i].as_slice()),
        None => (&parsed[top], chain[top].as_slice()),
    };

    // Ordered anchor-first, the direction the policy walks. `x5chain` runs the
    // other way, so this reversal is required; getting it wrong produces
    // "issuer name does not match" on chains that are perfectly good.
    let intermediate_refs: Vec<&Cert> = selection
        .intermediates
        .iter()
        .rev()
        .map(|&i| &parsed[i])
        .collect();

    let mut validities = Vec::with_capacity(selection.intermediates.len() + 2);
    for der_bytes in std::iter::once(anchor_der)
        .chain(selection.intermediates.iter().map(|&i| chain[i].as_slice()))
        .chain(std::iter::once(chain[0].as_slice()))
    {
        validities.push(der::parse_validity(der_bytes)?);
    }

    let (path_not_before, path_not_after) = path_window(&validities);
    let validated_at = match choose_time(&validities, options) {
        Ok(time) => time,
        Err(outcome) => return Ok(outcome),
    };

    // Asked before verification, not inferred from its error message. A gap in
    // what this build can check must not be reported as a chain that failed to
    // check out — one is a limit of the tool, the other an accusation against
    // the signer, and only the second should make a reader distrust the
    // statement.
    let path_certs: Vec<&Cert> = std::iter::once(anchor)
        .chain(intermediate_refs.iter().copied())
        .chain(std::iter::once(&parsed[0]))
        .collect();
    let path_der: Vec<&[u8]> = std::iter::once(anchor_der)
        .chain(
            selection
                .intermediates
                .iter()
                .rev()
                .map(|&i| chain[i].as_slice()),
        )
        .chain(std::iter::once(chain[0].as_slice()))
        .collect();
    if let Some(gap) = capability_gap(&path_certs, &path_der)? {
        return Ok(Outcome::Unsupported(gap));
    }

    let Ok(seconds) = u64::try_from(validated_at) else {
        return Ok(Outcome::Insufficient(
            "the certificate validity window predates the Unix epoch, which this build cannot \
             represent"
                .into(),
        ));
    };

    match <tav_crypto::Crypto as CryptoBackend>::verify_chain(
        anchor,
        &intermediate_refs,
        &parsed[0],
        Some(std::time::Duration::from_secs(seconds)),
    ) {
        Ok(()) => Ok(Outcome::Valid(Details {
            root_sha256: sha256(anchor_der),
            anchored_externally: selection.root_index.is_some(),
            validated_at,
            path_len: intermediate_refs.len() + 2,
            path_not_before,
            path_not_after,
        })),
        Err(e) => Ok(Outcome::Invalid(format!(
            "certificate path did not verify: {e}"
        ))),
    }
}

/// Parse every certificate up front so a malformed one is an error rather
/// than a silent omission from the path.
fn parse_all(chain: &[Vec<u8>]) -> Result<Vec<Cert>> {
    chain
        .iter()
        .enumerate()
        .map(|(i, der_bytes)| {
            <tav_crypto::Crypto as CertificateBackend>::from_der(der_bytes).map_err(|e| {
                Error::TrustMaterial(format!(
                    "certificate at chain index {i} is not valid DER: {e}"
                ))
            })
        })
        .collect()
}

fn parse_roots(roots: &[Vec<u8>]) -> Result<Vec<Cert>> {
    roots
        .iter()
        .enumerate()
        .map(|(i, der_bytes)| {
            <tav_crypto::Crypto as CertificateBackend>::from_der(der_bytes).map_err(|e| {
                Error::TrustMaterial(format!("trusted root {i} is not a valid certificate: {e}"))
            })
        })
        .collect()
}

/// Shortlist the trust anchors worth trying, best candidate first.
///
/// Returns `Err(Outcome)` for the cases that cannot proceed, so callers report
/// them verbatim rather than reinterpreting them.
fn anchor_candidates(
    chain: &[Vec<u8>],
    parsed: &[Cert],
    roots: &[Cert],
    options: &Options,
) -> Result<std::result::Result<Vec<Selection>, Outcome>> {
    let top = parsed.len() - 1;

    if !roots.is_empty() {
        let mut exact = Vec::new();
        let mut by_name = Vec::new();

        for (i, root) in roots.iter().enumerate() {
            // The chain already ends at this root: drop the statement's copy
            // and anchor on the caller's, so the anchor is one they vouched
            // for rather than one the statement supplied.
            if chain[top] == options.trusted_roots[i] {
                exact.push(Selection {
                    root_index: Some(i),
                    intermediates: (1..top).collect(),
                });
                continue;
            }

            // The partial-chain case: the statement omitted the root and the
            // caller supplied it, so the whole chain sits beneath it.
            let issued_top =
                <tav_crypto::Crypto as CertificateBackend>::issuer_name_matches_subject(
                    &parsed[top],
                    root,
                )
                .unwrap_or(false);
            if issued_top {
                by_name.push(Selection {
                    root_index: Some(i),
                    intermediates: (1..=top).collect(),
                });
            }
        }

        // Byte-identical roots are tried ahead of every name match, across the
        // whole bundle rather than in bundle order. An identical certificate
        // is a far stronger claim than a shared subject name, and a name match
        // sitting earlier in the file must not pre-empt it.
        exact.extend(by_name);

        if exact.is_empty() {
            // Failing here means not even a candidate existed, which is a real
            // negative answer rather than missing input.
            return Ok(Err(Outcome::Invalid(format!(
                "the chain ends at '{}', which none of the {} supplied trusted root(s) issued",
                <tav_crypto::Crypto as CertificateBackend>::subject_name(&parsed[top]),
                roots.len()
            ))));
        }
        return Ok(Ok(exact));
    }

    let self_issued = <tav_crypto::Crypto as CertificateBackend>::is_self_issued(&parsed[top])
        .map_err(|e| Error::Crypto(format!("could not inspect the topmost certificate: {e}")))?;

    // The policy requires a self-issued anchor. Detecting this here keeps a
    // truncated chain from being reported as "not self-issued", which reads
    // like a defect in the certificate rather than the absence of a root.
    if !self_issued {
        return Ok(Err(Outcome::Insufficient(format!(
            "the chain ends at '{}', which is not self-signed, so it does not reach a root; \
             supply the issuing root to validate it",
            <tav_crypto::Crypto as CertificateBackend>::subject_name(&parsed[top])
        ))));
    }

    Ok(Ok(vec![Selection {
        root_index: None,
        intermediates: (1..top).collect(),
    }]))
}

/// Report anything on the path this build cannot actually check.
///
/// Returning `Some` means no verdict is available because of a limit in this
/// tool, so the caller reports [`Outcome::Unsupported`] — not
/// [`Outcome::Insufficient`], which is for material that was simply absent and
/// might be supplied next run. All three cases below are real: a production
/// AMD chain is ECDSA-signed, a production Microsoft chain marks its
/// extendedKeyUsage critical, and RSA-PSS is admitted by OID while the pinned
/// backend accepts only one salt length per digest. OpenSSL-based verifiers
/// accept all of them, so calling any one invalid would contradict the service
/// that issued it.
///
/// `path` and `path_der` are anchor-first and must describe the same path.
fn capability_gap(path: &[&Cert], path_der: &[&[u8]]) -> Result<Option<String>> {
    // Skips index 0. The backend verifies the anchor's signature over its
    // first child and each child signature after that; it never verifies the
    // anchor's own self-signature, so the algorithm that signed the anchor is
    // never parsed and cannot be a reason this path is uncheckable. Including
    // it would refuse an entirely supported path because the operator's root
    // happens to be self-signed with something older.
    for (cert, der_bytes) in path.iter().zip(path_der).skip(1) {
        // Asked of the backend itself rather than compared against a list of
        // OIDs kept here. An allowlist agrees with the backend on the
        // algorithm and not on its parameters: RSA-PSS carries its digest,
        // mask function and salt length inside those parameters, and the
        // pinned backend refuses salt lengths it did not expect. That refusal
        // is an inability to check, so it has to be recognised here rather
        // than reaching the caller disguised as a chain that failed to verify.
        if let Err(e) = cert.signature_algorithm() {
            let oid = der::parse_signature_algorithm_oid(der_bytes)?;
            return Ok(Some(format!(
                "certificate '{}' is signed with algorithm {oid}, which this build cannot verify \
                 ({e}); the chain was not validated either way",
                <tav_crypto::Crypto as CertificateBackend>::subject_name(cert)
            )));
        }
    }

    for cert in path {
        for (oid, reject_non_critical) in SKIPPED_EXTENSION_OIDS {
            let criticality =
                <tav_crypto::Crypto as CertificateBackend>::extension_criticality(cert, oid)
                    .map_err(|e| {
                        Error::Crypto(format!("could not inspect extension {oid}: {e}"))
                    })?;
            let refused =
                criticality == Some(true) || (*reject_non_critical && criticality.is_some());
            if refused {
                return Ok(Some(format!(
                    "certificate '{}' carries extension {oid}, which the path policy in this \
                     build declines to evaluate; the chain was not validated either way",
                    <tav_crypto::Crypto as CertificateBackend>::subject_name(cert)
                )));
            }
        }

        let critical = <tav_crypto::Crypto as CertificateBackend>::critical_extension_oids(cert);
        let unhandled: Vec<String> = critical
            .into_iter()
            .filter(|oid| !HANDLED_CRITICAL_EXTENSION_OIDS.contains(&oid.as_str()))
            .collect();
        if !unhandled.is_empty() {
            return Ok(Some(format!(
                "certificate '{}' marks extension(s) {} critical, which the path policy in this \
                 build does not process; the chain was not validated either way",
                <tav_crypto::Crypto as CertificateBackend>::subject_name(cert),
                unhandled.join(", ")
            )));
        }
    }

    Ok(None)
}

/// The window during which every certificate on a path was simultaneously live.
///
/// An empty path cannot occur — a path always has an anchor and a leaf — but
/// the saturating defaults keep this total rather than panicking.
fn path_window(validities: &[Validity]) -> (i64, i64) {
    let latest_start = validities.iter().map(|v| v.not_before).max().unwrap_or(0);
    let earliest_end = validities
        .iter()
        .map(|v| v.not_after)
        .min()
        .unwrap_or(i64::MAX);
    (latest_start, earliest_end)
}

/// Pick the time to validate the path at. See the module comment.
///
/// Kept free of certificate parsing so the policy itself can be tested
/// directly, rather than only through hand-built DER.
fn choose_time(validities: &[Validity], options: &Options) -> std::result::Result<i64, Outcome> {
    if let Some(explicit) = options.require_valid_at {
        return Ok(explicit);
    }

    let (latest_start, earliest_end) = path_window(validities);

    if latest_start > earliest_end {
        return Err(Outcome::Invalid(
            "the certificates in this chain were never all valid at the same time, so they could \
             not have formed a usable path when the statement was signed"
                .into(),
        ));
    }

    Ok(latest_start)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Read DER certificates out of a PEM document.
///
/// Anything that is not a `CERTIFICATE` block is rejected rather than skipped.
/// A root file is trust material: silently ignoring a private key or an
/// unrecognised block would let an operator anchor to fewer roots than the
/// file appears to contain and never learn it.
pub fn parse_pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";

    let mut certificates = Vec::new();
    let mut body: Option<String> = None;

    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(BEGIN) {
            let label = rest.trim_end_matches('-');
            if label != "CERTIFICATE" {
                return Err(Error::TrustMaterial(format!(
                    "expected only CERTIFICATE blocks, found '{label}'"
                )));
            }
            if body.is_some() {
                return Err(Error::TrustMaterial(
                    "a PEM block began before the previous one ended".into(),
                ));
            }
            body = Some(String::new());
        } else if line.starts_with(END) {
            let Some(encoded) = body.take() else {
                return Err(Error::TrustMaterial(
                    "a PEM block ended without beginning".into(),
                ));
            };
            let der_bytes = tav_crypto::base64::base64_standard_decode(&encoded).map_err(|e| {
                Error::TrustMaterial(format!("a PEM block is not valid base64: {e}"))
            })?;
            // Parsed, not merely decoded. A block that base64-decodes to
            // something that is not a certificate has to fail *here*, where the
            // caller can still treat it as a broken invocation. Deferring it
            // leaves a run that was handed roots reporting only "chain not
            // validated" — the weak answer, under the strong flag.
            <tav_crypto::Crypto as CertificateBackend>::from_der(&der_bytes).map_err(|e| {
                Error::TrustMaterial(format!(
                    "a CERTIFICATE block did not decode to a valid certificate: {e}"
                ))
            })?;
            certificates.push(der_bytes);
        } else if let Some(accumulating) = body.as_mut() {
            accumulating.push_str(line);
        }
    }

    if body.is_some() {
        return Err(Error::TrustMaterial(
            "a PEM block began and was never closed".into(),
        ));
    }
    if certificates.is_empty() {
        return Err(Error::TrustMaterial(
            "no CERTIFICATE blocks were found".into(),
        ));
    }
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validity(not_before: i64, not_after: i64) -> Validity {
        Validity {
            not_before,
            not_after,
        }
    }

    #[test]
    fn an_absent_chain_is_insufficient_rather_than_invalid() {
        let outcome = validate(&[], &Options::default()).unwrap();
        assert!(
            matches!(outcome, Outcome::Insufficient(_)),
            "a missing chain has not failed validation: {outcome:?}"
        );
    }

    #[test]
    fn a_lone_leaf_without_roots_is_insufficient() {
        // The length check runs before parsing, which is what this pins.
        let outcome = validate(&[vec![0x30, 0x00]], &Options::default()).unwrap();
        assert!(matches!(outcome, Outcome::Insufficient(_)), "{outcome:?}");
    }

    #[test]
    fn malformed_certificates_are_an_error_not_a_quiet_omission() {
        let chain = vec![vec![0xff, 0xff], vec![0xff, 0xff]];
        assert!(validate(&chain, &Options::default()).is_err());
    }

    /// The default picks the earliest instant the whole path is valid, so a
    /// later-issued intermediate moves the evaluation time forward.
    #[test]
    fn the_default_time_is_the_latest_not_before_on_the_path() {
        let path = [
            validity(100, 5_000),
            validity(900, 4_000),
            validity(50, 900),
        ];
        assert_eq!(choose_time(&path, &Options::default()), Ok(900));
    }

    /// An expired-but-once-valid chain still validates by default. This is the
    /// MST parity behaviour and the reason the default is not "now".
    #[test]
    fn a_chain_that_has_since_expired_still_has_a_valid_instant() {
        let path = [validity(100, 200), validity(120, 250)];
        assert_eq!(choose_time(&path, &Options::default()), Ok(120));
    }

    /// Disjoint windows mean no instant exists — a defect, not an expiry, and
    /// so reported as invalid rather than as missing information.
    #[test]
    fn disjoint_validity_windows_are_invalid_not_insufficient() {
        let path = [validity(1_000, 2_000), validity(3_000, 4_000)];
        match choose_time(&path, &Options::default()) {
            Err(Outcome::Invalid(_)) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// Opting in must override the time-neutral default outright, including
    /// when the requested instant falls outside every window — otherwise the
    /// strict check would silently soften into the lenient one.
    #[test]
    fn an_explicit_time_overrides_the_default() {
        let options = Options {
            require_valid_at: Some(42),
            ..Options::default()
        };
        let path = [validity(1_000, 2_000)];
        assert_eq!(choose_time(&path, &options), Ok(42));

        let disjoint = [validity(1_000, 2_000), validity(3_000, 4_000)];
        assert_eq!(choose_time(&disjoint, &options), Ok(42));
    }

    /// The positive round-trip is covered end to end in the acceptance suite,
    /// which builds a PEM from the corpus statement's own chain. It cannot be
    /// unit-tested here without embedding a real certificate, and a fabricated
    /// one would only test the base64 step this no longer stops at.
    #[test]
    fn a_block_that_is_not_a_certificate_is_refused() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n";
        let message = parse_pem_certificates(pem).unwrap_err().to_string();
        assert!(
            message.contains("valid certificate"),
            "decoded bytes must be parsed, not just base64-decoded: {message}"
        );
    }

    #[test]
    fn non_certificate_blocks_are_refused_rather_than_skipped() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAEC\n-----END PRIVATE KEY-----\n";
        assert!(parse_pem_certificates(pem).is_err());
    }

    #[test]
    fn a_file_with_no_certificates_is_an_error() {
        assert!(parse_pem_certificates("# just a comment\n").is_err());
    }

    #[test]
    fn an_unterminated_block_is_an_error() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAEC\n";
        assert!(parse_pem_certificates(pem).is_err());
    }
}
