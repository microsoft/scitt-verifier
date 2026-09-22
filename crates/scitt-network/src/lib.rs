//! Explicit network acquisition for statement verification and optional adapters.
//!
//! # Why this is not just "download the key set"
//!
//! The key set is served by the ledger, over a connection the ledger's own
//! certificate authenticates. On its own that is circular: anything that can
//! answer at that address can present a certificate and serve keys matching it.
//!
//! The identity service breaks the circle. It is reached over the public web
//! PKI and says which certificate that ledger should be presenting. The key set
//! is then required to contain the key from *that* certificate. So a substituted
//! ledger fails not because its key set was malformed, but because it does not
//! hold the key the identity service named.
//!
//! What this does not establish: that a key is unrevoked, that the set is fresh,
//! that it has not been rolled back to an older one, or anything at all about
//! the statement's signer. A successful fetch is evidence about *who served the
//! keys*, and nothing more.

pub mod error;
pub mod http;
pub mod limits;
pub mod mst_ledger;
pub mod provider;

pub use error::{AcquireError, Diagnostic};
pub use provider::{route_for, validate_host, Route};

use scitt_receipt::{sha256_hex, spki_from_certificate_der, LedgerKeySet};
use std::time::Instant;
use ureq::tls::Certificate;

/// Trust material obtained from one ledger, with how it was obtained.
#[derive(Debug, Clone)]
pub struct Acquired {
    /// The issuer this material is scoped to.
    ///
    /// Carried with the bytes rather than alongside them because the one thing
    /// a caller must never do is use these keys for a different issuer's
    /// receipt, and separating the two makes that mistake possible.
    pub issuer: String,
    /// The key set exactly as served, for replay and for `--save-trust`.
    pub keyset_bytes: Vec<u8>,
    /// The parsed key set.
    pub keys: LedgerKeySet,
    /// The service certificate, DER, as published by the identity service.
    pub service_cert_der: Vec<u8>,
    /// Provenance, recorded whether or not the acquisition succeeded.
    pub provenance: Provenance,
}

/// Where trust material came from, and when.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub issuer: String,
    pub provider: &'static str,
    pub identity_url: String,
    pub keyset_url: String,
    /// SHA-256 of the service certificate DER, when one was obtained.
    pub service_cert_sha256: Option<String>,
    /// SHA-256 of the key set bytes, when they were obtained.
    pub keyset_sha256: Option<String>,
    /// The `kid` the service certificate's public key binds to, when computed.
    pub service_key_kid: Option<String>,
    /// Wall-clock time the acquisition ran, as a Unix timestamp.
    ///
    /// Supplied by the caller, which must pass the real clock and never a
    /// `--now`-style override: that override answers "when should this
    /// statement be judged", and writing it here would record a fetch as
    /// having happened at a time it did not. This crate cannot enforce that,
    /// so it is stated as the contract it is.
    pub acquired_at: i64,
    /// Identifiers that appear more than once in the served key set.
    ///
    /// Not a failure: a service may legitimately serve two keys and label them
    /// carelessly, and refusing would turn a labelling mistake into an outage.
    /// It is recorded because [`LedgerKeySet::find`] resolves a `kid` to the
    /// first match, so for these identifiers the order of entries in the key
    /// set — not any policy — decides which key a receipt is checked against.
    pub ambiguous_kids: Vec<String>,
    /// `None` on success, otherwise why it failed.
    pub failure: Option<AcquireError>,
}

/// A failed acquisition, kept so the reason survives into the record.
#[derive(Debug, Clone)]
pub struct Failed {
    pub provenance: Provenance,
    pub error: AcquireError,
}

/// The outcome for one ledger.
///
/// The failure is boxed because it is the rare case and the larger one: every
/// successful acquisition would otherwise carry the width of a failure it did
/// not have.
pub type Outcome = Result<Acquired, Box<Failed>>;

/// Provenance for a ledger that never got as far as a route.
fn unrouted(issuer: &str, now: i64, error: &AcquireError) -> Provenance {
    Provenance {
        issuer: issuer.to_string(),
        provider: "none",
        identity_url: String::new(),
        keyset_url: String::new(),
        service_cert_sha256: None,
        keyset_sha256: None,
        service_key_kid: None,
        acquired_at: now,
        ambiguous_kids: Vec::new(),
        failure: Some(error.clone()),
    }
}

/// A ledger's authenticated identity, established without fetching anything
/// from the ledger itself.
///
/// The first half of every acquisition, separated because two different
/// questions need it. Receipt-key acquisition uses it to decide which key set
/// to trust; evidence acquisition uses it to decide which node reports to
/// trust. Fusing the two would make the receipt issuer's trust stand in for
/// the target resource's, and those are routinely different services — a
/// production transparency service notarises builds for many deployments.
#[derive(Debug, Clone)]
pub struct LedgerIdentity {
    pub issuer: String,
    pub provider: &'static str,
    pub identity_url: String,
    /// The certificate the identity service says this ledger presents.
    ///
    /// The only thing that may authenticate a connection to the ledger. A
    /// certificate the ledger itself served would authenticate nothing:
    /// anything answering at that address can present one.
    pub service_cert: Certificate<'static>,
    pub service_cert_der: Vec<u8>,
    /// The `kid` the service certificate's public key binds to.
    pub service_key_kid: String,
}

/// A failed bootstrap, carrying whatever was established before it failed.
///
/// The certificate digest is kept separately because it may be known when the
/// bootstrap still fails: a served certificate whose key cannot be read is a
/// different fact from no certificate at all, and the record should be able to
/// tell them apart.
#[derive(Debug, Clone)]
pub struct BootstrapFailure {
    pub service_cert_sha256: Option<String>,
    pub error: AcquireError,
}

impl From<AcquireError> for BootstrapFailure {
    fn from(error: AcquireError) -> Self {
        Self {
            service_cert_sha256: None,
            error,
        }
    }
}

/// Establish which certificate a ledger must present, fetching nothing from it.
///
/// Public so that a caller needing an authenticated connection to a ledger for
/// some purpose other than receipt keys — appraising its node evidence, say —
/// can obtain one without also acquiring a key set it has no use for, and
/// without that key set's acceptance rules deciding whether the connection may
/// be made.
///
/// As with [`acquire`], the caller is responsible for having checked the host
/// against whatever policy authorises contacting it.
pub fn bootstrap(issuer: &str, deadline: Instant) -> Result<LedgerIdentity, BootstrapFailure> {
    let route = route_for(issuer)?;
    bootstrap_route(&route, deadline)
}

/// The bootstrap steps, once a route is known.
fn bootstrap_route(route: &Route, deadline: Instant) -> Result<LedgerIdentity, BootstrapFailure> {
    // Before the first TLS handshake, because the bundled crypto aborts the
    // process rather than returning an error on a host it cannot run on, and
    // an aborted process leaves no record at all.
    http::check_platform()?;

    // Step 1: ask the identity service, over the public web PKI, which
    // certificate this ledger presents.
    let identity_bytes = http::get_bounded(
        &http::public_roots_agent(budget(deadline, &route.issuer)?),
        &route.identity_url,
        limits::MAX_IDENTITY_BYTES,
    )?;

    let service_cert = parse_identity_document(&identity_bytes)?;
    let service_cert_der = service_cert.der().to_vec();
    let service_cert_sha256 = sha256_hex(&service_cert_der);

    // The identifier the ledger's own key would carry if the key set is
    // honest. Derived here from the certificate the identity service published,
    // so it is a statement about the ledger's identity rather than about
    // anything the ledger later chose to send.
    let service_key_kid = match spki_from_certificate_der(&service_cert_der) {
        Ok(spki) => sha256_hex(&spki),
        Err(e) => {
            return Err(BootstrapFailure {
                service_cert_sha256: Some(service_cert_sha256),
                error: AcquireError::new(
                    Diagnostic::MalformedIdentity,
                    format!("identity service certificate for {}: {e}", route.issuer),
                ),
            })
        }
    };

    Ok(LedgerIdentity {
        issuer: route.issuer.clone(),
        provider: route.provider,
        identity_url: route.identity_url.clone(),
        service_cert,
        service_cert_der,
        service_key_kid,
    })
}

/// What is left of the overall deadline, capped at the per-request timeout.
///
/// Recomputed before each request so a later one cannot spend a budget an
/// earlier one already consumed. Public because a caller making its own
/// requests on a bootstrapped connection must share the same deadline; a
/// second, independent budget would let one run spend twice the time an
/// operator was told it could.
pub fn budget(deadline: Instant, issuer: &str) -> Result<std::time::Duration, AcquireError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(AcquireError::new(
            Diagnostic::DeadlineExceeded,
            format!(
                "the {}s acquisition deadline passed while contacting {issuer}",
                limits::TOTAL_DEADLINE.as_secs()
            ),
        ));
    }
    Ok(remaining.min(limits::REQUEST_TIMEOUT))
}

/// Acquire trust material for one already-authorised issuer.
///
/// The caller is responsible for having checked the issuer against the policy
/// allowlist. This function will happily fetch from any issuer a provider
/// covers, because it cannot see the policy — which is exactly why the check
/// must not be left to it.
pub fn acquire(issuer: &str, now: i64) -> Outcome {
    acquire_before(issuer, now, Instant::now() + limits::TOTAL_DEADLINE)
}

/// Acquire for one issuer, finishing before `deadline` whatever happens.
///
/// The deadline is a wall for the whole ledger, not a fresh allowance per
/// request. Checking it only between ledgers — as this did originally — lets a
/// ledger started just inside the overall deadline still spend two full request
/// timeouts, so the run overshoots by the per-request budget times the number
/// of requests. A gate that hangs is a gate that gets removed.
fn acquire_before(issuer: &str, now: i64, deadline: Instant) -> Outcome {
    let route = match route_for(issuer) {
        Ok(r) => r,
        Err(error) => {
            let provenance = unrouted(issuer, now, &error);
            return Err(Box::new(Failed { provenance, error }));
        }
    };

    let mut provenance = Provenance {
        issuer: route.issuer.clone(),
        provider: route.provider,
        identity_url: route.identity_url.clone(),
        keyset_url: route.keyset_url.clone(),
        service_cert_sha256: None,
        keyset_sha256: None,
        service_key_kid: None,
        acquired_at: now,
        ambiguous_kids: Vec::new(),
        failure: None,
    };

    macro_rules! fail {
        ($e:expr) => {{
            let error: AcquireError = $e;
            provenance.failure = Some(error.clone());
            return Err(Box::new(Failed { provenance, error }));
        }};
    }

    // Step 1: establish the ledger's identity through the public web PKI.
    // Shared with evidence acquisition, which needs an authenticated
    // connection but no key set.
    let identity = match bootstrap_route(&route, deadline) {
        Ok(i) => i,
        Err(f) => {
            provenance.service_cert_sha256 = f.service_cert_sha256;
            fail!(f.error)
        }
    };
    provenance.service_cert_sha256 = Some(sha256_hex(&identity.service_cert_der));
    provenance.service_key_kid = Some(identity.service_key_kid.clone());

    // Step 2: fetch the key set from the ledger, trusting only that certificate.
    let keyset_bytes = match budget(deadline, &route.issuer).and_then(|b| {
        http::get_bounded(
            &http::pinned_agent(&identity.service_cert, b),
            &route.keyset_url,
            limits::MAX_KEYSET_BYTES,
        )
    }) {
        Ok(b) => b,
        Err(e) => fail!(e),
    };
    provenance.keyset_sha256 = Some(sha256_hex(&keyset_bytes));

    let keys = match LedgerKeySet::from_cose_key_set(&keyset_bytes) {
        Ok(k) => k,
        Err(e) => fail!(AcquireError::new(
            Diagnostic::MalformedKeySet,
            format!("key set from {}: {e}", route.keyset_url),
        )),
    };

    if let Err(e) = check_service_key_present(&keys, &identity.service_key_kid, &route.issuer) {
        fail!(e);
    }

    provenance.ambiguous_kids = ambiguous_kids(&keys);

    Ok(Acquired {
        issuer: route.issuer.clone(),
        keyset_bytes,
        keys,
        service_cert_der: identity.service_cert_der,
        provenance,
    })
}

/// Acquire for several issuers under one overall deadline.
///
/// Issuers past the deadline are reported as unevaluable rather than dropped.
/// A ledger that was never asked and a ledger that answered badly are different
/// facts, and only one of them says anything about the ledger.
pub fn acquire_all(issuers: &[String], now: i64) -> Vec<Outcome> {
    let deadline = Instant::now() + limits::TOTAL_DEADLINE;
    let mut out = Vec::with_capacity(issuers.len());

    for issuer in issuers {
        if Instant::now() >= deadline {
            let error = AcquireError::new(
                Diagnostic::DeadlineExceeded,
                format!(
                    "the {}s acquisition deadline passed before {issuer} was contacted",
                    limits::TOTAL_DEADLINE.as_secs()
                ),
            );
            let provenance = unrouted(issuer, now, &error);
            out.push(Err(Box::new(Failed { provenance, error })));
            continue;
        }
        out.push(acquire_before(issuer, now, deadline));
    }

    out
}

/// Pull the service certificate out of the identity service's response.
fn parse_identity_document(bytes: &[u8]) -> Result<Certificate<'static>, AcquireError> {
    let malformed = |why: String| AcquireError::new(Diagnostic::MalformedIdentity, why);

    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| malformed(format!("identity service response is not JSON: {e}")))?;

    let pem = value
        .get("ledgerTlsCertificate")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            malformed("identity service response has no string 'ledgerTlsCertificate'".into())
        })?;

    Certificate::from_pem(pem.as_bytes()).map_err(|e| {
        malformed(format!(
            "ledgerTlsCertificate is not a PEM certificate: {e}"
        ))
    })
}

/// Require the authenticated ledger's own key to be in the set it served.
///
/// Comparing `kid` strings alone would be worthless here: `kid` is a label
/// chosen by whoever wrote the key set. What makes this check meaningful is
/// that [`LedgerKeySet`] derives each key's expected identifier from the key
/// material itself, so a key claiming the service's `kid` while holding a
/// different point is already marked as unbound. Requiring both means the set
/// must contain the actual public key from the certificate the identity service
/// published.
/// Identifiers that more than one key in the set claims.
///
/// Only the service key's own identifier is treated as fatal elsewhere; every
/// other duplicate is reported so a reader can see that resolution for that
/// identifier is decided by entry order. Sorted and deduplicated so two runs
/// over the same key set produce the same record.
fn ambiguous_kids(keys: &LedgerKeySet) -> Vec<String> {
    let mut seen: Vec<&str> = keys.keys.iter().map(|k| k.kid.as_str()).collect();
    seen.sort_unstable();
    let mut out: Vec<String> = seen
        .windows(2)
        .filter(|w| w[0] == w[1])
        .map(|w| w[0].to_string())
        .collect();
    out.dedup();
    out
}

fn check_service_key_present(
    keys: &LedgerKeySet,
    service_key_kid: &str,
    issuer: &str,
) -> Result<(), AcquireError> {
    let matching = keys
        .keys
        .iter()
        .filter(|k| k.kid == service_key_kid)
        .count();

    if matching == 0 {
        return Err(AcquireError::new(
            Diagnostic::ServiceKeyMismatch,
            format!(
                "the key set served by {issuer} does not contain the service key \
                 {service_key_kid} that its identity service published"
            ),
        ));
    }

    // Two entries claiming the same identifier make "the key with this kid"
    // ambiguous, and a verifier resolving a receipt by kid would pick one of
    // them for reasons no policy author ever stated.
    if matching > 1 {
        return Err(AcquireError::new(
            Diagnostic::ServiceKeyMismatch,
            format!("{issuer} served more than one key with identifier {service_key_kid}"),
        ));
    }

    let key = keys
        .keys
        .iter()
        .find(|k| k.kid == service_key_kid)
        .expect("just counted exactly one");

    if !key.kid_bound_to_key {
        return Err(AcquireError::new(
            Diagnostic::ServiceKeyMismatch,
            format!(
                "{issuer} served a key labelled {service_key_kid} whose material does not \
                 hash to that identifier"
            ),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_set(kids: &[&str]) -> LedgerKeySet {
        LedgerKeySet {
            keys: kids
                .iter()
                .map(|kid| scitt_receipt::LedgerKey {
                    kid: (*kid).to_string(),
                    curve: scitt_receipt::der::Curve::P256,
                    spki_der: Vec::new(),
                    spki_sha256: String::new(),
                    kid_bound_to_key: false,
                })
                .collect(),
            revoked_kids: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// A probe that is stricter than the library it guards would refuse hosts
    /// that work. CI runs on a supported host, so this catches that mistake.
    #[test]
    fn a_supported_host_is_not_refused() {
        assert!(http::check_platform().is_ok());
    }

    #[test]
    fn a_key_set_with_distinct_identifiers_is_unambiguous() {
        assert!(ambiguous_kids(&key_set(&["a", "b", "c"])).is_empty());
    }

    /// Reported once per identifier, not once per extra entry: the reader needs
    /// to know which identifier is ambiguous, not how many keys claimed it.
    #[test]
    fn a_repeated_identifier_is_reported_once() {
        assert_eq!(ambiguous_kids(&key_set(&["a", "b", "a", "a"])), vec!["a"]);
    }

    #[test]
    fn every_ambiguous_identifier_is_named() {
        assert_eq!(
            ambiguous_kids(&key_set(&["b", "a", "b", "a"])),
            vec!["a", "b"]
        );
    }

    #[test]
    fn identity_document_without_a_certificate_is_refused() {
        let e = parse_identity_document(br#"{"ledgerId":"x"}"#).unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::MalformedIdentity);
    }

    #[test]
    fn identity_document_that_is_not_json_is_refused() {
        let e = parse_identity_document(b"not json").unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::MalformedIdentity);
    }

    #[test]
    fn non_pem_certificate_is_refused() {
        let e = parse_identity_document(br#"{"ledgerTlsCertificate":"hello"}"#).unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::MalformedIdentity);
    }

    /// An unroutable issuer must fail before any network call, and say why in a
    /// way the record can carry.
    #[test]
    fn unroutable_issuer_fails_as_configuration_without_networking() {
        let failed = acquire("ledger.example.test", 0).unwrap_err();
        assert_eq!(failed.error.diagnostic, Diagnostic::UnsupportedProvider);
        assert!(failed.error.diagnostic.is_configuration());
        assert!(failed.provenance.identity_url.is_empty());
    }

    #[test]
    fn issuer_carrying_a_url_is_refused_before_networking() {
        let failed = acquire("https://ledger.confidential-ledger.azure.com", 0).unwrap_err();
        assert_eq!(failed.error.diagnostic, Diagnostic::InvalidIssuer);
        assert!(failed.provenance.keyset_url.is_empty());
    }
}
