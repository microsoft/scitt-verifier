//! The two authenticated connections the trust flow needs, and nothing else.
//!
//! Both are built the same way and differ in exactly one respect: which roots
//! they will accept. That difference is the whole security argument, so it is
//! the only thing the two constructors below do not share.

use crate::error::{AcquireError, Diagnostic};
use crate::limits;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
use ureq::Agent;

/// Refuse before the bundled TLS crypto aborts the process.
///
/// `graviola` asserts the instruction sets it needs the first time a provider
/// is built, and the release profile sets `panic = "abort"`, so on a host
/// without them the process dies where it stands — no record, no exit code a
/// gate can read, which contradicts this tool's one hard guarantee that every
/// run leaves evidence. Probing first turns that into an ordinary diagnostic.
///
/// The list mirrors `graviola`'s own check. It is duplicated rather than
/// derived because `graviola` exposes no way to ask; a version bump that adds a
/// requirement would reintroduce the abort, which is why the baseline is
/// documented rather than left implicit.
#[cfg(target_arch = "x86_64")]
pub fn check_platform() -> Result<(), AcquireError> {
    let missing: Vec<&str> = [
        ("aes", is_x86_feature_detected!("aes")),
        ("pclmulqdq", is_x86_feature_detected!("pclmulqdq")),
        ("bmi1", is_x86_feature_detected!("bmi1")),
        ("adx", is_x86_feature_detected!("adx")),
        ("avx", is_x86_feature_detected!("avx")),
        ("avx2", is_x86_feature_detected!("avx2")),
    ]
    .into_iter()
    .filter_map(|(name, present)| (!present).then_some(name))
    .collect();

    if missing.is_empty() {
        return Ok(());
    }
    Err(AcquireError::new(
        Diagnostic::UnsupportedPlatform,
        format!(
            "this host does not provide {}, which the TLS implementation in this build \
             requires. Online acquisition needs an x86-64 CPU with AVX2 and ADX \
             (Intel Broadwell / AMD Excavator, 2014 or later).",
            missing.join(", ")
        ),
    ))
}

/// Non-x86-64 targets have nothing to probe: `graviola` selects a different
/// backend whose requirements are implied by the target itself.
#[cfg(not(target_arch = "x86_64"))]
pub fn check_platform() -> Result<(), AcquireError> {
    Ok(())
}

/// The crypto provider every connection in this crate uses.
///
/// `rustls-graviola` is pure Rust. The mainstream alternatives (`ring`,
/// `aws-lc-rs`) need a C toolchain, which would make this workspace
/// unbuildable on hosts that can build everything else in it today. It carries
/// no FIPS validation, and nothing in this crate implies otherwise.
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls_graviola::default_provider())
}

/// Shared connection policy.
///
/// Redirects are refused rather than followed. A redirect is an instruction
/// from the far end about where to look next, and honouring one would let a
/// response decide the destination of the request that authenticates it —
/// which is the same substitution the allowlist exists to prevent, arriving one
/// layer lower.
fn agent_with(roots: RootCerts, budget: Duration) -> Agent {
    Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::Rustls)
                .unversioned_rustls_crypto_provider(crypto_provider())
                .root_certs(roots)
                .build(),
        )
        .max_redirects(0)
        .max_redirects_will_error(true)
        .timeout_connect(Some(limits::CONNECT_TIMEOUT.min(budget)))
        .timeout_global(Some(budget))
        .user_agent(concat!("scitt-verifier/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// An agent for the identity service, trusting the public web PKI.
///
/// This is the one connection in the flow whose authority comes from the
/// public root store. It is acceptable here precisely because it is not being
/// asked for the key set: it is asked which certificate the ledger presents,
/// and that answer is then checked against the key set the ledger itself
/// serves.
pub fn public_roots_agent(budget: Duration) -> Agent {
    agent_with(RootCerts::WebPki, budget)
}

/// An agent that will accept exactly one root: the ledger's service certificate.
///
/// Not "the public roots, plus this one". A CCF service certificate is not
/// issued by a public CA, so falling back to public roots could only ever
/// succeed for a certificate the identity service did not name — which is the
/// substitution this connection exists to rule out.
pub fn pinned_agent(service_cert: &Certificate<'static>, budget: Duration) -> Agent {
    agent_with(
        RootCerts::Specific(Arc::new(vec![service_cert.clone()])),
        budget,
    )
}

/// GET `url`, refusing anything but a 200 and anything larger than `max_bytes`.
///
/// The body is read through a limiter rather than checked afterwards, so a
/// response that never ends costs `max_bytes` rather than all available memory.
/// A `Content-Length` is not trusted for this: it is a claim by the same party
/// sending the body.
pub fn get_bounded(agent: &Agent, url: &str, max_bytes: usize) -> Result<Vec<u8>, AcquireError> {
    let response = agent.get(url).call().map_err(|e| classify(url, e))?;

    let status = response.status().as_u16();
    if status != 200 {
        return Err(AcquireError::new(
            Diagnostic::Transport,
            format!("{url} returned HTTP {status}"),
        ));
    }

    let mut buf = Vec::new();
    let mut reader = response
        .into_body()
        .into_reader()
        .take(max_bytes as u64 + 1);
    reader.read_to_end(&mut buf).map_err(|e| {
        AcquireError::new(Diagnostic::Transport, format!("reading {url} failed: {e}"))
    })?;

    if buf.len() > max_bytes {
        return Err(AcquireError::new(
            Diagnostic::ResponseTooLarge,
            format!("{url} returned more than {max_bytes} bytes"),
        ));
    }

    Ok(buf)
}

/// Separate "could not authenticate the far end" from "could not reach it".
///
/// They lead to different actions. A transport fault is a reason to retry; a
/// failed handshake is a reason to stop, because something answered and was not
/// who it needed to be.
fn classify(url: &str, e: ureq::Error) -> AcquireError {
    let text = e.to_string();
    let looks_like_tls = matches!(e, ureq::Error::Tls(_))
        || text.contains("certificate")
        || text.contains("CertificateError")
        || text.contains("UnknownIssuer")
        || text.contains("NotValidForName")
        || text.contains("invalid peer certificate");

    let diagnostic = if looks_like_tls {
        Diagnostic::TlsAuthentication
    } else {
        Diagnostic::Transport
    };

    AcquireError::new(diagnostic, format!("{url}: {text}"))
}
