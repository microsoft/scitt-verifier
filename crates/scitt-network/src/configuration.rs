//! The transparency service's current configuration, as an observation.
//!
//! # What this is not
//!
//! Everything here is reported and nothing here is decided. The configuration
//! is read over the same connection the key set was, authenticated to the
//! certificate the identity service published, so it is known to have come
//! from that service. That is the whole of what it establishes:
//!
//! * It is what the service says **now**. It is not evidence of the policy a
//!   statement was registered under, which may have changed since.
//! * It is **not signed** and not bound to any receipt. A saved copy keeps the
//!   bytes and loses the authentication.
//! * A registration policy is the **service's**, not the relying party's. It is
//!   never executed, and nothing in it can relax, satisfy, or replace an
//!   assertion the operator wrote.
//! * It says nothing about the code the service runs.
//!
//! The fetch is optional in the sense that matters for a gate: a service that
//! does not serve the endpoint, refuses it, times out, or answers with garbage
//! produces an observation saying so, and never a change in any verdict.

use std::time::Instant;

use scitt_receipt::sha256_hex;
use ureq::tls::Certificate;

use crate::{budget, http, limits, route_for, AcquireError, Acquired, Diagnostic};

/// What a run learned about one selected service's configuration.
///
/// One per selected issuer, whether or not anything was fetched, so a record
/// never reads a ledger nobody asked as a ledger with nothing to say.
#[derive(Debug, Clone)]
pub struct Observation {
    pub issuer: String,
    /// The endpoint asked, or would have been. `None` only when the issuer
    /// could not be routed at all.
    pub url: Option<String>,
    /// SHA-256 of the service certificate the connection was pinned to.
    ///
    /// `None` when no connection was made. Recorded with the observation so a
    /// reader can see which authenticated identity served these bytes without
    /// cross-referencing the key-acquisition block.
    pub service_cert_sha256: Option<String>,
    /// Wall-clock time of the fetch, as a Unix timestamp.
    ///
    /// The caller must pass the real clock, never a `--now`-style override: this
    /// records when the service said this, and an override would date the
    /// observation to a moment the service was never asked.
    pub observed_at: i64,
    pub outcome: Outcome,
}

/// How far one observation got.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The service answered with a JSON object.
    Retrieved(Configuration),
    /// A request was made, or was about to be, and did not produce one.
    Failed(AcquireError),
    /// No request was made, with the reason. Used when the service's identity
    /// or key set could not be established: a configuration read over a
    /// connection nobody authenticated would say nothing about the service.
    NotAttempted(String),
}

/// A configuration document exactly as served.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// The response body, byte for byte.
    ///
    /// Kept because the digest below is only reproducible from these bytes. A
    /// re-serialised document would reorder keys and drop duplicates, and a
    /// digest over that would describe something the service never sent.
    pub bytes: Vec<u8>,
    /// SHA-256 of [`Self::bytes`].
    pub sha256: String,
    /// The parsed document, with every field the service returned.
    ///
    /// Nothing is defaulted or dropped. A field the service omitted is absent
    /// here too, rather than filled with what some implementation assumes.
    pub document: serde_json::Map<String, serde_json::Value>,
}

impl Observation {
    /// An observation for a service this run did not ask.
    pub fn not_attempted(issuer: &str, reason: impl Into<String>, now: i64) -> Self {
        Self {
            issuer: issuer.to_string(),
            url: route_for(issuer).ok().map(|r| r.configuration_url),
            service_cert_sha256: None,
            observed_at: now,
            outcome: Outcome::NotAttempted(reason.into()),
        }
    }
}

/// Read the current configuration of a service whose keys were acquired.
///
/// Takes an [`Acquired`] rather than an issuer so it cannot be called for a
/// service whose identity was not established: the only certificate it can
/// pin to is the one the identity service published and the key set was
/// checked against.
///
/// `deadline` is the acquisition phase's own. Sharing it keeps a run's total
/// network time within the bound an operator was told, and running after the
/// key sets means this can only ever spend time the key sets did not need.
pub fn observe(acquired: &Acquired, now: i64, deadline: Instant) -> Observation {
    let issuer = acquired.issuer.as_str();
    let mut observation = Observation {
        issuer: issuer.to_string(),
        url: None,
        service_cert_sha256: Some(sha256_hex(&acquired.service_cert_der)),
        observed_at: now,
        outcome: Outcome::NotAttempted(String::new()),
    };

    let route = match route_for(issuer) {
        Ok(r) => r,
        Err(e) => {
            observation.outcome = Outcome::Failed(e);
            return observation;
        }
    };
    observation.url = Some(route.configuration_url.clone());

    let cert = Certificate::from_der(&acquired.service_cert_der).to_owned();
    observation.outcome = match budget(deadline, issuer).and_then(|b| {
        fetch(
            &http::pinned_agent(&cert, b),
            &route.configuration_url,
            limits::MAX_CONFIGURATION_BYTES,
        )
    }) {
        Ok(c) => Outcome::Retrieved(c),
        Err(e) => Outcome::Failed(e),
    };
    observation
}

/// GET and parse one configuration document on an already-built connection.
///
/// Split from [`observe`] so the status, size, redirect and parsing rules can
/// be exercised against a local server without a TLS identity.
fn fetch(agent: &ureq::Agent, url: &str, max_bytes: usize) -> Result<Configuration, AcquireError> {
    let bytes = http::get_bounded_optional(agent, url, max_bytes)?;
    parse(bytes, url)
}

/// Accept a JSON object and nothing else.
///
/// The fields are the service's to define, so none is required. The top level
/// must still be an object: anything else is not a configuration by any
/// implementation's definition, and printing it as one would invite a reader
/// to interpret it.
fn parse(bytes: Vec<u8>, url: &str) -> Result<Configuration, AcquireError> {
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        AcquireError::new(
            Diagnostic::MalformedConfiguration,
            format!("{url} did not return JSON: {e}"),
        )
    })?;
    let serde_json::Value::Object(document) = value else {
        return Err(AcquireError::new(
            Diagnostic::MalformedConfiguration,
            format!("{url} returned JSON that is not an object"),
        ));
    };
    Ok(Configuration {
        sha256: sha256_hex(&bytes),
        bytes,
        document,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    /// Serve exactly one canned HTTP response on a loopback port.
    ///
    /// Plain HTTP on purpose: these tests are about what happens after a
    /// connection exists — statuses, sizes, redirects, bodies — and TLS
    /// authentication is the pinned agent's job, shared with key acquisition.
    fn serve_once(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(&response);
            }
        });
        format!("http://{addr}/configuration")
    }

    fn respond(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn agent() -> ureq::Agent {
        http::public_roots_agent(Duration::from_secs(5))
    }

    const CCF_SHAPE: &[u8] = br#"{"authentication":{"allowUnauthenticated":true},"policy":{"policyScript":"export function apply(phdr) { return true; }"}}"#;

    #[test]
    fn a_json_object_is_retrieved_with_a_digest_of_the_exact_bytes() {
        let url = serve_once(respond("200 OK", "", CCF_SHAPE));
        let c = fetch(&agent(), &url, 1024).unwrap();
        assert_eq!(c.bytes, CCF_SHAPE);
        assert_eq!(c.sha256, sha256_hex(CCF_SHAPE));
        assert!(c.document.contains_key("policy"));
    }

    /// Nothing the service leaves out is filled in, and nothing it adds that
    /// this build has never heard of is dropped.
    #[test]
    fn unknown_fields_are_kept_and_absent_ones_are_not_invented() {
        let body = br#"{"somethingNew":{"nested":[1,2]}}"#;
        let url = serve_once(respond("200 OK", "", body));
        let c = fetch(&agent(), &url, 1024).unwrap();
        assert_eq!(c.document.len(), 1);
        assert_eq!(c.document["somethingNew"]["nested"][1], 2);
        assert!(!c.document.contains_key("authentication"));
    }

    /// The digest is over what arrived, not over a tidied copy. Duplicate keys
    /// and odd spacing survive in `bytes` even though the parsed map keeps one.
    #[test]
    fn the_digest_is_not_over_a_reserialised_document() {
        let body = br#"{ "a" : 1 , "a" : 2 }"#;
        let url = serve_once(respond("200 OK", "", body));
        let c = fetch(&agent(), &url, 1024).unwrap();
        assert_eq!(c.sha256, sha256_hex(body));
        assert_ne!(
            c.sha256,
            sha256_hex(serde_json::to_string(&c.document).unwrap().as_bytes())
        );
    }

    #[test]
    fn a_missing_endpoint_is_reported_as_not_served() {
        let url = serve_once(respond("404 Not Found", "", b""));
        let e = fetch(&agent(), &url, 1024).unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::EndpointNotServed);
    }

    #[test]
    fn a_refusal_is_reported_as_access_denied() {
        for status in ["401 Unauthorized", "403 Forbidden"] {
            let url = serve_once(respond(status, "", b""));
            let e = fetch(&agent(), &url, 1024).unwrap_err();
            assert_eq!(e.diagnostic, Diagnostic::AccessDenied, "{status}");
        }
    }

    #[test]
    fn a_server_error_is_a_transport_failure() {
        let url = serve_once(respond("503 Service Unavailable", "", b""));
        let e = fetch(&agent(), &url, 1024).unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::Transport);
    }

    /// A redirect would let the response choose where the next request goes,
    /// which is the one decision nothing the service sends may make.
    #[test]
    fn a_redirect_is_refused_rather_than_followed() {
        let url = serve_once(respond(
            "302 Found",
            "Location: http://127.0.0.1:9/elsewhere\r\n",
            b"",
        ));
        let e = fetch(&agent(), &url, 1024).unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::Transport);
        assert!(e.detail.contains("redirect"), "{}", e.detail);
    }

    #[test]
    fn an_oversized_response_is_refused() {
        let body = format!(r#"{{"pad":"{}"}}"#, "x".repeat(2048));
        let url = serve_once(respond("200 OK", "", body.as_bytes()));
        let e = fetch(&agent(), &url, 1024).unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::ResponseTooLarge);
    }

    #[test]
    fn a_body_that_is_not_json_is_malformed() {
        let url = serve_once(respond("200 OK", "", b"<html>hello</html>"));
        let e = fetch(&agent(), &url, 1024).unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::MalformedConfiguration);
    }

    #[test]
    fn json_that_is_not_an_object_is_malformed() {
        for body in [&b"[]"[..], b"\"policy\"", b"null", b"42"] {
            let e = parse(body.to_vec(), "u").unwrap_err();
            assert_eq!(e.diagnostic, Diagnostic::MalformedConfiguration);
        }
    }

    /// A server that accepts the connection and never answers must cost the
    /// budget and no more.
    #[test]
    fn a_silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let held = listener.accept();
            std::thread::sleep(Duration::from_secs(5));
            drop(held);
        });
        let started = Instant::now();
        let e = fetch(
            &http::public_roots_agent(Duration::from_millis(300)),
            &format!("http://{addr}/configuration"),
            1024,
        )
        .unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::Transport);
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn an_exhausted_deadline_fails_without_a_request() {
        let e = budget(Instant::now(), "x").unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::DeadlineExceeded);
    }

    #[test]
    fn a_service_not_asked_says_why_and_where_it_would_have_asked() {
        let o = Observation::not_attempted(
            "example-ledger.confidential-ledger.azure.com",
            "key acquisition failed",
            7,
        );
        assert!(matches!(o.outcome, Outcome::NotAttempted(ref r) if r.contains("key")));
        assert_eq!(
            o.url.as_deref(),
            Some("https://example-ledger.confidential-ledger.azure.com/configuration")
        );
        assert!(o.service_cert_sha256.is_none());
    }
}
