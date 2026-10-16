//! Root authorization from an exact, independently approved HTTPS endpoint.
//!
//! A fetched certificate is an authorized anchor, not evidence that a path
//! validates. The existing chain validator must establish that separately.

use std::time::Instant;

use scitt_receipt::{chain::parse_pem_certificates, sha256_hex};

use crate::{budget, http, limits, validate_host, AcquireError, Diagnostic};

#[derive(Debug, Clone)]
pub struct Observation {
    pub url: String,
    pub acquired_at: i64,
    pub outcome: Result<RootBundle, AcquireError>,
}

#[derive(Debug, Clone)]
pub struct RootBundle {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub root_sha256: Vec<String>,
    pub encoding: Encoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Pem,
    Der,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::Der => "der",
        }
    }
}

/// Validate all policy destinations before any network acquisition starts.
pub fn validate_url(url: &str) -> Result<(), AcquireError> {
    let invalid = |why: &str| {
        AcquireError::new(
            Diagnostic::InvalidRootSource,
            format!("signing root source '{url}' is unusable: {why}"),
        )
    };
    if !url.starts_with("https://") || url.len() > 2048 || !url.is_ascii() {
        return Err(invalid(
            "expected an ASCII https:// URL of at most 2048 bytes",
        ));
    }
    if url
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || url.contains(['@', '?', '#', '\\'])
    {
        return Err(invalid(
            "credentials, queries, fragments, controls and backslashes are refused",
        ));
    }
    let uri: ureq::http::Uri = url.parse().map_err(|_| invalid("invalid URL syntax"))?;
    let authority = uri.authority().ok_or_else(|| invalid("no hostname"))?;
    validate_host(authority.host()).map_err(|_| invalid("expected a lowercase DNS hostname"))?;
    if authority.as_str().contains(':') && !matches!(authority.port_u16(), Some(1..=u16::MAX)) {
        return Err(invalid("invalid port"));
    }
    Ok(())
}

/// Fetch only a URL the caller has already authorized in relying-party policy.
///
/// Public WebPKI authenticates this endpoint. No statement field, redirect,
/// AIA URL, ambient credential, or unsigned cached response can replace it.
pub fn acquire(url: &str, now: i64, deadline: Instant) -> Observation {
    let outcome = validate_url(url)
        .and_then(|()| http::check_platform())
        .and_then(|()| budget(deadline, url))
        .and_then(|remaining| {
            fetch(
                &http::public_roots_agent(remaining),
                url,
                limits::MAX_ROOT_BYTES,
            )
        });
    Observation {
        url: url.to_string(),
        acquired_at: now,
        outcome,
    }
}

fn fetch(agent: &ureq::Agent, url: &str, max_bytes: usize) -> Result<RootBundle, AcquireError> {
    let bytes = http::get_bounded(agent, url, max_bytes)?;
    parse(bytes)
}

fn parse(bytes: Vec<u8>) -> Result<RootBundle, AcquireError> {
    let malformed = |why: String| AcquireError::new(Diagnostic::MalformedRoots, why);
    let (certificates, encoding) = if bytes.first() == Some(&0x30) {
        scitt_receipt::spki_from_certificate_der(&bytes).map_err(|e| malformed(e.to_string()))?;
        (vec![bytes.clone()], Encoding::Der)
    } else {
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            malformed(format!(
                "the root response is neither UTF-8 PEM nor DER: {e}"
            ))
        })?;
        (
            parse_pem_certificates(text).map_err(|e| malformed(e.to_string()))?,
            Encoding::Pem,
        )
    };
    if certificates.len() > limits::MAX_ROOT_CERTIFICATES {
        return Err(malformed(format!(
            "the root bundle contains {} certificates; the limit is {}",
            certificates.len(),
            limits::MAX_ROOT_CERTIFICATES
        )));
    }
    let mut root_sha256 = Vec::new();
    for der in &certificates {
        root_sha256.push(sha256_hex(der));
    }
    root_sha256.sort();
    root_sha256.dedup();
    Ok(RootBundle {
        sha256: sha256_hex(&bytes),
        bytes,
        root_sha256,
        encoding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::Duration;

    const PEM: &str = include_str!("../../scitt-verifier/tests/fixtures/external-chain/roots.pem");

    fn serve(status: &str, headers: &str, body: &[u8]) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut response = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(&response);
        });
        (format!("http://{address}/roots.pem"), thread)
    }

    #[test]
    fn root_sources_are_exact_https_destinations() {
        for url in [
            "https://roots.example/roots.pem",
            "https://roots.example:8443/roots.pem",
        ] {
            validate_url(url).unwrap();
        }
        for url in [
            "http://roots.example/roots.pem",
            "file:///roots.pem",
            "https://",
            "https://user:password@roots.example/roots.pem",
            "https://roots.example/roots.pem?token=secret",
            "https://roots.example/roots.pem#fragment",
            "https://roots.example\\other.example/roots.pem",
            "https://roots.example:0/roots.pem",
            "https://roots.example:65536/roots.pem",
            "https://roots.example:abc/roots.pem",
            "https://ROOTS.example/roots.pem",
            "https://roots.example./roots.pem",
            "https://roots.example/\r\ninjected",
        ] {
            let error = validate_url(url).unwrap_err();
            assert_eq!(error.diagnostic, Diagnostic::InvalidRootSource, "{url}");
        }
    }

    #[test]
    fn pem_bundle_records_exact_bytes_and_der_fingerprints() {
        let bytes = format!("{PEM}\n{PEM}").into_bytes();
        let bundle = parse(bytes.clone()).unwrap();
        assert_eq!(bundle.bytes, bytes);
        assert_eq!(bundle.sha256, sha256_hex(&bytes));
        assert_eq!(bundle.encoding, Encoding::Pem);
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../scitt-verifier/tests/fixtures/external-chain/expected.json"
        ))
        .unwrap();
        assert_eq!(
            bundle.root_sha256,
            [expected["rootSha256"].as_str().unwrap()]
        );
    }

    #[test]
    fn der_certificate_records_exact_bytes_and_rejects_trailing_or_truncated_data() {
        let der = parse_pem_certificates(PEM).unwrap().remove(0);
        let bundle = parse(der.clone()).unwrap();
        assert_eq!(bundle.bytes, der);
        assert_eq!(bundle.sha256, sha256_hex(&der));
        assert_eq!(bundle.root_sha256, [sha256_hex(&der)]);
        assert_eq!(bundle.encoding, Encoding::Der);
        let mut trailing = der.clone();
        trailing.push(0);
        for invalid in [
            der[..der.len() - 1].to_vec(),
            trailing,
            [der.as_slice(), der.as_slice()].concat(),
            vec![0x30, 0x03, 0x02, 0x01, 0x01],
        ] {
            assert_eq!(
                parse(invalid).unwrap_err().diagnostic,
                Diagnostic::MalformedRoots
            );
        }
    }

    #[test]
    fn invalid_empty_or_excessive_bundles_are_not_trust_material() {
        for bytes in [
            vec![0xff],
            Vec::new(),
            b"<html>not a certificate</html>".to_vec(),
            b"-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n".to_vec(),
            b"-----BEGIN CERTIFICATE-----\n!".to_vec(),
            format!("{PEM}\n-----BEGIN PRIVATE KEY-----\nAAEC\n-----END PRIVATE KEY-----\n")
                .into_bytes(),
            PEM.repeat(limits::MAX_ROOT_CERTIFICATES + 1).into_bytes(),
        ] {
            assert_eq!(
                parse(bytes).unwrap_err().diagnostic,
                Diagnostic::MalformedRoots
            );
        }
    }

    #[test]
    fn a_fetched_bundle_is_bounded_and_status_checked() {
        let agent = http::public_roots_agent(Duration::from_secs(5));
        let (url, server) = serve("200 OK", "", PEM.as_bytes());
        let bundle = fetch(&agent, &url, limits::MAX_ROOT_BYTES).unwrap();
        server.join().unwrap();
        assert_eq!(bundle.bytes, PEM.as_bytes());

        let (url, server) = serve("200 OK", "", PEM.as_bytes());
        let error = fetch(&agent, &url, 16).unwrap_err();
        server.join().unwrap();
        assert_eq!(error.diagnostic, Diagnostic::ResponseTooLarge);

        let (url, server) = serve("404 Not Found", "", PEM.as_bytes());
        assert_eq!(
            fetch(&agent, &url, limits::MAX_ROOT_BYTES)
                .unwrap_err()
                .diagnostic,
            Diagnostic::Transport
        );
        server.join().unwrap();
    }

    #[test]
    fn redirects_never_contact_the_second_destination() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let location = format!(
            "Location: http://{}/roots.pem\r\n",
            destination.local_addr().unwrap()
        );
        let (url, server) = serve("302 Found", &location, b"");
        let error = fetch(
            &http::public_roots_agent(Duration::from_secs(5)),
            &url,
            1024,
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.diagnostic, Diagnostic::Transport);
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn production_acquisition_refuses_plain_http_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/roots.pem", listener.local_addr().unwrap());
        let observation = acquire(&url, 7, Instant::now() + Duration::from_secs(5));
        assert_eq!(observation.acquired_at, 7);
        assert_eq!(
            observation.outcome.unwrap_err().diagnostic,
            Diagnostic::InvalidRootSource
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn an_exhausted_deadline_never_starts_a_request() {
        let observation = acquire("https://roots.example/roots.pem", 7, Instant::now());
        assert_eq!(
            observation.outcome.unwrap_err().diagnostic,
            Diagnostic::DeadlineExceeded
        );
    }

    #[test]
    fn https_never_accepts_an_unauthenticated_plaintext_response() {
        let (url, server) = serve("200 OK", "", PEM.as_bytes());
        let url = url.replacen("http://", "https://", 1);
        let observation = acquire(&url, 7, Instant::now() + Duration::from_secs(5));
        server.join().unwrap();
        assert!(matches!(
            observation.outcome.unwrap_err().diagnostic,
            Diagnostic::TlsAuthentication | Diagnostic::Transport
        ));
    }
}
