//! Acquisition of MAA's certificate evidence and unsigned build-version header.

use crate::{http, limits, validate_host, AcquireError, Diagnostic};

pub const VERSION_HEADER: &str = "x-ms-maa-service-version";
pub const MAX_CERTS_BYTES: usize = 4 * 1024 * 1024;

/// Accept only a service origin, so appending /certs cannot change authority.
pub fn endpoint_host(endpoint: &str) -> Result<&str, AcquireError> {
    let host = endpoint
        .strip_prefix("https://")
        .map(|origin| origin.strip_suffix('/').unwrap_or(origin))
        .ok_or_else(|| {
            AcquireError::new(
                Diagnostic::UnsupportedProvider,
                "MAA endpoint must be an HTTPS service origin",
            )
        })?;
    certs_url(host)?;
    Ok(host)
}

#[derive(Debug, Clone)]
pub struct Acquired {
    pub certs_json: Vec<u8>,
    pub service_version: Option<String>,
}

pub fn collect(host: &str) -> Result<Acquired, AcquireError> {
    let url = certs_url(host)?;
    http::check_platform()?;
    fetch(&http::public_roots_agent(limits::REQUEST_TIMEOUT), &url)
}

fn certs_url(host: &str) -> Result<String, AcquireError> {
    validate_host(host)?;
    if !host.ends_with(".attest.azure.net") {
        return Err(AcquireError::new(
            Diagnostic::UnsupportedProvider,
            format!(
                "MAA evidence acquisition supports hosts ending '.attest.azure.net', not '{host}'"
            ),
        ));
    }
    Ok(format!("https://{host}/certs"))
}

fn fetch(agent: &ureq::Agent, url: &str) -> Result<Acquired, AcquireError> {
    let (certs_json, service_version) =
        http::get_bounded_with_header(agent, url, MAX_CERTS_BYTES, Some(VERSION_HEADER))?;
    let value: serde_json::Value = serde_json::from_slice(&certs_json).map_err(|e| {
        AcquireError::new(
            Diagnostic::MalformedKeySet,
            format!("{url} did not return a JSON key set: {e}"),
        )
    })?;
    if !value.is_object() || !value.get("keys").is_some_and(serde_json::Value::is_array) {
        return Err(AcquireError::new(
            Diagnostic::MalformedKeySet,
            format!("{url} did not return an object with a keys array"),
        ));
    }
    Ok(Acquired {
        certs_json,
        service_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn serve(headers: &str, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        );
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{address}/certs")
    }

    #[test]
    fn only_reviewed_https_maa_hosts_can_be_acquired() {
        assert_eq!(
            certs_url("example.region.attest.azure.net").unwrap(),
            "https://example.region.attest.azure.net/certs"
        );
        for host in [
            "https://example.attest.azure.net",
            "example.attest.azure.net:443",
            "example.attest.azure.net/path",
            "example.attest.azure.net.evil.invalid",
            "attest.azure.net",
            "EXAMPLE.attest.azure.net",
        ] {
            assert!(certs_url(host).is_err(), "{host}");
        }
    }

    #[test]
    fn endpoint_is_only_an_https_maa_origin_with_optional_trailing_slash() {
        for endpoint in [
            "https://example.region.attest.azure.net",
            "https://example.region.attest.azure.net/",
        ] {
            let host = endpoint_host(endpoint).unwrap();
            assert_eq!(host, "example.region.attest.azure.net");
            assert_eq!(
                certs_url(host).unwrap(),
                "https://example.region.attest.azure.net/certs"
            );
        }
        for endpoint in [
            "http://example.attest.azure.net",
            "example.attest.azure.net",
            "https://user@example.attest.azure.net",
            "https://user:password@example.attest.azure.net",
            "https://example.attest.azure.net:443",
            "https://example.attest.azure.net/certs",
            "https://example.attest.azure.net//",
            "https://example.attest.azure.net?query",
            "https://example.attest.azure.net#fragment",
            "https://example.attest.azure.net\\evil",
            "https://example.attest.azure.net.evil.invalid",
            "https://127.0.0.1",
            "https://",
            "https:///example.attest.azure.net",
            "https://EXAMPLE.attest.azure.net",
            "https://example.attest.azure.net\n",
        ] {
            assert!(endpoint_host(endpoint).is_err(), "{endpoint:?}");
        }
    }

    #[test]
    fn body_bytes_and_build_header_come_from_the_same_response() {
        let body = "{ \"keys\": [] }\n";
        let url = serve("X-MS-MAA-Service-Version: 1.2.3.4\r\n", body);
        let acquired = fetch(&http::public_roots_agent(Duration::from_secs(2)), &url).unwrap();
        assert_eq!(acquired.certs_json, body.as_bytes());
        assert_eq!(acquired.service_version.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn missing_version_is_absent_not_defaulted() {
        let url = serve("", r#"{"keys":[]}"#);
        let acquired = fetch(&http::public_roots_agent(Duration::from_secs(2)), &url).unwrap();
        assert!(acquired.service_version.is_none());
    }

    #[test]
    fn ambiguous_version_and_malformed_key_sets_are_refused() {
        for (headers, body) in [
            (
                "x-ms-maa-service-version: 1\r\nx-ms-maa-service-version: 2\r\n",
                r#"{"keys":[]}"#,
            ),
            ("", "[]"),
            ("", r#"{"keys":{}}"#),
            ("", "not-json"),
        ] {
            let url = serve(headers, body);
            assert!(fetch(&http::public_roots_agent(Duration::from_secs(2)), &url).is_err());
        }
    }
}
