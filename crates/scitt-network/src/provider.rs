//! Which ledgers this build knows how to bootstrap, and how.
//!
//! A provider maps a validated ledger hostname to the identity service that can
//! attest it. That mapping is the root of the whole flow, so it comes from code
//! an operator reviewed and shipped — never from the statement being checked.
//! A receipt naming a ledger cannot introduce the authority that vouches for
//! it; at most it can name one this build already trusts.

use crate::error::{AcquireError, Diagnostic};

/// Azure's public-cloud confidential ledger suffix.
const AZURE_LEDGER_SUFFIX: &str = ".confidential-ledger.azure.com";

/// The identity service for Azure public cloud.
const AZURE_IDENTITY_HOST: &str = "identity.confidential-ledger.core.azure.com";

/// Path on the ledger that serves the receipt-verification key set.
pub const KEYSET_PATH: &str = "/.well-known/scitt-keys";

/// Path on the ledger that serves each node's attestation report.
pub const QUOTES_PATH: &str = "/node/quotes";

/// Path on the ledger that serves the node certificates.
///
/// The api-version is pinned rather than left to the service's default: a
/// later version may rename a field or change what one means, and this build
/// would go on reading the response as though it had not.
pub const NODES_PATH: &str = "/gov/service/nodes?api-version=2024-07-01";

/// A bootstrap route for one ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The ledger issuer exactly as the policy allowlisted it.
    pub issuer: String,
    /// Stable name of the provider that produced this route, for the record.
    pub provider: &'static str,
    /// Where the service certificate is fetched from, authenticated by public PKI.
    pub identity_url: String,
    /// Where the key set is fetched from, authenticated by that certificate.
    pub keyset_url: String,
    /// Where node attestation reports are fetched from, authenticated by that
    /// certificate.
    pub quotes_url: String,
    /// Where node certificates are fetched from, authenticated by that
    /// certificate.
    pub nodes_url: String,
}

/// Resolve a ledger issuer to a bootstrap route.
///
/// Returns `UnsupportedProvider` rather than guessing when no shipped mapping
/// covers the host. Inventing an endpoint from a pattern would mean this build
/// could be pointed at a service nobody reviewed, which is the failure the
/// whole provider concept exists to prevent.
pub fn route_for(issuer: &str) -> Result<Route, AcquireError> {
    validate_host(issuer)?;

    if let Some(name) = issuer.strip_suffix(AZURE_LEDGER_SUFFIX) {
        // A ledger name must be a single label. Without this, a host like
        // `a.b.confidential-ledger.azure.com` would produce an identity-service
        // path containing a dot, and the request would no longer be asking
        // about the ledger the issuer named.
        if name.is_empty() || name.contains('.') {
            return Err(AcquireError::new(
                Diagnostic::UnsupportedProvider,
                format!("'{issuer}' is not a single-label Azure ledger name"),
            ));
        }
        return Ok(Route {
            issuer: issuer.to_string(),
            provider: "azure-public",
            identity_url: format!("https://{AZURE_IDENTITY_HOST}/ledgerIdentity/{name}"),
            keyset_url: format!("https://{issuer}{KEYSET_PATH}"),
            quotes_url: format!("https://{issuer}{QUOTES_PATH}"),
            nodes_url: format!("https://{issuer}{NODES_PATH}"),
        });
    }

    Err(AcquireError::new(
        Diagnostic::UnsupportedProvider,
        format!(
            "no bootstrap provider in this build covers '{issuer}'. \
             Supported: Azure public cloud ledgers ending '{AZURE_LEDGER_SUFFIX}'"
        ),
    ))
}

/// Accept only a bare DNS hostname.
///
/// A CWT `iss` is an opaque string, and an allowlist entry is whatever an
/// operator typed. Either could carry a scheme, credentials, a port, or a path,
/// and each of those changes where a request would go while still looking like
/// the host it names. Rejecting is the only safe reading: this build cannot know
/// what an operator meant by `ledger:8443@evil.example/x`, so it refuses to act
/// on it.
///
/// Note what this deliberately does *not* do: it does not lowercase, strip a
/// trailing dot, or otherwise normalise. Those would make the allowlist match
/// more strings than the operator wrote, and the allowlist is the one control
/// standing between an attacker-appended receipt and a network request.
pub fn validate_host(host: &str) -> Result<(), AcquireError> {
    let reject = |why: &str| {
        Err(AcquireError::new(
            Diagnostic::InvalidIssuer,
            format!("issuer '{host}' is not a bare hostname: {why}"),
        ))
    };

    if host.is_empty() {
        return reject("it is empty");
    }
    if host.len() > 253 {
        return reject("it is longer than 253 characters");
    }
    if host.contains("://") {
        return reject("it carries a URL scheme");
    }
    if host.contains('@') {
        return reject("it carries user information");
    }
    if host.contains(':') {
        return reject("it carries a port");
    }
    if host.contains('/') || host.contains('?') || host.contains('#') {
        return reject("it carries a path, query, or fragment");
    }
    if host.starts_with('.') || host.ends_with('.') {
        return reject("it has an empty leading or trailing label");
    }
    if host.contains("..") {
        return reject("it has an empty label");
    }

    for label in host.split('.') {
        if label.len() > 63 {
            return reject("a label is longer than 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return reject("a label starts or ends with a hyphen");
        }
        for c in label.chars() {
            if c.is_ascii_uppercase() {
                // Folding case here would let `LEDGER.example` match an
                // allowlist entry of `ledger.example`. DNS would resolve both,
                // but the policy author wrote one of them.
                return reject("it contains uppercase; allowlist matching is exact");
            }
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return reject("it contains characters outside [a-z0-9-]");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_ledger_maps_to_the_public_identity_service() {
        let r = route_for("example-ledger.confidential-ledger.azure.com").unwrap();
        assert_eq!(r.provider, "azure-public");
        assert_eq!(
            r.identity_url,
            "https://identity.confidential-ledger.core.azure.com/ledgerIdentity/example-ledger"
        );
        assert_eq!(
            r.keyset_url,
            "https://example-ledger.confidential-ledger.azure.com/.well-known/scitt-keys"
        );
        assert_eq!(
            r.quotes_url,
            "https://example-ledger.confidential-ledger.azure.com/node/quotes"
        );
        // The api-version is part of the pinned URL. If it ever moves, this
        // test is the record that it was a decision rather than a drift.
        assert_eq!(
            r.nodes_url,
            "https://example-ledger.confidential-ledger.azure.com\
             /gov/service/nodes?api-version=2024-07-01"
        );
    }

    #[test]
    fn unknown_suffix_is_rejected_rather_than_guessed() {
        let e = route_for("ledger.example.test").unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::UnsupportedProvider);
    }

    #[test]
    fn multi_label_azure_name_is_refused() {
        let e = route_for("a.b.confidential-ledger.azure.com").unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::UnsupportedProvider);
    }

    /// Each of these is a string that could be mistaken for a hostname while
    /// sending the request somewhere else.
    #[test]
    fn hosts_that_are_not_bare_hostnames_are_refused() {
        for bad in [
            "",
            "https://ledger.confidential-ledger.azure.com",
            "user@ledger.confidential-ledger.azure.com",
            "ledger.confidential-ledger.azure.com:8443",
            "ledger.confidential-ledger.azure.com/path",
            "ledger.confidential-ledger.azure.com?q=1",
            "ledger.confidential-ledger.azure.com#f",
            ".ledger.confidential-ledger.azure.com",
            "ledger.confidential-ledger.azure.com.",
            "ledger..confidential-ledger.azure.com",
            "-ledger.confidential-ledger.azure.com",
            "led_ger.confidential-ledger.azure.com",
        ] {
            let e = validate_host(bad).unwrap_err();
            assert_eq!(e.diagnostic, Diagnostic::InvalidIssuer, "accepted {bad:?}");
        }
    }

    #[test]
    fn uppercase_is_refused_rather_than_folded() {
        let e = validate_host("Ledger.confidential-ledger.azure.com").unwrap_err();
        assert_eq!(e.diagnostic, Diagnostic::InvalidIssuer);
    }
}
