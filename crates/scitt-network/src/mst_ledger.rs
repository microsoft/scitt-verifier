//! Authenticated transport for MST node evidence, without interpreting it.

use std::time::Instant;

use crate::{bootstrap, budget, http, limits, provider, AcquireError};

pub struct CollectedEvidence {
    pub host: String,
    pub service_certificate_der: Vec<u8>,
    pub quotes: Vec<u8>,
    pub nodes: Vec<u8>,
}

/// Fetch both evidence views over TLS pinned to independently acquired identity.
pub fn collect(host: &str, deadline: Instant) -> Result<CollectedEvidence, AcquireError> {
    let route = provider::route_for(host)?;
    let identity = bootstrap(host, deadline).map_err(|failure| failure.error)?;
    let agent = http::pinned_agent(&identity.service_cert, budget(deadline, host)?);
    let quotes = http::get_bounded(&agent, &route.quotes_url, limits::MAX_QUOTES_BYTES)?;
    let agent = http::pinned_agent(&identity.service_cert, budget(deadline, host)?);
    let nodes = http::get_bounded(&agent, &route.nodes_url, limits::MAX_NODES_BYTES)?;
    Ok(CollectedEvidence {
        host: route.issuer,
        service_certificate_der: identity.service_cert_der,
        quotes,
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_target_is_refused_before_acquisition() {
        let result = collect("https://example.test/path", Instant::now());
        assert!(matches!(
            result,
            Err(AcquireError {
                diagnostic: crate::Diagnostic::InvalidIssuer,
                ..
            })
        ));
    }
}
