//! Authenticated transport for MST node evidence, without interpreting it.

use std::time::Instant;

use crate::{bootstrap, budget, http, limits, provider, AcquireError};

pub struct CollectedEvidence {
    pub host: String,
    pub service_certificate_der: Vec<u8>,
    pub quotes: Vec<u8>,
    pub nodes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionStep {
    ResolvingIdentity,
    Connecting,
    Authenticated,
    FetchingNodes,
}

/// Fetch both evidence views over TLS pinned to independently acquired identity.
pub fn collect(host: &str, deadline: Instant) -> Result<CollectedEvidence, AcquireError> {
    collect_with(host, deadline, &mut |_| {})
}

/// Observe actual transport boundaries; authentication is reported only after
/// the first pinned request has succeeded, never just after creating a client.
pub fn collect_with(
    host: &str,
    deadline: Instant,
    progress: &mut dyn FnMut(CollectionStep),
) -> Result<CollectedEvidence, AcquireError> {
    let route = provider::route_for(host)?;
    progress(CollectionStep::ResolvingIdentity);
    let identity = bootstrap(host, deadline).map_err(|failure| failure.error)?;
    progress(CollectionStep::Connecting);
    let agent = http::pinned_agent(&identity.service_cert, budget(deadline, host)?);
    let quotes = http::get_bounded(&agent, &route.quotes_url, limits::MAX_QUOTES_BYTES)?;
    progress(CollectionStep::Authenticated);
    progress(CollectionStep::FetchingNodes);
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

    #[test]
    fn refused_target_emits_no_transport_success() {
        let mut events = Vec::new();
        let result = collect_with("https://example.test/path", Instant::now(), &mut |step| {
            events.push(step)
        });
        assert!(result.is_err());
        assert!(events.is_empty());
    }
}
