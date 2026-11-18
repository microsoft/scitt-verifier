//! Authenticated transport for MST node evidence, without interpreting it.

use std::time::{Duration, Instant};

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

/// The target's node list alone, over TLS pinned to its independently acquired identity.
///
/// For reading what the nodes declare about themselves before any evidence is
/// appraised. It is the same request [`collect_with`] makes, so it is
/// authenticated the same way; what it is *not* is attested, and a caller must
/// treat anything read from it as a claim to be checked rather than a fact.
pub fn fetch_nodes(host: &str, deadline: Instant) -> Result<Vec<u8>, AcquireError> {
    let route = provider::route_for(host)?;
    let identity = bootstrap(host, deadline).map_err(|failure| failure.error)?;
    let agent = http::pinned_agent(&identity.service_cert, budget(deadline, host)?);
    http::get_bounded(&agent, &route.nodes_url, limits::MAX_NODES_BYTES)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementStep {
    ResolvingIdentity,
    NotYetAvailable { attempt: u32, retry_in: Duration },
}

pub struct FetchedStatement {
    pub url: String,
    pub bytes: Vec<u8>,
    pub attempts: u32,
}

/// Fetch one registered statement, with its receipt, from a transparency service.
///
/// The connection is pinned to the certificate the identity service names for
/// `issuer`, as for key acquisition. That authenticates who served the bytes;
/// it is not why they are trusted. The statement is verified afterwards exactly
/// as one read from disk would be, so a service that served the wrong entry
/// produces a failed verification, never a pass.
///
/// The caller is responsible for having checked `issuer` against the policy.
pub fn fetch_statement(
    issuer: &str,
    transaction_id: &str,
    deadline: Instant,
    progress: &mut dyn FnMut(StatementStep),
) -> Result<FetchedStatement, AcquireError> {
    let url = provider::statement_url(issuer, transaction_id)?;
    progress(StatementStep::ResolvingIdentity);
    let identity = bootstrap(issuer, deadline).map_err(|failure| failure.error)?;
    let (bytes, attempts) = poll(
        deadline,
        &mut |_| {
            let agent = http::pinned_agent(&identity.service_cert, budget(deadline, issuer)?);
            http::get_bounded_when_ready(&agent, &url, limits::MAX_STATEMENT_BYTES)
        },
        &mut Instant::now,
        &mut |attempt, wait| {
            progress(StatementStep::NotYetAvailable {
                attempt,
                retry_in: wait,
            });
            std::thread::sleep(wait);
        },
    )
    .map_err(|e| match e.diagnostic {
        crate::Diagnostic::DeadlineExceeded => {
            AcquireError::new(e.diagnostic, format!("{url}: {}", e.detail))
        }
        _ => e,
    })?;
    Ok(FetchedStatement {
        url,
        bytes,
        attempts,
    })
}

/// Ask until the resource is ready or the deadline would pass.
///
/// A ledger loads older entries from storage on demand and answers 503 until
/// it has, so a first refusal is the expected case rather than a fault. The
/// wait grows to a few seconds and the deadline, not an attempt count, ends
/// it: what bounds a gate is how long it holds a pipeline. A wait that would
/// overrun the deadline is not started, so giving up costs no idle time.
fn poll(
    deadline: Instant,
    get: &mut dyn FnMut(u32) -> Result<Option<Vec<u8>>, AcquireError>,
    now: &mut dyn FnMut() -> Instant,
    wait: &mut dyn FnMut(u32, Duration),
) -> Result<(Vec<u8>, u32), AcquireError> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        if let Some(bytes) = get(attempt)? {
            return Ok((bytes, attempt));
        }
        let delay = Duration::from_secs(u64::from(attempt.min(5)));
        if deadline.saturating_duration_since(now()) <= delay {
            return Err(AcquireError::new(
                crate::Diagnostic::DeadlineExceeded,
                format!(
                    "still not available after {attempt} attempt(s) within the {}s acquisition \
                     deadline",
                    limits::TOTAL_DEADLINE.as_secs()
                ),
            ));
        }
        wait(attempt, delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    type Polled = Result<(Vec<u8>, u32), AcquireError>;

    /// Drive `poll` against a scripted service on a simulated clock.
    fn run_poll(responses: &[Result<Option<&[u8]>, crate::Diagnostic>]) -> (Polled, Vec<Duration>) {
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let mut waits = Vec::new();
        let result = poll(
            start + limits::TOTAL_DEADLINE,
            &mut |attempt| match responses.get(attempt as usize - 1) {
                Some(Ok(body)) => Ok(body.map(<[u8]>::to_vec)),
                Some(Err(d)) => Err(AcquireError::new(*d, "scripted")),
                None => Ok(None),
            },
            &mut || start + elapsed.get(),
            &mut |_, delay| {
                waits.push(delay);
                elapsed.set(elapsed.get() + delay);
            },
        );
        (result, waits)
    }

    #[test]
    fn a_statement_not_yet_loaded_is_asked_for_again() {
        let (result, waits) = run_poll(&[Ok(None), Ok(None), Ok(Some(b"cose"))]);
        let (bytes, attempts) = result.unwrap();
        assert_eq!((bytes.as_slice(), attempts), (&b"cose"[..], 3));
        assert_eq!(waits, [Duration::from_secs(1), Duration::from_secs(2)]);
    }

    #[test]
    fn polling_stops_before_a_wait_that_would_overrun_the_deadline() {
        let (result, waits) = run_poll(&[]);
        let e = result.unwrap_err();
        assert_eq!(e.diagnostic, crate::Diagnostic::DeadlineExceeded);
        let total: Duration = waits.iter().sum();
        assert!(total < limits::TOTAL_DEADLINE, "{total:?}");
        assert!(waits.iter().all(|w| *w <= Duration::from_secs(5)));
    }

    #[test]
    fn a_failure_other_than_not_ready_is_not_retried() {
        let (result, waits) = run_poll(&[Err(crate::Diagnostic::TlsAuthentication)]);
        assert_eq!(
            result.unwrap_err().diagnostic,
            crate::Diagnostic::TlsAuthentication
        );
        assert!(waits.is_empty());
    }

    #[test]
    fn an_invalid_statement_location_is_refused_before_any_request() {
        let mut events = Vec::new();
        let result = fetch_statement(
            "example-ledger.confidential-ledger.azure.com",
            "1.2/../../x",
            Instant::now(),
            &mut |step| events.push(step),
        );
        assert_eq!(
            result.err().map(|e| e.diagnostic),
            Some(crate::Diagnostic::InvalidStatementLocation)
        );
        assert!(events.is_empty());
    }

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
