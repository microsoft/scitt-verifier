//! Drive a verification future that is expected never to suspend.
//!
//! The core is written once against TAV's asynchronous crypto API because
//! WebCrypto offers nothing else. On native backends that API is a blanket
//! wrapper over synchronous calls, so every future here completes on its
//! first poll. The synchronous entry points rely on that and poll once.
//!
//! A future that suspends is reported as a crypto error rather than waited on.
//! That cannot happen with a native backend; if a backend ever changes so
//! that it does, the result is an unanswered check, never a pass.

use crate::error::{Error, Result};
use std::future::Future;
use std::task::{Context, Poll, Waker};

/// Why a synchronous entry point gave up, for callers that report it.
pub const SUSPENDED: &str =
    "the crypto backend suspended, so this synchronous call cannot complete; use the async API";

/// Poll `future` once. `None` means it suspended.
pub fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

/// Poll a fallible `future` once, mapping suspension to [`Error::Crypto`].
pub fn run<T>(future: impl Future<Output = Result<T>>) -> Result<T> {
    poll_once(future).unwrap_or_else(|| Err(Error::Crypto(SUSPENDED.into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ready_future_completes() {
        assert_eq!(poll_once(async { 7 }), Some(7));
    }

    #[test]
    fn a_suspending_future_fails_closed() {
        let pending = std::future::pending::<Result<bool>>();
        assert!(matches!(run(pending), Err(Error::Crypto(_))));
    }
}
