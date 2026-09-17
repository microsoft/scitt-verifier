//! Why an acquisition did not produce usable trust material.
//!
//! The codes are stable strings because a responder triages by them, and
//! because the difference between "the network was down" and "the key set did
//! not belong to the ledger" is the difference between retrying and stopping.
//! Collapsing them into one "acquisition failed" would leave both looking like
//! an outage, and only one of them is.

use std::fmt;

/// A coarse reason an acquisition failed.
///
/// Kept to the buckets a reader acts on, not a taxonomy of every fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Diagnostic {
    /// The issuer string was not a bare hostname.
    InvalidIssuer,
    /// No bootstrap provider in this build covers that ledger.
    UnsupportedProvider,
    /// DNS, connection, or HTTP status failure.
    Transport,
    /// A TLS connection could not be authenticated.
    TlsAuthentication,
    /// A response was larger than the limit for that endpoint.
    ResponseTooLarge,
    /// The identity service answered, but not with a usable certificate.
    MalformedIdentity,
    /// The key set was not a usable COSE_KeySet.
    MalformedKeySet,
    /// The key set did not contain the key the authenticated ledger presented.
    ServiceKeyMismatch,
    /// The acquisition deadline passed before this ledger was reached.
    DeadlineExceeded,
    /// This CPU lacks an instruction set the bundled TLS crypto requires.
    UnsupportedPlatform,
}

impl Diagnostic {
    /// The stable code that appears in structured output.
    pub fn code(self) -> &'static str {
        match self {
            Diagnostic::InvalidIssuer => "invalidIssuer",
            Diagnostic::UnsupportedProvider => "unsupportedProvider",
            Diagnostic::Transport => "transport",
            Diagnostic::TlsAuthentication => "tlsAuthentication",
            Diagnostic::ResponseTooLarge => "responseTooLarge",
            Diagnostic::MalformedIdentity => "malformedIdentity",
            Diagnostic::MalformedKeySet => "malformedKeySet",
            Diagnostic::ServiceKeyMismatch => "serviceKeyMismatch",
            Diagnostic::DeadlineExceeded => "deadlineExceeded",
            Diagnostic::UnsupportedPlatform => "unsupportedPlatform",
        }
    }

    /// Whether the fault is in how this run was configured.
    ///
    /// Configuration faults are knowable before any packet is sent, so they are
    /// a usage error rather than evidence about the ledger. Keeping them apart
    /// is what lets a typo in a policy read as a typo instead of an outage.
    pub fn is_configuration(self) -> bool {
        matches!(
            self,
            Diagnostic::InvalidIssuer
                | Diagnostic::UnsupportedProvider
                | Diagnostic::UnsupportedPlatform
        )
    }

    /// What to do about it.
    ///
    /// Paired with the code rather than written at each call site so that the
    /// same fault never gets two different pieces of advice, and so that
    /// advice to retry is only ever attached to faults that might pass.
    pub fn action(self) -> &'static str {
        match self {
            Diagnostic::InvalidIssuer => {
                "Give the issuer as a bare hostname, with no scheme, port, or path."
            }
            Diagnostic::UnsupportedProvider => {
                "This build has no bootstrap provider for that service. Fetch its key set \
                 out of band and pass it with --scitt-keys."
            }
            Diagnostic::Transport | Diagnostic::DeadlineExceeded => {
                "Check network reachability and retry. Nothing here says anything about \
                 the artifact."
            }
            Diagnostic::TlsAuthentication => {
                "The connection could not be authenticated to that service. Do not retry \
                 past this; investigate the endpoint before trusting anything it serves."
            }
            Diagnostic::ResponseTooLarge => {
                "The service returned more than this build will read. Fetch the key set \
                 out of band and pass it with --scitt-keys."
            }
            Diagnostic::MalformedIdentity | Diagnostic::MalformedKeySet => {
                "The service answered with something this build cannot use. Report it to \
                 the service operator."
            }
            Diagnostic::ServiceKeyMismatch => {
                "The key set did not contain the key the ledger authenticated with, so it \
                 cannot be that ledger's current key set. Do not work around this."
            }
            Diagnostic::UnsupportedPlatform => {
                "This build's TLS stack needs a newer CPU than this host provides. Run the \
                 fetch on a supported host and pass the key set with --scitt-keys, or run \
                 the verification itself there."
            }
        }
    }
}

/// A failed acquisition, with the code and the sentence explaining it.
#[derive(Debug, Clone)]
pub struct AcquireError {
    pub diagnostic: Diagnostic,
    pub detail: String,
}

impl AcquireError {
    pub fn new(diagnostic: Diagnostic, detail: impl Into<String>) -> Self {
        Self {
            diagnostic,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for AcquireError {}
