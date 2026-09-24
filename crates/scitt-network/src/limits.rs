//! Bounds on a single acquisition run.
//!
//! These are constants rather than options on purpose. Every one of them is a
//! safety property of the trust flow — an operator who could raise them from
//! the command line could also be talked into raising them by the thing they
//! are meant to contain. A deployment gate that hangs is a gate that gets
//! removed, so the failure mode here is always "give up and say so".

use std::time::Duration;

/// How long to wait for a TCP connection and TLS handshake.
///
/// Reduced when less than this remains of [`TOTAL_DEADLINE`].
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most a single request may take.
///
/// A ceiling, not an allowance: a request is given the smaller of this and
/// whatever is left of [`TOTAL_DEADLINE`].
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Ceiling on the whole acquisition phase, across every ledger.
///
/// Distinct from the per-request timeout: several ledgers each finishing just
/// inside their own limit would otherwise add up to an unbounded wait. Enforced
/// before every request rather than only between ledgers, so the phase cannot
/// overshoot by a request timeout for each request already in flight.
pub const TOTAL_DEADLINE: Duration = Duration::from_secs(60);

/// Largest identity-service response we will read.
///
/// The document is a small JSON object holding one PEM certificate. Anything
/// approaching this is not that document.
pub const MAX_IDENTITY_BYTES: usize = 64 * 1024;

/// Largest key set we will read.
///
/// A CCF key set is a few hundred bytes per key. This leaves room for a service
/// that retains many rotations while still refusing an endless stream.
pub const MAX_KEYSET_BYTES: usize = 256 * 1024;

/// Largest node-quotes response we will read.
///
/// An SNP report is 1184 bytes, but each node's entry also carries an AMD
/// certificate chain and a UVM endorsement, which dominate: observed at
/// roughly 25 KB per node. This allows a large fleet while still refusing an
/// endless stream.
pub const MAX_QUOTES_BYTES: usize = 8 * 1024 * 1024;

/// Largest service-nodes response we will read.
///
/// One certificate and a little metadata per node, around 16 KB observed.
pub const MAX_NODES_BYTES: usize = 4 * 1024 * 1024;

/// Largest service-configuration response we will read.
///
/// A few hundred bytes observed, most of it the registration policy script.
/// This leaves room for a long Rego policy while still refusing an endless
/// stream, and it bounds how much untrusted text the report can be asked to
/// print.
pub const MAX_CONFIGURATION_BYTES: usize = 256 * 1024;

/// Most nodes one run will appraise.
///
/// Bounds the work before any parsing, so a response claiming an implausible
/// fleet is refused rather than expanded in memory.
pub const MAX_NODES: usize = 128;

/// Most ledgers one run may contact.
///
/// Receipts arrive in the statement's unprotected header bucket, which no
/// signature covers, so the number of *candidates* is chosen by whoever last
/// handled the file. The allowlist already bounds which of them can be
/// selected; this bounds the work even when an operator allowlists many.
pub const MAX_LEDGERS: usize = 8;
