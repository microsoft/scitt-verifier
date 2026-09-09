//! Binding a statement to the artifact it describes.
//!
//! Verification answers "is this statement genuine". Binding answers a
//! different and usually more urgent question: "is this statement about the
//! file I am holding". A statement can be perfectly genuine and describe
//! something else entirely, so the two are kept apart everywhere.
//!
//! This lives in the core rather than in the CLI because every embedder needs
//! it and none of them should reimplement it. A browser that compared bytes in
//! JavaScript and a pipeline that compared them here would eventually disagree
//! about a hash envelope or a detached payload, and the disagreement would
//! surface as a deployment that should have been stopped. The comparison is
//! pure — bytes in, verdict out — so it costs the core nothing.
//!
//! Note what is deliberately absent: nothing here reads a file, names a flag,
//! or chooses a mode. The mode is always supplied by the caller, because an
//! inferred binding is a claim the operator never made.

use crate::cbor::hex;
use crate::labels;
use crate::statement::{digest_with, sha256_hex, Sign1};

/// How the caller claims the artifact relates to the statement's payload.
///
/// There is no `None` here. "No binding was requested" is the absence of a
/// call, not a mode — modelling it as a mode invites a caller to ask for a
/// comparison and receive a pass for one nobody performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    /// The statement's payload is the artifact, byte for byte.
    PayloadBytes,
    /// The statement's payload is a digest of the artifact (RFC 9995).
    PayloadDigest,
}

impl BindingMode {
    /// The spelling used on the command line, in records, and in JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            BindingMode::PayloadBytes => "payload-bytes",
            BindingMode::PayloadDigest => "payload-digest",
        }
    }
}

/// The result of comparing an artifact against a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The artifact is the one the statement describes.
    Bound,
    /// The artifact is *not* the one the statement describes.
    Mismatch,
    /// The comparison could not be made. This is a limitation of the inputs,
    /// never evidence about the artifact, and must not be reported as though
    /// it were: `Mismatch` accuses an operator of shipping the wrong file.
    CannotCompare,
}

impl Binding {
    pub fn as_str(self) -> &'static str {
        match self {
            Binding::Bound => "bound",
            Binding::Mismatch => "mismatch",
            Binding::CannotCompare => "cannotCompare",
        }
    }
}

/// Why the comparison came out the way it did.
///
/// Structured rather than pre-formatted prose so that each caller can name the
/// artifact the way its own user does — a path in a pipeline, an uploaded file
/// name in a browser — while the finding itself stays identical between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingReason {
    PayloadIsArtifact {
        len: usize,
    },
    PayloadIsNotArtifact {
        payload_len: usize,
        payload_sha256: String,
        artifact_len: usize,
        artifact_sha256: String,
    },
    DigestIsArtifact {
        alg: String,
        len: usize,
    },
    DigestIsNotArtifact {
        alg: String,
        stated: String,
        computed: String,
    },
    /// `payload-bytes` was asked for, but the payload is a digest.
    HashEnvelopeNeedsDigestMode,
    /// `payload-digest` was asked for, but the payload is not a digest.
    NotAHashEnvelope,
    /// There is no payload carried in the statement to compare against.
    PayloadDetached {
        mode: BindingMode,
    },
    /// The signer named a hash this build cannot compute.
    UnsupportedHashAlg {
        alg: String,
    },
    /// The payload is the wrong length to be a digest of the named algorithm,
    /// so the statement is internally inconsistent.
    DigestLengthMismatch {
        alg: String,
        expected_len: usize,
        payload_len: usize,
    },
}

impl BindingReason {
    /// A short machine-stable tag, for records and JSON consumers that should
    /// not have to parse prose.
    pub fn code(&self) -> &'static str {
        match self {
            BindingReason::PayloadIsArtifact { .. } => "payloadIsArtifact",
            BindingReason::PayloadIsNotArtifact { .. } => "payloadIsNotArtifact",
            BindingReason::DigestIsArtifact { .. } => "digestIsArtifact",
            BindingReason::DigestIsNotArtifact { .. } => "digestIsNotArtifact",
            BindingReason::HashEnvelopeNeedsDigestMode => "hashEnvelopeNeedsDigestMode",
            BindingReason::NotAHashEnvelope => "notAHashEnvelope",
            BindingReason::PayloadDetached { .. } => "payloadDetached",
            BindingReason::UnsupportedHashAlg { .. } => "unsupportedHashAlg",
            BindingReason::DigestLengthMismatch { .. } => "digestLengthMismatch",
        }
    }

    /// The finding, in prose, naming the artifact as `artifact`.
    ///
    /// Deliberately stops at the finding and offers no remedy. The remedy
    /// differs by caller — a command-line flag is meaningless in a browser —
    /// so each one appends its own rather than inheriting advice its user
    /// cannot act on.
    pub fn describe(&self, artifact: &str) -> String {
        match self {
            BindingReason::PayloadIsArtifact { len } => {
                format!("the statement payload is byte-identical to {artifact} ({len} bytes)")
            }
            BindingReason::PayloadIsNotArtifact {
                payload_len,
                payload_sha256,
                artifact_len,
                artifact_sha256,
            } => format!(
                "the statement payload ({payload_len} bytes, sha256 {payload_sha256}) does not \
                 equal {artifact} ({artifact_len} bytes, sha256 {artifact_sha256})"
            ),
            BindingReason::DigestIsArtifact { alg, len } => format!(
                "{alg} of {artifact} ({len} bytes) equals the statement's hash-envelope payload"
            ),
            BindingReason::DigestIsNotArtifact {
                alg,
                stated,
                computed,
            } => format!(
                "the statement's hash-envelope payload ({alg} {stated}) does not equal {alg} of \
                 {artifact} ({computed})"
            ),
            BindingReason::HashEnvelopeNeedsDigestMode => {
                "this statement is a COSE Hash Envelope, so its payload is a digest rather than \
                 the artifact"
                    .into()
            }
            BindingReason::NotAHashEnvelope => {
                "this statement is not a COSE Hash Envelope: protected header 258 (payload hash \
                 algorithm) is absent, so its payload is not a digest"
                    .into()
            }
            BindingReason::PayloadDetached { mode } => format!(
                "the statement payload is detached, so binding mode {} has nothing to compare \
                 {artifact} against",
                mode.as_str()
            ),
            BindingReason::UnsupportedHashAlg { alg } => format!(
                "the statement names payload hash algorithm {alg}, which this build cannot \
                 compute; refusing to substitute a different one"
            ),
            BindingReason::DigestLengthMismatch {
                alg,
                expected_len,
                payload_len,
            } => format!(
                "the statement names payload hash algorithm {alg} ({expected_len} bytes) but its \
                 payload is {payload_len} bytes, so the payload is not a digest of that algorithm"
            ),
        }
    }
}

/// A binding outcome together with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingReport {
    pub outcome: Binding,
    pub reason: BindingReason,
}

impl BindingReport {
    fn new(outcome: Binding, reason: BindingReason) -> Self {
        Self { outcome, reason }
    }
}

/// Compare `artifact` against what `statement` says about it.
///
/// Never returns `Mismatch` for a question the inputs cannot answer. That
/// distinction is the whole point of the `CannotCompare` arm: a detached
/// payload, a mode that does not fit the statement, or a hash this build lacks
/// are all facts about the comparison, not about the artifact, and collapsing
/// them into `Mismatch` would tell an operator to halt a release over a
/// limitation of the tool.
pub fn bind(statement: &Sign1, artifact: &[u8], mode: BindingMode) -> BindingReport {
    match mode {
        BindingMode::PayloadBytes => bind_payload_bytes(statement, artifact),
        BindingMode::PayloadDigest => bind_payload_digest(statement, artifact),
    }
}

fn bind_payload_bytes(statement: &Sign1, artifact: &[u8]) -> BindingReport {
    // A hash envelope's payload is a digest, so comparing it to the artifact
    // would always differ. Reporting a mismatch here would accuse the operator
    // of shipping a tampered artifact when the real fault is the mode.
    if statement.is_hash_envelope() {
        return BindingReport::new(
            Binding::CannotCompare,
            BindingReason::HashEnvelopeNeedsDigestMode,
        );
    }

    let Some(payload) = statement.payload.as_deref() else {
        return BindingReport::new(
            Binding::CannotCompare,
            BindingReason::PayloadDetached {
                mode: BindingMode::PayloadBytes,
            },
        );
    };

    if payload == artifact {
        BindingReport::new(
            Binding::Bound,
            BindingReason::PayloadIsArtifact {
                len: artifact.len(),
            },
        )
    } else {
        BindingReport::new(
            Binding::Mismatch,
            BindingReason::PayloadIsNotArtifact {
                payload_len: payload.len(),
                payload_sha256: sha256_hex(payload),
                artifact_len: artifact.len(),
                artifact_sha256: sha256_hex(artifact),
            },
        )
    }
}

/// COSE Hash Envelope binding (RFC 9995).
///
/// The artifact is hashed with the algorithm named in protected header 258
/// rather than a default: the signer chose it, and quietly substituting
/// another would mean checking something the signer never asserted.
fn bind_payload_digest(statement: &Sign1, artifact: &[u8]) -> BindingReport {
    let Some(alg) = statement.payload_hash_alg() else {
        return BindingReport::new(Binding::CannotCompare, BindingReason::NotAHashEnvelope);
    };

    let Some(payload) = statement.payload.as_deref() else {
        return BindingReport::new(
            Binding::CannotCompare,
            BindingReason::PayloadDetached {
                mode: BindingMode::PayloadDigest,
            },
        );
    };

    let alg_name = labels::alg::name(alg);

    let Some(computed) = digest_with(alg, artifact) else {
        // An unsupported hash is a limitation of this tool, never a finding
        // about the artifact.
        return BindingReport::new(
            Binding::CannotCompare,
            BindingReason::UnsupportedHashAlg { alg: alg_name },
        );
    };

    // A length difference means the payload was not produced by the algorithm
    // the header names. Say so, rather than reporting a content mismatch: the
    // statement is internally inconsistent.
    if payload.len() != computed.len() {
        return BindingReport::new(
            Binding::CannotCompare,
            BindingReason::DigestLengthMismatch {
                alg: alg_name,
                expected_len: computed.len(),
                payload_len: payload.len(),
            },
        );
    }

    if payload == computed.as_slice() {
        BindingReport::new(
            Binding::Bound,
            BindingReason::DigestIsArtifact {
                alg: alg_name,
                len: artifact.len(),
            },
        )
    } else {
        BindingReport::new(
            Binding::Mismatch,
            BindingReason::DigestIsNotArtifact {
                alg: alg_name,
                stated: hex(payload),
                computed: hex(&computed),
            },
        )
    }
}
