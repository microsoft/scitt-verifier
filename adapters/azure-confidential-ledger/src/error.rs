//! What can go wrong before an appraisal can even be attempted.
//!
//! Deliberately small, and deliberately distinct from a *finding*. A malformed
//! bundle is not evidence that a ledger is misconfigured, and must never reach
//! a report looking like one. Anything this crate genuinely assessed comes
//! back as a [`crate::Check`]; only inputs it could not use at all come back
//! as an error.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppraisalError {
    /// The bundle contained no nodes.
    ///
    /// An error rather than a passing appraisal over an empty set, which is
    /// the shape this whole design exists to refuse: zero nodes assessed, zero
    /// mismatches found, therefore everything agrees.
    EmptyBundle,
    /// A required piece of evidence was absent for a node.
    MissingEvidence { node_id: String, what: &'static str },
    /// Evidence was present but could not be parsed.
    Malformed { node_id: String, detail: String },
    /// The consumer's requirements could not be applied as written.
    UnusableRequirements(String),
}

impl fmt::Display for AppraisalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppraisalError::EmptyBundle => {
                write!(
                    f,
                    "the evidence bundle contains no nodes; an empty set cannot be appraised"
                )
            }
            AppraisalError::MissingEvidence { node_id, what } => {
                write!(f, "node {node_id} is missing its {what}")
            }
            AppraisalError::Malformed { node_id, detail } => {
                write!(f, "node {node_id} supplied unusable evidence: {detail}")
            }
            AppraisalError::UnusableRequirements(detail) => {
                write!(f, "the configured requirements cannot be applied: {detail}")
            }
        }
    }
}

impl std::error::Error for AppraisalError {}
