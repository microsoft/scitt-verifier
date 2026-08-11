//! The result model.
//!
//! Every path through `verify` — including the ones that fail before a single
//! signature is checked — produces exactly one `Assessment`. That is the point
//! of this module. Earlier releases built the evidence record only after all
//! the checks had run, so the failures most worth auditing were the ones that
//! left no record at all, and a pipeline archiving evidence on `always()` got
//! an empty hand precisely when it needed the file.

use scitt_policy::PolicyDecision;
use scitt_receipt::StatementFacts;

/// The answer, and what a caller should do about it.
///
/// Success is split in two because "the signature and receipt are good" and
/// "the thing I am about to deploy is the thing that was registered" are
/// different claims, and only the second one is what a release gate is
/// actually asking. Collapsing both into `verified` let a run that never
/// looked at the artifact print the same word as one that did.
///
/// `CannotEvaluate` exists because the honest answer to some questions is "I
/// don't know", and a tool that collapses that into either pass or fail is
/// lying in one direction or the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The statement is transparent *and* it describes the artifact supplied.
    ArtifactTransparent,
    /// The statement is transparent, but no artifact binding was requested,
    /// so this run says nothing about what is being deployed.
    StatementTransparent,
    Untrusted,
    PolicyFailed,
    CannotEvaluate,
    UsageError,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::ArtifactTransparent => "artifact-transparent",
            Verdict::StatementTransparent => "statement-transparent",
            Verdict::Untrusted => "untrusted",
            Verdict::PolicyFailed => "policy-failed",
            Verdict::CannotEvaluate => "cannot-evaluate",
            Verdict::UsageError => "usage-error",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::ArtifactTransparent | Verdict::StatementTransparent => 0,
            Verdict::Untrusted => 1,
            Verdict::PolicyFailed => 2,
            Verdict::CannotEvaluate => 3,
            Verdict::UsageError => 4,
        }
    }

    pub fn is_pass(self) -> bool {
        matches!(
            self,
            Verdict::ArtifactTransparent | Verdict::StatementTransparent
        )
    }

    /// The first word of human output: the instruction, not the description.
    pub fn banner(self) -> &'static str {
        if self.is_pass() {
            "PASS"
        } else {
            "STOP"
        }
    }
}

/// Where a problem came from. Kept coarse on purpose — these are the buckets a
/// responder triages by, not a taxonomy of every possible fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// The operator gave us something we could not use.
    Input,
    /// The trust material is missing, stale, or scoped to another service.
    Trust,
    /// A signature or inclusion proof did not hold.
    Crypto,
    /// The statement does not describe the artifact.
    Binding,
    /// The relying party's own rules were not met.
    Policy,
    /// Something about the signer we did not establish.
    SignerIdentity,
    /// A real feature of the input that this build does not implement.
    /// Never evidence of compromise, and kept apart from `Crypto` for exactly
    /// that reason.
    Unsupported,
    /// The tool itself failed — writing a file, for instance.
    Internal,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Input => "input",
            Category::Trust => "trust",
            Category::Crypto => "crypto",
            Category::Binding => "binding",
            Category::Policy => "policy",
            Category::SignerIdentity => "signer-identity",
            Category::Unsupported => "unsupported",
            Category::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// A single named problem, with the thing to go do about it.
///
/// `action` is not decoration. A gate that says `ReceiptKeyUnknown` and stops
/// there has handed its user a research project; the difference between that
/// and "refresh the committed key set" is the difference between a five-minute
/// fix and an escalation.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub code: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub message: String,
    pub action: &'static str,
}

impl Diagnostic {
    pub fn error(
        code: &'static str,
        category: Category,
        message: impl Into<String>,
        action: &'static str,
    ) -> Self {
        Self {
            code,
            category,
            severity: Severity::Error,
            message: message.into(),
            action,
        }
    }

    /// Something that did not stop the run but that a reader must not miss.
    ///
    /// Emitted into `diagnostics` so a pipeline can detect it structurally
    /// rather than string-matching the human output for a notice.
    pub fn warning(
        code: &'static str,
        category: Category,
        message: impl Into<String>,
        action: &'static str,
    ) -> Self {
        Self {
            code,
            category,
            severity: Severity::Warning,
            message: message.into(),
            action,
        }
    }
}

/// The state of one of the four questions this tool answers.
///
/// `NotChecked` and `CannotEvaluate` are deliberately distinct: the first means
/// nobody asked, the second means we asked and could not find out. Reporting
/// them with the same token would hide the difference between an incomplete
/// invocation and a broken one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Pass,
    Fail,
    NotChecked,
    CannotEvaluate,
}

impl CheckState {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckState::Pass => "pass",
            CheckState::Fail => "fail",
            CheckState::NotChecked => "not-checked",
            CheckState::CannotEvaluate => "cannot-evaluate",
        }
    }

    /// The human rendering. Uppercase for anything that is not a clean pass,
    /// because these are the lines a reader must not skim past.
    pub fn label(self) -> &'static str {
        match self {
            CheckState::Pass => "pass",
            CheckState::Fail => "FAIL",
            CheckState::NotChecked => "NOT CHECKED",
            CheckState::CannotEvaluate => "CANNOT EVALUATE",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Checks {
    pub statement_signature: CheckState,
    pub receipt_inclusion: CheckState,
    pub artifact_binding: CheckState,
    pub policy: CheckState,
}

impl Checks {
    /// Nothing has been established yet. The starting point for every run, so
    /// that a failure at any depth reports the checks below it honestly.
    pub fn none() -> Self {
        Self {
            statement_signature: CheckState::NotChecked,
            receipt_inclusion: CheckState::NotChecked,
            artifact_binding: CheckState::NotChecked,
            policy: CheckState::NotChecked,
        }
    }
}

/// Something this run did not establish.
///
/// Structured rather than prose so that a fleet-wide report can count how many
/// deployments went out without artifact binding, which is a question no amount
/// of grepping English sentences answers reliably.
#[derive(Debug, Clone)]
pub struct Gap {
    pub code: &'static str,
    pub category: Category,
    pub message: String,
    pub impact: &'static str,
}

impl Gap {
    pub fn new(
        code: &'static str,
        category: Category,
        message: impl Into<String>,
        impact: &'static str,
    ) -> Self {
        Self {
            code,
            category,
            message: message.into(),
            impact,
        }
    }
}

/// How the trust material arrived, and therefore what it is worth.
///
/// Promoted to a first-class field because "the receipt signature is valid" is
/// only as meaningful as the answer to "valid under whose key, and who says
/// so". A raw COSE key set carries no publisher signature, so the honest
/// description of this mode is that it is trust-on-first-use with a paper
/// trail.
#[derive(Debug, Clone)]
pub struct Trust {
    pub mode: &'static str,
    pub issuer_scope: Option<String>,
    pub limitations: Vec<&'static str>,
}

impl Trust {
    pub fn unsigned_key_set(issuer_scope: Option<String>) -> Self {
        let mut limitations = vec![
            "the key set carries no publisher signature",
            "no revocation status is available offline",
            "no anti-rollback protection: an older key set will verify happily",
        ];
        if issuer_scope.is_none() {
            limitations.push("the key set is not scoped to an issuer (--issuer)");
        }
        Self {
            mode: "unsigned-scitt-keys",
            issuer_scope,
            limitations,
        }
    }

    pub fn describe(&self) -> &'static str {
        "unsigned SCITT key set"
    }
}

/// Everything one run of `verify` established, and everything it did not.
pub struct Assessment {
    pub verdict: Verdict,
    pub primary: Option<Diagnostic>,
    pub diagnostics: Vec<Diagnostic>,
    pub checks: Checks,
    pub not_checked: Vec<Gap>,
    pub trust: Trust,
    pub facts: Option<StatementFacts>,
    pub decision: Option<PolicyDecision>,
    pub binding: BindingResult,
}

impl Assessment {
    /// A run that stopped before it could establish anything.
    ///
    /// `not_checked` is a required argument rather than a default, because a
    /// run that stopped early has *more* gaps than one that finished, not
    /// fewer. Letting a caller omit it would produce the one output this tool
    /// must never emit: a failure report that claims nothing was skipped.
    pub fn incomplete(
        verdict: Verdict,
        trust: Trust,
        primary: Diagnostic,
        not_checked: Vec<Gap>,
    ) -> Self {
        Self {
            verdict,
            diagnostics: vec![primary.clone()],
            primary: Some(primary),
            checks: Checks::none(),
            not_checked,
            trust,
            facts: None,
            decision: None,
            binding: BindingResult::not_requested(),
        }
    }
}

/// Outcome of comparing the statement to the artifact on disk.
///
/// Four states, not three, because "nobody asked" and "we were asked and could
/// not find out" are different facts about a deployment, and a boolean with a
/// `None` for both of them cannot report the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// No artifact was supplied, or `--binding-mode none` was chosen.
    NotRequested,
    /// The artifact is the one the statement describes.
    Bound,
    /// The artifact is *not* the one the statement describes.
    Mismatch,
    /// A binding was requested, but the comparison could not be made — an
    /// unreadable artifact, or a statement whose payload is detached. This is
    /// not evidence of tampering, and must not be reported as though it were.
    CannotCompare,
}

#[derive(Debug, Clone)]
pub struct BindingResult {
    pub outcome: Binding,
    pub detail: String,
}

impl BindingResult {
    pub fn not_requested() -> Self {
        Self {
            outcome: Binding::NotRequested,
            detail: "no artifact binding was requested".into(),
        }
    }

    pub fn state(&self) -> CheckState {
        match self.outcome {
            Binding::Bound => CheckState::Pass,
            Binding::Mismatch => CheckState::Fail,
            Binding::CannotCompare => CheckState::CannotEvaluate,
            Binding::NotRequested => CheckState::NotChecked,
        }
    }

    /// What the record reports. `null` where no answer exists, so a consumer
    /// cannot read a missing comparison as a failed one.
    pub fn as_json_bool(&self) -> Option<bool> {
        match self.outcome {
            Binding::Bound => Some(true),
            Binding::Mismatch => Some(false),
            Binding::NotRequested | Binding::CannotCompare => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_successes_exit_zero_but_are_distinguishable() {
        assert_eq!(Verdict::ArtifactTransparent.exit_code(), 0);
        assert_eq!(Verdict::StatementTransparent.exit_code(), 0);
        assert_ne!(
            Verdict::ArtifactTransparent.as_str(),
            Verdict::StatementTransparent.as_str()
        );
    }

    #[test]
    fn only_the_two_transparent_verdicts_are_passes() {
        for v in [
            Verdict::Untrusted,
            Verdict::PolicyFailed,
            Verdict::CannotEvaluate,
            Verdict::UsageError,
        ] {
            assert!(!v.is_pass(), "{} must not be a pass", v.as_str());
            assert_eq!(v.banner(), "STOP");
        }
    }

    #[test]
    fn not_checked_and_cannot_evaluate_never_render_alike() {
        assert_ne!(
            CheckState::NotChecked.as_str(),
            CheckState::CannotEvaluate.as_str()
        );
        assert_ne!(
            CheckState::NotChecked.label(),
            CheckState::CannotEvaluate.label()
        );
    }

    #[test]
    fn an_incomplete_assessment_claims_nothing() {
        let a = Assessment::incomplete(
            Verdict::CannotEvaluate,
            Trust::unsigned_key_set(None),
            Diagnostic::error("X", Category::Trust, "m", "a"),
            vec![Gap::new(
                "PolicyNotEvaluated",
                Category::Policy,
                "No policy was evaluated.",
                "no relying-party decision was made about these facts",
            )],
        );
        assert_eq!(a.checks.statement_signature, CheckState::NotChecked);
        assert_eq!(a.checks.policy, CheckState::NotChecked);
        assert!(a.primary.is_some());
        assert_eq!(a.diagnostics.len(), 1);
        // A run that stopped early has more gaps than one that finished, so
        // an empty `notChecked` here would be a lie of omission.
        assert!(!a.not_checked.is_empty());
    }

    #[test]
    fn an_unscoped_key_set_names_that_as_a_limitation() {        let scoped = Trust::unsigned_key_set(Some("x".into()));
        let open = Trust::unsigned_key_set(None);
        assert!(open.limitations.len() > scoped.limitations.len());
    }

    #[test]
    fn a_comparison_that_could_not_be_made_is_not_a_mismatch() {
        // The distinction this enum exists for. "We could not compare" must
        // not reach a gate looking like "the artifact is wrong", because the
        // second sentence accuses someone and the first does not.
        let cannot = BindingResult {
            outcome: Binding::CannotCompare,
            detail: "detached".into(),
        };
        let mismatch = BindingResult {
            outcome: Binding::Mismatch,
            detail: "differs".into(),
        };
        assert_eq!(cannot.state(), CheckState::CannotEvaluate);
        assert_eq!(mismatch.state(), CheckState::Fail);
        assert_ne!(cannot.state(), mismatch.state());

        // In the record, only a real mismatch is `false`. An absent answer is
        // null, so a consumer cannot read it as a failed comparison.
        assert_eq!(cannot.as_json_bool(), None);
        assert_eq!(mismatch.as_json_bool(), Some(false));
    }

    #[test]
    fn not_requested_and_cannot_compare_are_different_facts() {
        let cannot = BindingResult {
            outcome: Binding::CannotCompare,
            detail: "unreadable".into(),
        };
        assert_eq!(BindingResult::not_requested().state(), CheckState::NotChecked);
        assert_eq!(cannot.state(), CheckState::CannotEvaluate);
    }
}