//! Appraisal of ledger node evidence against a statement-derived commitment.
//!
//! The question this crate answers is narrow and worth stating exactly: *does
//! the execution policy embedded in an already-accepted transparent statement
//! match the policy the attested nodes are actually enforcing?*
//!
//! It does not verify the statement — that happened before anything here runs,
//! and this crate takes the result as given. It does not fetch evidence; a
//! caller supplies bytes. It does not decide what any of this means for a
//! deployment: it reports findings, and something above it decides.
//!
//! That last separation is the important one. This crate has no way to express
//! a verdict, because the type does not exist here. An adapter that could
//! return "pass" could turn evidence it failed to gather into a successful
//! deployment gate, which is the single failure this design exists to prevent.

pub mod bundle;
pub mod error;
#[cfg(feature = "mst-ledger")]
mod identity;
#[cfg(feature = "mst-ledger")]
mod snp;

pub use bundle::{EvidenceBundle, NodeEvidence};
pub use error::AppraisalError;

/// The state of one check.
///
/// The same four states the CLI reports, defined here rather than imported so
/// this crate stays independent of the binary that presents it. The caller
/// maps these into its own vocabulary.
///
/// `NotChecked` and `CannotEvaluate` are kept apart for the reason they are
/// everywhere else in this project: the first says nobody asked, the second
/// says we asked and could not find out. Collapsing them lets an incomplete
/// run read like a complete one.
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

    /// Whether this state permits an overall pass.
    ///
    /// Only a clean `Pass` does. In particular `CannotEvaluate` does not, so a
    /// check nobody could complete can never be silently counted as satisfied.
    pub fn is_pass(self) -> bool {
        matches!(self, CheckState::Pass)
    }
}

/// One finding: a state, and the reason for it.
///
/// The reason is not optional. A bare `CannotEvaluate` tells an operator
/// nothing they can act on, and this crate produces a lot of them.
#[derive(Debug, Clone)]
pub struct Check {
    pub state: CheckState,
    pub detail: String,
}

impl Check {
    pub fn new(state: CheckState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: detail.into(),
        }
    }

    pub fn cannot_evaluate(detail: impl Into<String>) -> Self {
        Self::new(CheckState::CannotEvaluate, detail)
    }
}

/// The checks this adapter contributes, one field each.
///
/// Fields rather than a list, deliberately. The set is fixed and known at
/// compile time, so making each one a field means a check cannot be
/// *forgotten*: adding one breaks every construction site until it is filled
/// in. A `Vec` would let an unimplemented check simply be absent, and an
/// absent check is indistinguishable from one that passed.
///
/// (The CLI holds its adapter checks in a list for the opposite reason: across
/// adapters the set is open, and it cannot know in advance what it will be
/// handed.)
#[derive(Debug, Clone)]
pub struct Appraisal {
    /// Each report's attested key belongs to the intended ledger's service
    /// identity: service certificate → node certificate → `REPORT_DATA`.
    pub ledger_identity_binding: Check,
    /// The SNP report and AMD collateral authenticate, the UVM endorsement
    /// authenticates, and platform requirements are met.
    pub snp_uvm_validation: Check,
    /// The statement-derived policy digest equals the authenticated
    /// `HOST_DATA` on every assessed node.
    pub cce_policy_host_data: Check,
    /// Every node in the assessed membership snapshot produced usable
    /// evidence.
    pub node_coverage: Check,
    /// Permanently unavailable against CCF; see [`Appraisal::unevaluated`].
    pub freshness: Check,
    /// Permanently unavailable against CCF; see [`Appraisal::unevaluated`].
    pub connection_binding: Check,
    /// Per-node findings, in the order the nodes were assessed.
    pub nodes: Vec<NodeOutcome>,
}

/// The stable machine name and human label of each check, in report order.
///
/// Held here rather than at the call site so the record and the human output
/// cannot drift apart.
pub const CHECK_NAMES: [(&str, &str); 6] = [
    ("ledger-identity-binding", "Ledger identity/key binding"),
    ("snp-uvm-validation", "SNP and UVM validation"),
    ("cce-policy-host-data", "CCE policy / HOST_DATA"),
    ("node-coverage", "Enumerated-node coverage"),
    ("freshness", "Freshness"),
    ("connection-binding", "Connection binding"),
];

impl Appraisal {
    /// Nothing has been established.
    ///
    /// This is the only starting point, and every field begins at
    /// `CannotEvaluate` rather than `Pass`. A partially implemented appraisal
    /// therefore reports honestly by default: code that has not run yet cannot
    /// contribute a pass it did not earn.
    ///
    /// `freshness` and `connection_binding` are given their permanent reasons
    /// here because they are not pending work. CCF offers no challenge-response
    /// attestation, so no nonce can be bound into a report, and the endpoint
    /// load-balances per connection, so nothing ties a served response to an
    /// attested node. Both are properties of the service, not gaps in this
    /// crate, and they are expected to read `CANNOT EVALUATE` forever.
    pub fn unevaluated(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            ledger_identity_binding: Check::cannot_evaluate(reason.clone()),
            snp_uvm_validation: Check::cannot_evaluate(reason.clone()),
            cce_policy_host_data: Check::cannot_evaluate(reason.clone()),
            node_coverage: Check::cannot_evaluate(reason),
            freshness: Check::cannot_evaluate(
                "CCF offers no challenge-response attestation, so no nonce can be bound \
                 into a report; a stored report cannot be shown to be current",
            ),
            connection_binding: Check::cannot_evaluate(
                "the ledger endpoint load-balances per connection, so no served response \
                 can be tied to a specific attested node",
            ),
            nodes: Vec::new(),
        }
    }

    /// The checks in report order, paired with their names.
    pub fn checks(&self) -> [(&'static str, &'static str, &Check); 6] {
        [
            (
                CHECK_NAMES[0].0,
                CHECK_NAMES[0].1,
                &self.ledger_identity_binding,
            ),
            (CHECK_NAMES[1].0, CHECK_NAMES[1].1, &self.snp_uvm_validation),
            (
                CHECK_NAMES[2].0,
                CHECK_NAMES[2].1,
                &self.cce_policy_host_data,
            ),
            (CHECK_NAMES[3].0, CHECK_NAMES[3].1, &self.node_coverage),
            (CHECK_NAMES[4].0, CHECK_NAMES[4].1, &self.freshness),
            (CHECK_NAMES[5].0, CHECK_NAMES[5].1, &self.connection_binding),
        ]
    }

    /// Whether every check that must hold for a scoped pass did hold.
    ///
    /// `freshness` and `connection_binding` are excluded because they can
    /// never pass, and a gate that required them could never succeed — which
    /// in practice means operators route around it. What they *do* is bound
    /// the claim: a pass here is a statement about the assessed membership
    /// snapshot, not about the service right now. The caller is responsible
    /// for saying so, and must not present this as an unqualified pass.
    pub fn scoped_pass(&self) -> bool {
        self.ledger_identity_binding.state.is_pass()
            && self.snp_uvm_validation.state.is_pass()
            && self.cce_policy_host_data.state.is_pass()
            && self.node_coverage.state.is_pass()
    }

    /// The checks that `scoped_pass` consults and that did not pass.
    ///
    /// Exists so a caller can say *why* there was no pass without re-deriving
    /// the rule. Listing every non-passing check instead would name
    /// `freshness` and `connection_binding`, which are excluded above and had
    /// no bearing on the outcome — telling an operator to go investigate two
    /// things that were never going to change the answer.
    ///
    /// Empty exactly when [`Appraisal::scoped_pass`] is true.
    pub fn blocking(&self) -> Vec<(&'static str, &'static str)> {
        // Written out rather than sliced from `checks()`, so that reordering
        // the report cannot silently change which checks are decisive. This
        // list and `scoped_pass` must always name the same four.
        [
            (CHECK_NAMES[0], &self.ledger_identity_binding),
            (CHECK_NAMES[1], &self.snp_uvm_validation),
            (CHECK_NAMES[2], &self.cce_policy_host_data),
            (CHECK_NAMES[3], &self.node_coverage),
        ]
        .into_iter()
        .filter(|(_, check)| !check.state.is_pass())
        .map(|((name, label), _)| (name, label))
        .collect()
    }
}

/// What one node's evidence established.
#[derive(Debug, Clone)]
pub struct NodeOutcome {
    /// The node identifier as the ledger reported it.
    pub node_id: String,
    /// The report's attested key belongs to this ledger's service identity.
    pub identity_binding: CheckState,
    /// The SNP report, AMD collateral and UVM endorsement authenticate.
    pub attestation: CheckState,
    /// Authenticated `HOST_DATA` equals the statement-derived digest.
    pub host_data_match: CheckState,
    pub detail: String,
}

/// Consumer-configured acceptance requirements.
///
/// Supplied by the caller from its policy document. This crate never reads a
/// policy file and never infers a requirement from the evidence it is
/// appraising — evidence does not get to say what would make it acceptable.
#[derive(Debug, Clone)]
pub struct Requirements {
    /// The did:x509 the UVM endorsement chain must anchor to.
    pub uvm_did_x509: String,
    /// The expected UVM feed, e.g. `ContainerPlat-AMD-UVM`.
    pub uvm_feed: String,
    /// The EKU the UVM endorsement's signer must carry.
    ///
    /// Enforced by this crate rather than by TAV: TAV's did:x509 parser
    /// discards everything after `::`, so a declared `::eku:` suffix is parsed
    /// and then ignored. A root pin alone does not distinguish signing roles,
    /// and the statement and UVM endorsement were observed sharing a root.
    pub uvm_eku: String,
    /// Minimum acceptable UVM guest SVN.
    ///
    /// Unrelated to a statement's artifact-rollback version: this is a
    /// property of the platform the ledger runs on, not of the thing signed.
    pub min_uvm_svn: u64,
    /// Minimum acceptable reported TCB, per CPU generation.
    ///
    /// Per generation because the comparison is generation-aware and a floor
    /// pinned to one generation's value silently rejects nodes of another.
    ///
    /// A *floor*, not a pin, for a reason observed on a live three-node ledger
    /// (2026-09-22): its nodes reported two different TCBs, and two different
    /// launch measurements. A requirement demanding one exact value would have
    /// rejected part of a healthy fleet. The comparison is componentwise and
    /// refuses incomparable values, so the floor must be at or below every
    /// node's version in every field.
    pub min_tcb: Vec<TcbFloor>,
}

/// A minimum TCB for one CPU generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbFloor {
    /// CPU generation name as the policy spells it, e.g. `genoa`.
    pub generation: String,
    /// The raw 64-bit reported-TCB floor.
    pub reported_tcb: u64,
}

/// Appraise a bundle of node evidence against a statement-derived digest.
///
/// `policy_digest` is the SHA-256 of the exact decoded execution policy bytes
/// taken from the statement that already passed acceptance. It is a parameter
/// rather than something derived here so that the bytes compared are provably
/// the bytes that were accepted.
///
/// Returns findings, never a verdict.
#[cfg(not(feature = "mst-ledger"))]
pub fn appraise(
    _bundle: &EvidenceBundle,
    _policy_digest: &[u8; 32],
    _requirements: &Requirements,
) -> Result<Appraisal, AppraisalError> {
    // Reporting `CannotEvaluate` for every check is the correct answer for a
    // build that cannot appraise attestation, and is why `unevaluated` is the
    // only constructor: there is no state of this crate in which absent
    // functionality reports a pass.
    Ok(Appraisal::unevaluated(
        "this build was compiled without the mst-ledger adapter, so no attestation \
         evidence can be appraised",
    ))
}

/// Appraise a bundle of node evidence against a statement-derived digest.
///
/// `policy_digest` is the SHA-256 of the exact decoded execution policy bytes
/// taken from the statement that already passed acceptance. It is a parameter
/// rather than something derived here so that the bytes compared are provably
/// the bytes that were accepted.
///
/// Every node in the bundle is assessed, and a node that fails does not stop
/// the others being looked at: an operator fixing a ledger needs to know which
/// nodes disagree, not merely that one did.
///
/// Returns findings, never a verdict.
#[cfg(feature = "mst-ledger")]
pub fn appraise(
    bundle: &EvidenceBundle,
    policy_digest: &[u8; 32],
    requirements: &Requirements,
) -> Result<Appraisal, AppraisalError> {
    if bundle.nodes.is_empty() {
        return Err(AppraisalError::EmptyBundle);
    }

    let mut appraisal = Appraisal::unevaluated("not assessed");

    // Parsed once, before any node is looked at. A bundle with no service
    // certificate cannot establish the binding for any node, and saying so
    // once is clearer than repeating the same sentence per node. It is not an
    // error: a bundle recorded before this check existed is incomplete, not
    // malformed, and the remaining checks are still worth reporting.
    let service_der = parse_service_certificate(&bundle.service_certificate_pem);

    for node in &bundle.nodes {
        match snp::verify_node(node, policy_digest, requirements) {
            Ok(v) => {
                // Compared here as well as inside the library, because when
                // the library rejected the node this crate still has to say
                // *which* requirement it failed — and because reporting a
                // match on the strength of an absent error would be claiming
                // a comparison nobody made. This check is the whole point of
                // the adapter, so it is made directly.
                let agrees = &v.host_data == policy_digest;
                // Assessed even when the node failed a requirement. The
                // report's signature and AMD chain verified, so `REPORT_DATA`
                // is authentic regardless, and whether a rejected node belongs
                // to this ledger is exactly what an operator needs to know: a
                // stranger's machine and your own ledger running the wrong
                // policy call for opposite responses.
                let (binding_state, binding_detail) =
                    assess_binding(node, service_der.as_deref(), &v.report_data);
                // One `detail` serves every check's aggregate message, so it
                // has to describe whichever finding a reader would be chasing.
                // Ordered by how far it sets them back: a node that is not
                // this ledger's makes its policy agreement beside the point,
                // so that is said first even when `HOST_DATA` matched.
                let detail = if binding_state == CheckState::Fail {
                    binding_detail
                } else if !agrees {
                    // The observed digest belongs here, not only in the
                    // aggregate: an operator chasing a mismatch needs the
                    // value the node is actually enforcing.
                    format!(
                        "authenticated HOST_DATA {} does not equal the statement's \
                         policy digest {}",
                        hex(&v.host_data),
                        hex(policy_digest)
                    )
                } else if let Some(why) = &v.requirement_failure {
                    why.clone()
                } else if binding_state == CheckState::CannotEvaluate {
                    binding_detail
                } else {
                    format!("measurement {}", hex(&v.measurement))
                };
                appraisal.nodes.push(NodeOutcome {
                    node_id: node.node_id.clone(),
                    identity_binding: binding_state,
                    // The report authenticated — that much is settled by
                    // reaching this arm. What remains is whether the node met
                    // the *platform* requirements, and the library stops at
                    // the first unmet requirement without saying which. When
                    // `HOST_DATA` already disagrees, that mismatch alone
                    // explains the rejection, so the platform requirements may
                    // never have been reached and reporting them as failed
                    // would accuse the node of something unobserved. The
                    // policy mismatch is reported by its own check, which
                    // fails, so nothing is let through by saying so honestly.
                    attestation: match (&v.requirement_failure, agrees) {
                        (None, _) => CheckState::Pass,
                        (Some(_), true) => CheckState::Fail,
                        (Some(_), false) => CheckState::CannotEvaluate,
                    },
                    host_data_match: if agrees {
                        CheckState::Pass
                    } else {
                        CheckState::Fail
                    },
                    detail,
                });
            }
            Err(why) => {
                appraisal.nodes.push(NodeOutcome {
                    node_id: node.node_id.clone(),
                    // Nothing in this report is authenticated, so its
                    // `REPORT_DATA` cannot be compared to anything. A node
                    // whose report did not verify has not been shown to belong
                    // to this ledger or to any other.
                    identity_binding: CheckState::CannotEvaluate,
                    attestation: CheckState::Fail,
                    // Not `Fail`: the comparison never happened. A node whose
                    // report did not authenticate has not been shown to
                    // disagree about the policy, and saying it did would be a
                    // finding this crate did not make.
                    host_data_match: CheckState::CannotEvaluate,
                    detail: why.clone(),
                });
            }
        }
    }

    let summary = aggregate(&appraisal.nodes);
    appraisal.ledger_identity_binding = summary.ledger_identity_binding;
    appraisal.snp_uvm_validation = summary.snp_uvm_validation;
    appraisal.cce_policy_host_data = summary.cce_policy_host_data;
    appraisal.node_coverage = summary.node_coverage;

    Ok(appraisal)
}

/// Read the bundle's service identity certificate, or say why it cannot be.
///
/// Returns `Err` with a sentence fit to show an operator rather than an
/// [`AppraisalError`]: a bundle recorded without a service certificate is
/// incomplete, not malformed, and the attestation findings it *does* contain
/// are still worth reporting alongside an honest "identity was not assessed".
#[cfg(feature = "mst-ledger")]
fn parse_service_certificate(pem: &[u8]) -> Result<Vec<u8>, String> {
    if pem.is_empty() {
        return Err(
            "the bundle contains no service identity certificate, so no node can \
                    be tied to a ledger"
                .to_string(),
        );
    }
    let text = core::str::from_utf8(pem)
        .map_err(|_| "the service identity certificate is not valid UTF-8 PEM".to_string())?;
    let mut certs = scitt_receipt::chain::parse_pem_certificates(text)
        .map_err(|e| format!("the service identity certificate could not be parsed: {e}"))?;
    if certs.len() != 1 {
        // Which certificate is the trust anchor decides what every node
        // binding means, so an ambiguous file is refused rather than guessed.
        return Err(format!(
            "expected exactly one service identity certificate, found {}",
            certs.len()
        ));
    }
    Ok(certs.remove(0))
}

/// Assess one node's binding to the ledger, given the parsed service anchor.
///
/// Never returns `Pass` on absent evidence. A missing certificate is
/// [`CheckState::CannotEvaluate`] — the question was not asked — whereas a
/// certificate that is present and does not bind is [`CheckState::Fail`],
/// because it was asked and answered no.
#[cfg(feature = "mst-ledger")]
fn assess_binding(
    node: &NodeEvidence,
    service_der: Result<&[u8], &String>,
    report_data: &[u8; 64],
) -> (CheckState, String) {
    let service_der = match service_der {
        Ok(der) => der,
        Err(why) => return (CheckState::CannotEvaluate, why.clone()),
    };
    if node.certificate_pem.is_empty() {
        return (
            CheckState::CannotEvaluate,
            "this node's certificate was not recorded, so the key its report attests \
             cannot be tied to the ledger. CCF nodes rotate, so a certificate omitted at \
             collection time cannot be fetched afterwards."
                .to_string(),
        );
    }
    match identity::verify_binding(&node.certificate_pem, service_der, report_data) {
        Ok(details) => (
            CheckState::Pass,
            format!(
                "attested key certified by the service identity; node certificate valid \
                 {} to {} (validity not enforced)",
                details.not_before, details.not_after
            ),
        ),
        Err(why) => (CheckState::Fail, why),
    }
}

/// The three fleet-wide checks derived from per-node findings.
#[cfg(any(feature = "mst-ledger", test))]
struct Aggregate {
    ledger_identity_binding: Check,
    snp_uvm_validation: Check,
    cce_policy_host_data: Check,
    node_coverage: Check,
}

/// Roll per-node findings up into the checks a caller gates on.
///
/// Separated from [`appraise`] and kept pure so the rules below can be tested
/// against every combination of node findings, including ones real evidence
/// cannot conveniently produce. It is compiled in non-adapter builds too, so
/// the default test run still covers them.
///
/// Three rules here are deliberate and easy to get wrong:
///
/// 1. **Zero nodes establishes nothing.** Every counting rule below is of the
///    form "all N agreed", which is vacuously true at N = 0. An empty slice
///    would therefore report a clean pass having looked at nothing, so it is
///    special-cased first. [`appraise`] already refuses an empty bundle; this
///    is the same refusal at the layer that does the counting.
/// 2. **A node that could not be assessed has not disagreed.** Nodes whose
///    reports did not authenticate produce no `HOST_DATA` finding, so a run
///    where the assessable nodes all agreed reports `CannotEvaluate`, not
///    `Fail`. Both block a pass; only one of them sends an operator hunting a
///    policy mismatch that was never observed.
/// 3. **Incomplete coverage still blocks.** Rule 2 does not weaken the gate,
///    because `node_coverage` fails whenever any node produced no usable
///    evidence. The distinction is in what the report claims, not in what it
///    permits.
#[cfg(any(feature = "mst-ledger", test))]
fn aggregate(outcomes: &[NodeOutcome]) -> Aggregate {
    let total = outcomes.len();

    if total == 0 {
        let reason = "no node evidence was assessed, so nothing was established";
        return Aggregate {
            ledger_identity_binding: Check::cannot_evaluate(reason),
            snp_uvm_validation: Check::cannot_evaluate(reason),
            cce_policy_host_data: Check::cannot_evaluate(reason),
            node_coverage: Check::cannot_evaluate(reason),
        };
    }

    let verified = outcomes.iter().filter(|n| n.attestation.is_pass()).count();
    let agreed = outcomes
        .iter()
        .filter(|n| n.host_data_match.is_pass())
        .count();
    let disagreed = outcomes
        .iter()
        .filter(|n| n.host_data_match == CheckState::Fail)
        .count();

    let detail_of = |f: &dyn Fn(&NodeOutcome) -> bool| {
        outcomes
            .iter()
            .filter(|n| f(n))
            .map(|n| format!("node {}: {}", n.node_id, n.detail))
            .collect::<Vec<_>>()
            .join("; ")
    };

    // Three-way, like the identity rule and for the same reason: a node that
    // failed a platform requirement is a different finding from one whose
    // platform requirements were never reached because its policy digest
    // already disagreed. Reporting the second as a failure would accuse the
    // node of something nobody observed, and would send an operator looking
    // for a TCB problem when the ledger had simply been upgraded.
    let platform_failed = outcomes
        .iter()
        .filter(|n| n.attestation == CheckState::Fail)
        .count();

    let snp_uvm_validation = if platform_failed > 0 {
        Check::new(
            CheckState::Fail,
            format!(
                "{platform_failed} of {total} node(s) did not authenticate or did not meet the \
                 platform requirements: {}",
                detail_of(&|n: &NodeOutcome| n.attestation == CheckState::Fail)
            ),
        )
    } else if verified == total {
        Check::new(
            CheckState::Pass,
            format!("{total} node(s) authenticated against AMD and UVM collateral"),
        )
    } else {
        Check::cannot_evaluate(format!(
            "{verified} of {total} node(s) met the platform requirements; for the rest the \
             policy digest already disagreed, so the platform requirements were not reached"
        ))
    };

    let cce_policy_host_data = if disagreed > 0 {
        Check::new(
            CheckState::Fail,
            format!(
                "{disagreed} of {total} node(s) enforce a different policy: {}",
                detail_of(&|n: &NodeOutcome| n.host_data_match == CheckState::Fail)
            ),
        )
    } else if agreed == 0 {
        // `agreed`, not `verified`: a node may produce an authenticated report
        // and still be rejected on a platform requirement, and its `HOST_DATA`
        // is comparable either way. Keying this on acceptance would report
        // "nothing to compare" about digests that were in fact compared.
        Check::cannot_evaluate(
            "no node's report authenticated, so no authenticated HOST_DATA exists to compare",
        )
    } else if agreed == total {
        Check::new(
            CheckState::Pass,
            format!("{agreed}/{total} node(s) enforce the statement's policy digest"),
        )
    } else {
        Check::cannot_evaluate(format!(
            "{agreed} of {total} node(s) enforce the statement's policy digest and none \
             disagree, but {} node(s) could not be assessed",
            total - agreed
        ))
    };

    // Same shape as the rules above, and for the same reasons: a node that
    // disagrees is a failure, a node that could not be assessed leaves the
    // question open, and "all of them agreed" is only meaningful because the
    // zero-node case was refused first. A mixture is `CannotEvaluate` rather
    // than a partial pass — if one node in a fleet cannot be shown to belong
    // to this ledger, the operator has not learned that this ledger enforces
    // the policy, only that some machine somewhere does.
    let bound = outcomes
        .iter()
        .filter(|n| n.identity_binding.is_pass())
        .count();
    let unbound = outcomes
        .iter()
        .filter(|n| n.identity_binding == CheckState::Fail)
        .count();

    let ledger_identity_binding = if unbound > 0 {
        Check::new(
            CheckState::Fail,
            format!(
                "{unbound} of {total} node(s) could not be tied to the ledger's service \
                 identity: {}",
                detail_of(&|n: &NodeOutcome| n.identity_binding == CheckState::Fail)
            ),
        )
    } else if bound == total {
        Check::new(
            CheckState::Pass,
            format!(
                "{bound}/{total} node(s) attest a key certified by the ledger's service \
                 identity"
            ),
        )
    } else {
        Check::cannot_evaluate(format!(
            "{bound} of {total} node(s) were tied to the ledger's service identity and none \
             contradicted it, but {} could not be assessed",
            total - bound
        ))
    };

    // "Usable evidence" means an authenticated report was obtained, which is
    // not the same as the node being acceptable. A node whose report verified
    // and which is enforcing the wrong policy has produced perfectly usable
    // evidence — of a problem. Counting it as a coverage gap would report the
    // snapshot as incomplete when it was in fact complete and damning.
    let assessable = outcomes
        .iter()
        .filter(|n| n.host_data_match != CheckState::CannotEvaluate)
        .count();

    let node_coverage = if assessable == total {
        Check::new(
            CheckState::Pass,
            format!("every node in the assessed snapshot ({total}) produced usable evidence"),
        )
    } else {
        Check::new(
            CheckState::Fail,
            format!(
                "{} of {total} node(s) produced no usable evidence",
                total - assessable
            ),
        )
    };

    Aggregate {
        ledger_identity_binding,
        snp_uvm_validation,
        cce_policy_host_data,
        node_coverage,
    }
}

/// Lowercase hex, for reporting a digest an operator will compare by eye.
#[cfg(feature = "mst-ledger")]
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unevaluated_appraisal_passes_nothing() {
        let a = Appraisal::unevaluated("nothing ran");
        for (name, _, check) in a.checks() {
            assert_eq!(
                check.state,
                CheckState::CannotEvaluate,
                "{name} must start unevaluated"
            );
            assert!(!check.detail.is_empty(), "{name} must carry a reason");
        }
        assert!(!a.scoped_pass());
    }

    /// `blocking` and `scoped_pass` must always agree.
    ///
    /// They are two readings of one rule, and the reason for the second is to
    /// explain the first. If they ever diverge, a run reports no pass while
    /// naming nothing that stopped it, or names a blocker on a run that
    /// passed — both of which send an operator somewhere useless.
    ///
    /// Exhaustive over all 16 assignments of the four decisive checks, with
    /// the two excluded checks held at `CannotEvaluate`, which is what they
    /// are in every real run.
    #[test]
    fn blocking_is_empty_exactly_when_the_appraisal_scoped_passes() {
        for bits in 0u8..16 {
            let st = |i: u8| {
                if bits & (1 << i) != 0 {
                    CheckState::Pass
                } else {
                    CheckState::Fail
                }
            };
            let mut a = Appraisal::unevaluated("start");
            a.ledger_identity_binding = Check::new(st(0), "d");
            a.snp_uvm_validation = Check::new(st(1), "d");
            a.cce_policy_host_data = Check::new(st(2), "d");
            a.node_coverage = Check::new(st(3), "d");

            let blocking = a.blocking();
            assert_eq!(
                blocking.is_empty(),
                a.scoped_pass(),
                "bits {bits:04b}: scoped_pass={} but blocking={blocking:?}",
                a.scoped_pass()
            );
            assert_eq!(blocking.len(), (bits.count_zeros() as usize) - 4);
            // The two checks that can never pass must never be named: they are
            // excluded from the rule, and naming them would send an operator
            // to investigate something that was never going to change.
            for (name, _) in &blocking {
                assert_ne!(*name, "freshness");
                assert_ne!(*name, "connection-binding");
            }
        }
    }

    /// An empty bundle must be refused, not appraised.
    ///
    /// This is the failure the whole design exists to prevent: zero nodes
    /// assessed means zero mismatches found, which would otherwise read as
    /// unanimous agreement.
    #[test]
    fn an_empty_bundle_is_an_error_rather_than_a_unanimous_agreement() {
        let bundle = EvidenceBundle {
            service_certificate_pem: Vec::new(),
            nodes: Vec::new(),
        };
        let result = appraise(&bundle, &[0u8; 32], &requirements());

        #[cfg(feature = "mst-ledger")]
        assert_eq!(result.unwrap_err(), AppraisalError::EmptyBundle);

        // Without the adapter there is nothing to appraise at all, so the
        // answer is every check unevaluated — and, critically, not a pass.
        #[cfg(not(feature = "mst-ledger"))]
        {
            let a = result.expect("appraisal");
            assert!(!a.scoped_pass());
            assert_eq!(a.cce_policy_host_data.state, CheckState::CannotEvaluate);
        }
    }

    /// A build without the adapter must say so, and must not pass.
    #[cfg(not(feature = "mst-ledger"))]
    #[test]
    fn a_build_without_the_adapter_cannot_report_a_pass() {
        let bundle = EvidenceBundle {
            service_certificate_pem: Vec::new(),
            nodes: vec![NodeEvidence {
                node_id: "n".into(),
                certificate_pem: Vec::new(),
                snp_report: Vec::new(),
                amd_endorsements: Vec::new(),
                uvm_endorsement: Vec::new(),
            }],
        };
        let a = appraise(&bundle, &[0u8; 32], &requirements()).expect("appraisal");
        assert!(!a.scoped_pass());
        for (_, _, check) in a.checks() {
            assert_eq!(check.state, CheckState::CannotEvaluate);
        }
        assert!(a.cce_policy_host_data.detail.contains("mst-ledger"));
    }

    /// Evidence that cannot authenticate must not produce a HOST_DATA finding.
    ///
    /// A node whose report did not verify has not been shown to disagree about
    /// the policy. Reporting `Fail` there would be a finding this crate did
    /// not make, and would send an operator looking for a policy mismatch that
    /// may not exist.
    #[cfg(feature = "mst-ledger")]
    #[test]
    fn unusable_evidence_fails_attestation_without_claiming_a_policy_mismatch() {
        let bundle = EvidenceBundle {
            service_certificate_pem: Vec::new(),
            nodes: vec![NodeEvidence {
                node_id: "node-1".into(),
                certificate_pem: Vec::new(),
                snp_report: vec![0u8; 16],
                amd_endorsements: vec![vec![1], vec![2], vec![3]],
                uvm_endorsement: Vec::new(),
            }],
        };
        let a = appraise(&bundle, &[0u8; 32], &requirements()).expect("appraisal");

        assert!(!a.scoped_pass());
        assert_eq!(a.snp_uvm_validation.state, CheckState::Fail);
        assert_eq!(a.node_coverage.state, CheckState::Fail);
        assert_eq!(
            a.cce_policy_host_data.state,
            CheckState::CannotEvaluate,
            "no authenticated HOST_DATA existed, so there was nothing to compare"
        );
        assert_eq!(a.nodes.len(), 1);
        assert_eq!(a.nodes[0].attestation, CheckState::Fail);
        assert_eq!(a.nodes[0].host_data_match, CheckState::CannotEvaluate);
    }

    /// Identity binding is not implemented, and must not be inferred.
    ///
    /// A valid SNP report proves a genuine confidential VM; it does not prove
    /// that VM belongs to the ledger being assessed.
    #[cfg(feature = "mst-ledger")]
    #[test]
    fn identity_binding_is_never_inferred_from_a_valid_attestation() {
        let bundle = EvidenceBundle {
            service_certificate_pem: Vec::new(),
            nodes: vec![NodeEvidence {
                node_id: "node-1".into(),
                certificate_pem: Vec::new(),
                snp_report: vec![0u8; 16],
                amd_endorsements: vec![vec![1], vec![2], vec![3]],
                uvm_endorsement: Vec::new(),
            }],
        };
        let a = appraise(&bundle, &[0u8; 32], &requirements()).expect("appraisal");
        assert_eq!(a.ledger_identity_binding.state, CheckState::CannotEvaluate);
        assert!(a.nodes[0].identity_binding == CheckState::CannotEvaluate);
    }

    /// These two are not pending work, and their reasons must say why rather
    /// than reading like something a later release will fix.
    #[test]
    fn freshness_and_connection_binding_carry_permanent_reasons() {
        let a = Appraisal::unevaluated("nothing ran");
        assert!(a.freshness.detail.contains("challenge-response"));
        assert!(a.connection_binding.detail.contains("load-balances"));
        // And they are not merely echoing the caller's reason.
        assert!(!a.freshness.detail.contains("nothing ran"));
        assert!(!a.connection_binding.detail.contains("nothing ran"));
    }

    /// `CannotEvaluate` must never be counted as satisfied.
    #[test]
    fn only_a_clean_pass_counts_as_a_pass() {
        assert!(CheckState::Pass.is_pass());
        assert!(!CheckState::Fail.is_pass());
        assert!(!CheckState::NotChecked.is_pass());
        assert!(!CheckState::CannotEvaluate.is_pass());
    }

    /// A scoped pass requires all four assessable checks. Any one of them
    /// short of `Pass` must sink it.
    #[test]
    fn a_scoped_pass_needs_every_assessable_check() {
        let pass = |a: &mut Appraisal| {
            a.ledger_identity_binding = Check::new(CheckState::Pass, "ok");
            a.snp_uvm_validation = Check::new(CheckState::Pass, "ok");
            a.cce_policy_host_data = Check::new(CheckState::Pass, "ok");
            a.node_coverage = Check::new(CheckState::Pass, "ok");
        };

        let mut all = Appraisal::unevaluated("x");
        pass(&mut all);
        assert!(all.scoped_pass(), "freshness must not block a scoped pass");

        for i in 0..4 {
            let mut a = Appraisal::unevaluated("x");
            pass(&mut a);
            match i {
                0 => a.ledger_identity_binding = Check::new(CheckState::Fail, "no"),
                1 => a.snp_uvm_validation = Check::new(CheckState::CannotEvaluate, "no"),
                2 => a.cce_policy_host_data = Check::new(CheckState::Fail, "no"),
                _ => a.node_coverage = Check::new(CheckState::NotChecked, "no"),
            }
            assert!(!a.scoped_pass(), "check {i} short of pass must sink it");
        }
    }

    fn requirements() -> Requirements {
        Requirements {
            uvm_did_x509: "did:x509:0:sha256:abc".into(),
            uvm_feed: "ContainerPlat-AMD-UVM".into(),
            uvm_eku: "1.3.6.1.4.1.311.76.59.1.2".into(),
            min_uvm_svn: 104,
            min_tcb: vec![TcbFloor {
                generation: "genoa".into(),
                reported_tcb: 0x5417_0000_0000_000a,
            }],
        }
    }

    // ---- aggregation rules -------------------------------------------------
    //
    // These exercise the fleet-wide roll-up directly. Doing it through real
    // evidence would need a bundle per case, each containing genuinely signed
    // SNP reports that cannot be synthesised, and several of the cases below
    // (a partially assessable ledger, a single dissenting node) are precisely
    // the ones a healthy ledger will not produce on demand.

    fn outcome(node_id: &str, attestation: CheckState, host: CheckState) -> NodeOutcome {
        NodeOutcome {
            node_id: node_id.into(),
            identity_binding: CheckState::CannotEvaluate,
            attestation,
            host_data_match: host,
            detail: format!("{node_id} detail"),
        }
    }

    fn agreeing(node_id: &str) -> NodeOutcome {
        outcome(node_id, CheckState::Pass, CheckState::Pass)
    }

    fn dissenting(node_id: &str) -> NodeOutcome {
        outcome(node_id, CheckState::Pass, CheckState::Fail)
    }

    fn unusable(node_id: &str) -> NodeOutcome {
        outcome(node_id, CheckState::Fail, CheckState::CannotEvaluate)
    }

    /// Nothing assessed must establish nothing.
    ///
    /// Every rule in the roll-up counts agreement, and "all of them agreed" is
    /// vacuously true of an empty set. Without the explicit guard this returns
    /// three passes having examined no evidence at all.
    #[test]
    fn aggregating_zero_nodes_establishes_nothing() {
        let a = aggregate(&[]);
        for check in [
            &a.ledger_identity_binding,
            &a.snp_uvm_validation,
            &a.cce_policy_host_data,
            &a.node_coverage,
        ] {
            assert_eq!(check.state, CheckState::CannotEvaluate);
            assert!(check.detail.contains("no node evidence"));
        }
    }

    fn bound(node_id: &str) -> NodeOutcome {
        NodeOutcome {
            identity_binding: CheckState::Pass,
            ..agreeing(node_id)
        }
    }

    #[test]
    fn identity_passes_only_when_every_node_is_bound() {
        let a = aggregate(&[bound("a"), bound("b")]);
        assert_eq!(a.ledger_identity_binding.state, CheckState::Pass);
        assert!(a.ledger_identity_binding.detail.contains("2/2"));
    }

    /// One node that cannot be tied to this ledger is a failure, not a
    /// partial pass. An operator has not learned that *their* ledger enforces
    /// the policy while a machine of unknown provenance sits in the fleet.
    #[test]
    fn one_unbound_node_fails_identity_and_is_named() {
        let mut stranger = bound("b");
        stranger.identity_binding = CheckState::Fail;
        let a = aggregate(&[bound("a"), stranger]);
        assert_eq!(a.ledger_identity_binding.state, CheckState::Fail);
        assert!(a.ledger_identity_binding.detail.contains("node b"));
    }

    /// A bundle that recorded no certificates leaves the question unasked.
    /// It must never read as a pass — that is the whole failure this check
    /// exists to prevent.
    #[test]
    fn identity_is_cannot_evaluate_when_nothing_was_assessed() {
        let a = aggregate(&[agreeing("a"), agreeing("b")]);
        assert_eq!(a.ledger_identity_binding.state, CheckState::CannotEvaluate);
    }

    /// A node whose report verified but whose policy digest disagrees has not
    /// been shown to fail a *platform* requirement: the library stops at the
    /// first unmet requirement, so the platform checks may never have run.
    /// Reporting a failure there would send an operator hunting a TCB problem
    /// when the ledger had simply been upgraded.
    #[test]
    fn a_policy_mismatch_is_not_reported_as_a_platform_failure() {
        let node = outcome("a", CheckState::CannotEvaluate, CheckState::Fail);
        let a = aggregate(&[node]);
        assert_eq!(a.snp_uvm_validation.state, CheckState::CannotEvaluate);
        assert_eq!(a.cce_policy_host_data.state, CheckState::Fail);
    }

    /// Coverage asks whether evidence was obtained, not whether it was liked.
    /// A node enforcing the wrong policy produced entirely usable evidence —
    /// of a problem — and calling the snapshot incomplete would hide that.
    #[test]
    fn an_unaccepted_but_authenticated_node_still_counts_as_covered() {
        let node = outcome("a", CheckState::CannotEvaluate, CheckState::Fail);
        assert_eq!(aggregate(&[node]).node_coverage.state, CheckState::Pass);
        assert_eq!(
            aggregate(&[unusable("a")]).node_coverage.state,
            CheckState::Fail
        );
    }

    #[test]
    fn a_fully_agreeing_fleet_passes_every_aggregate_check() {
        let a = aggregate(&[agreeing("a"), agreeing("b"), agreeing("c")]);
        assert_eq!(a.snp_uvm_validation.state, CheckState::Pass);
        assert_eq!(a.cce_policy_host_data.state, CheckState::Pass);
        assert_eq!(a.node_coverage.state, CheckState::Pass);
        assert!(a.cce_policy_host_data.detail.contains("3/3"));
    }

    /// One authenticated node enforcing a different policy is a real finding,
    /// and the node responsible has to be named — "2/3 agree" leaves an
    /// operator to work out which box to go and look at.
    #[test]
    fn a_single_dissenting_node_fails_the_comparison_and_is_named() {
        let a = aggregate(&[agreeing("a"), dissenting("b"), agreeing("c")]);
        assert_eq!(a.cce_policy_host_data.state, CheckState::Fail);
        assert!(a.cce_policy_host_data.detail.contains("node b"));
        assert!(
            !a.cce_policy_host_data.detail.contains("node a"),
            "only the dissenting node should be reported as dissenting"
        );
        assert_eq!(
            a.snp_uvm_validation.state,
            CheckState::Pass,
            "a node that disagreed about policy still authenticated"
        );
        assert_eq!(a.node_coverage.state, CheckState::Pass);
    }

    /// The honesty rule: unassessable nodes are not dissenters.
    ///
    /// Every node that could be assessed agreed, so no disagreement was
    /// observed and the comparison must not claim one. It still cannot pass —
    /// the nodes that did not report might enforce anything — so the state is
    /// `CannotEvaluate`, and coverage carries the failure.
    #[test]
    fn nodes_that_could_not_be_assessed_are_not_reported_as_disagreeing() {
        let a = aggregate(&[agreeing("a"), unusable("b"), agreeing("c")]);
        assert_eq!(
            a.cce_policy_host_data.state,
            CheckState::CannotEvaluate,
            "no node was observed enforcing a different policy"
        );
        assert!(a.cce_policy_host_data.detail.contains("none"));
        assert_eq!(a.node_coverage.state, CheckState::Fail);
        assert!(a.node_coverage.detail.contains("1 of 3"));
        assert_eq!(a.snp_uvm_validation.state, CheckState::Fail);
        assert!(a.snp_uvm_validation.detail.contains("node b"));
    }

    #[test]
    fn a_fleet_that_wholly_failed_to_authenticate_compares_nothing() {
        let a = aggregate(&[unusable("a"), unusable("b")]);
        assert_eq!(a.cce_policy_host_data.state, CheckState::CannotEvaluate);
        assert!(a.cce_policy_host_data.detail.contains("no node's report"));
        assert_eq!(a.node_coverage.state, CheckState::Fail);
    }

    /// An observed disagreement outranks incomplete coverage.
    ///
    /// Both block, so the gate is unaffected; the difference is that a node
    /// demonstrably enforcing the wrong policy is the more urgent thing to put
    /// in front of an operator, and must not be masked by a nearby node that
    /// merely failed to respond.
    #[test]
    fn an_observed_disagreement_outranks_unassessable_nodes() {
        let a = aggregate(&[dissenting("a"), unusable("b")]);
        assert_eq!(a.cce_policy_host_data.state, CheckState::Fail);
        assert!(a.cce_policy_host_data.detail.contains("node a"));
    }

    /// Exhaustive: across every arrangement of three nodes, the aggregate
    /// checks all pass if and only if every node authenticated *and* agreed.
    ///
    /// Written as an enumeration rather than a handful of examples because
    /// this is the property the deployment gate rests on, and a rule added
    /// later that admits some other combination would be a silent weakening.
    #[test]
    fn every_aggregate_check_passes_only_when_every_node_authenticated_and_agreed() {
        let kinds = [agreeing("n"), dissenting("n"), unusable("n")];
        for i in 0..3usize {
            for j in 0..3usize {
                for k in 0..3usize {
                    let nodes = [kinds[i].clone(), kinds[j].clone(), kinds[k].clone()];
                    let a = aggregate(&nodes);
                    let all_pass = a.snp_uvm_validation.state.is_pass()
                        && a.cce_policy_host_data.state.is_pass()
                        && a.node_coverage.state.is_pass();
                    let every_node_agreed = [i, j, k].iter().all(|&x| x == 0);
                    assert_eq!(
                        all_pass, every_node_agreed,
                        "combination {i}{j}{k} disagreed with the gate rule"
                    );
                }
            }
        }
    }

    /// No aggregate check may ever be silently absent: each must carry a
    /// reason an operator can act on, in every combination.
    #[test]
    fn every_aggregate_outcome_carries_a_reason() {
        let kinds = [agreeing("n"), dissenting("n"), unusable("n")];
        for a in &kinds {
            for b in &kinds {
                let agg = aggregate(&[a.clone(), b.clone()]);
                for check in [
                    &agg.snp_uvm_validation,
                    &agg.cce_policy_host_data,
                    &agg.node_coverage,
                ] {
                    assert!(!check.detail.is_empty());
                    assert_ne!(check.state, CheckState::NotChecked);
                }
            }
        }
    }
}
