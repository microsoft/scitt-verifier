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
    /// Observed `reported_tcb` was *not* uniform across a single ledger.
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
    let mut verified = 0usize;
    let mut matched = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for node in &bundle.nodes {
        match snp::verify_node(node, policy_digest, requirements) {
            Ok(v) => {
                verified += 1;
                // The library already refused a mismatch, so reaching here
                // means these are equal. Compared again anyway, because the
                // alternative is reporting a match on the strength of an
                // absent error, and this check is the entire point of the
                // adapter.
                let agrees = &v.host_data == policy_digest;
                if agrees {
                    matched += 1;
                } else {
                    failures.push(format!(
                        "node {}: HOST_DATA {} does not equal the statement's policy digest {}",
                        node.node_id,
                        hex(&v.host_data),
                        hex(policy_digest)
                    ));
                }
                appraisal.nodes.push(NodeOutcome {
                    node_id: node.node_id.clone(),
                    // Not yet established: binding REPORT_DATA to the node
                    // certificate, and that certificate to the service
                    // identity, is separate work. Reported as unevaluated
                    // rather than inferred from a successful attestation.
                    identity_binding: CheckState::CannotEvaluate,
                    attestation: CheckState::Pass,
                    host_data_match: if agrees {
                        CheckState::Pass
                    } else {
                        CheckState::Fail
                    },
                    detail: if agrees {
                        format!("measurement {}", hex(&v.measurement))
                    } else {
                        "authenticated HOST_DATA does not match the statement".to_string()
                    },
                });
            }
            Err(why) => {
                failures.push(format!("node {}: {why}", node.node_id));
                appraisal.nodes.push(NodeOutcome {
                    node_id: node.node_id.clone(),
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

    let total = bundle.nodes.len();

    appraisal.snp_uvm_validation = if verified == total {
        Check::new(
            CheckState::Pass,
            format!("{total} node(s) authenticated against AMD and UVM collateral"),
        )
    } else {
        Check::new(
            CheckState::Fail,
            format!(
                "{verified} of {total} node(s) authenticated: {}",
                failures.join("; ")
            ),
        )
    };

    appraisal.cce_policy_host_data = if verified == 0 {
        Check::cannot_evaluate(
            "no node's report authenticated, so no authenticated HOST_DATA exists to compare",
        )
    } else if matched == total {
        Check::new(
            CheckState::Pass,
            format!("{matched}/{total} node(s) enforce the statement's policy digest"),
        )
    } else {
        Check::new(
            CheckState::Fail,
            format!("{matched}/{total} node(s) agree with the statement's policy digest"),
        )
    };

    appraisal.node_coverage = if verified == total {
        Check::new(
            CheckState::Pass,
            format!("every node in the assessed snapshot ({total}) produced usable evidence"),
        )
    } else {
        Check::new(
            CheckState::Fail,
            format!(
                "{} of {total} node(s) produced no usable evidence",
                total - verified
            ),
        )
    };

    // Deliberately left as it began. Binding each report's attested key to the
    // service identity is not implemented, and an appraisal that inferred it
    // from a valid attestation would accept a genuine SNP node that belongs to
    // some other service entirely.
    appraisal.ledger_identity_binding = Check::cannot_evaluate(
        "binding a report's attested key to the ledger's service identity is not \
         implemented in this build",
    );

    Ok(appraisal)
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
}
