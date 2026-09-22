//! Running a resource adapter and turning its findings into checks.
//!
//! The orchestration seam. The adapter reports what it found and never returns
//! a verdict; this module converts those findings into the same `CheckState`
//! vocabulary the core checks use, and hands them to the code that decides.
//! Keeping the conversion here rather than in the adapter is what stops an
//! adapter from deciding a run's success — it has no way to express one.
//!
//! Two things happen here that deliberately do not happen in the adapter.
//!
//! The **reference digest is derived here**, from the same in-memory statement
//! that passed acceptance, through the same extraction path `inspect --decode`
//! uses. Never a re-read of the file, and never an `inspect` result: the bytes
//! that get compared have to be provably the bytes that were verified, and a
//! second read of a path is a second chance for them to differ.
//!
//! The **policy's acceptance requirements are translated here**, so the
//! adapter receives a typed requirement set rather than a policy document. It
//! has no opinion about where its requirements came from, and cannot acquire
//! one by reading the file.

#[cfg(feature = "adapter-mst-ledger")]
use scitt_policy::ledger::Encoding;
use scitt_policy::ledger::{BindLedgerPolicy, LedgerTarget, TrustInputs};
#[cfg(feature = "adapter-mst-ledger")]
use scitt_receipt::base64::Alphabet;
use scitt_receipt::Sign1;

use crate::cli::Adapter;
use crate::outcome::{AdapterCheck, CheckState};

/// What an adapter run established, and what it could not.
pub struct ResourceAppraisal {
    pub checks: Vec<AdapterCheck>,
    /// Whether every check required for a scoped pass held.
    ///
    /// Not a verdict. The caller may narrow on the strength of it; nothing
    /// here can widen one.
    pub scoped_pass: bool,
    /// The scope the caller must state alongside any pass.
    pub scope: String,
    /// Which decisive checks did not pass, by human label.
    ///
    /// Empty exactly when `scoped_pass` is true. Carried rather than derived
    /// by the caller, because which checks are decisive is the adapter's rule:
    /// two of the checks it reports can never pass and deliberately do not
    /// block, and a caller that filtered on "did not pass" would send an
    /// operator to investigate them.
    pub blocking: Vec<String>,
    /// Diagnostics to surface, most consequential first.
    pub notes: Vec<String>,
}

impl ResourceAppraisal {
    /// An appraisal that did not happen, with the reason.
    ///
    /// Public because the reasons an appraisal cannot start — an unaccepted
    /// statement, a policy with no ledger section — are known to the caller,
    /// not to this module. Every check is still named and still reported as
    /// `CannotEvaluate`: a run that silently omitted them would be
    /// indistinguishable from one where they did not apply.
    pub fn not_attempted(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let checks = scitt_attest_names()
            .into_iter()
            .map(|(name, label)| AdapterCheck {
                name: name.to_string(),
                label: label.to_string(),
                state: CheckState::CannotEvaluate,
                detail: reason.clone(),
            })
            .collect();
        Self {
            checks,
            scoped_pass: false,
            scope: "no evidence was appraised".to_string(),
            // Every decisive check, because none of them were reached. The
            // first four names are the ones `scoped_pass` consults.
            blocking: scitt_attest_names()
                .into_iter()
                .take(4)
                .map(|(_, label)| label.to_string())
                .collect(),
            notes: vec![reason],
        }
    }
}

/// The check names an appraisal reports, whether or not one ran.
///
/// Taken from the adapter when it is compiled in, so the two cannot drift. A
/// build without the adapter still has to name the checks it did not perform:
/// a run that omitted them entirely would be indistinguishable from one where
/// they were never relevant.
#[cfg(feature = "adapter-mst-ledger")]
fn scitt_attest_names() -> Vec<(&'static str, &'static str)> {
    scitt_attest::CHECK_NAMES.to_vec()
}

#[cfg(not(feature = "adapter-mst-ledger"))]
fn scitt_attest_names() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ledger-identity-binding", "Ledger identity/key binding"),
        ("snp-uvm-validation", "SNP and UVM validation"),
        ("cce-policy-host-data", "CCE policy / HOST_DATA"),
        ("node-coverage", "Enumerated-node coverage"),
        ("freshness", "Freshness"),
        ("connection-binding", "Connection binding"),
    ]
}

/// Where an appraisal's evidence comes from.
///
/// The two differ in one way that matters to the reader: a saved bundle
/// supplies its own service certificate, so the subject of the appraisal also
/// supplies the anchor the appraisal checks against. A bundle that is
/// internally consistent therefore passes whether or not it came from the
/// ledger the policy names. Live acquisition takes the anchor from the public
/// identity service instead, so the ledger cannot vouch for itself.
#[derive(Debug, Clone, Copy)]
// A build without the adapter still has to accept the argument so that one
// call site serves both, but it never reads it. Naming that rather than
// deleting the fields keeps the two builds' signatures identical.
#[cfg_attr(not(feature = "adapter-mst-ledger"), allow(dead_code))]
pub enum EvidenceSource<'a> {
    /// A bundle recorded earlier, read from disk.
    Saved(&'a std::path::Path),
    /// Collected by this run from the ledger the policy names.
    Live {
        /// Where to write the collected evidence, if the run asked for a copy.
        save_to: Option<&'a std::path::Path>,
    },
}

/// Appraise ledger evidence against an accepted statement.
///
/// `statement` is the parsed statement that already passed acceptance.
#[cfg(not(feature = "adapter-mst-ledger"))]
pub fn appraise_evidence(
    _adapter: Adapter,
    _source: EvidenceSource<'_>,
    _statement: &Sign1,
    _bind: &BindLedgerPolicy,
    _trust: &TrustInputs,
    _ledger: &LedgerTarget,
) -> ResourceAppraisal {
    // Not an error and not a failure: the question was asked and this binary
    // cannot answer it. Reported as `CannotEvaluate` so it exits 3 rather than
    // 0, because a build that silently skipped the appraisal would let a gate
    // pass on the strength of a check that never ran.
    ResourceAppraisal::not_attempted(
        "this build was compiled without the mst-ledger adapter, so no ledger evidence can be \
         appraised. Rebuild with --features adapter-mst-ledger.",
    )
}

/// Appraise ledger evidence against an accepted statement.
#[cfg(feature = "adapter-mst-ledger")]
pub fn appraise_evidence(
    adapter: Adapter,
    source: EvidenceSource<'_>,
    statement: &Sign1,
    bind: &BindLedgerPolicy,
    trust: &TrustInputs,
    ledger: &LedgerTarget,
) -> ResourceAppraisal {
    let Adapter::MstLedger = adapter;

    let requirements = match requirements(bind, trust) {
        Ok(r) => r,
        Err(why) => return ResourceAppraisal::not_attempted(why),
    };

    // The reference digest, from the statement that was accepted.
    let alphabet = match bind.encoding {
        Encoding::Base64 => Alphabet::Standard,
        Encoding::Base64url => Alphabet::UrlSafe,
    };
    let policy_bytes =
        match scitt_policy::claim::encoded_claim_bytes(statement, &bind.path, alphabet) {
            Ok(b) => b,
            Err(e) => {
                return ResourceAppraisal::not_attempted(format!(
                    "the statement's execution policy could not be read: {}",
                    e.describe()
                ))
            }
        };
    if let Some(max) = bind.max_decoded_bytes {
        if policy_bytes.len() > max {
            return ResourceAppraisal::not_attempted(format!(
                "the statement's execution policy is {} bytes, above the {max} the policy \
                 allows; its digest is not reported, because a claim this far from what was \
                 expected is more likely a wrong path than a large policy",
                policy_bytes.len()
            ));
        }
    }
    let policy_digest = scitt_receipt::sha256(&policy_bytes);

    let mut notes = Vec::new();

    // An optional pin against a correctly signed statement for the wrong
    // build. Checked before the evidence, because if the statement is not the
    // one this gate intended then nothing the nodes report is relevant.
    if let Some(expected) = &bind.expect_policy_sha256 {
        let actual = hex(&policy_digest);
        if !actual.eq_ignore_ascii_case(expected) {
            let mut appraisal = ResourceAppraisal::not_attempted(format!(
                "the statement's execution policy digest is {actual}, but the policy pins \
                 {expected}. This statement is for a different build."
            ));
            // A mismatch here is a finding, not an inability: the comparison
            // ran and disagreed.
            for check in &mut appraisal.checks {
                if check.name == "cce-policy-host-data" {
                    check.state = CheckState::Fail;
                }
            }
            return appraisal;
        }
        notes.push(format!(
            "the statement's execution policy matches the pinned digest {expected}"
        ));
    }

    let loaded = match source {
        EvidenceSource::Saved(dir) => {
            crate::evidence::load(dir).map_err(|e| format!("the evidence bundle is unusable: {e}"))
        }
        EvidenceSource::Live { save_to } => {
            // One deadline for the whole acquisition, started here. Reaching
            // an unreachable ledger is an inability, never a finding: the
            // question was asked and nothing answered it, which is not the
            // same as a node that answered badly.
            let deadline = std::time::Instant::now() + scitt_acquire::limits::TOTAL_DEADLINE;
            crate::live::fetch(&ledger.host, deadline)
                .map_err(|e| format!("evidence could not be collected from {}: {e}", ledger.host))
                .and_then(|(bundle, metadata)| match save_to {
                    Some(dir) => crate::evidence::save(dir, &bundle, &metadata)
                        .map(|()| (bundle, metadata))
                        .map_err(|e| {
                            // Refused rather than appraised-and-not-saved. A
                            // run asked for a copy of what it judged; a
                            // verdict with no such copy is not the run that
                            // was requested.
                            format!("the collected evidence could not be saved: {e}")
                        }),
                    None => Ok((bundle, metadata)),
                })
        }
    };
    let (bundle, metadata) = match loaded {
        Ok(b) => b,
        Err(e) => return ResourceAppraisal::not_attempted(e),
    };

    // The policy names the ledger it is about. Until this check existed the
    // name was recorded and never enforced, so a bundle captured from one
    // service was appraised against a policy written for another and the
    // report named the wrong subject throughout. A statement's execution
    // policy is a claim about a particular deployment; comparing it to some
    // other service's nodes answers a question nobody asked.
    //
    // Scope of the guarantee: for a saved bundle, `snapshot.json`'s `ledger`
    // is collector-asserted and unsigned, so this catches the wrong bundle,
    // not a forged one. Only a live run closes that gap, by pinning the
    // connection to the certificate the public identity service publishes for
    // `ledger.host`. The comparison still runs on a live run, where it is
    // trivially satisfied, so that one rule governs both paths.
    let expected = normalise_host(&ledger.host);
    let found = normalise_host(&metadata.ledger);
    if expected != found {
        let mut appraisal = ResourceAppraisal::not_attempted(format!(
            "the policy is about {}, but this evidence was collected from {}. The \
             statement's execution policy describes one deployment; nothing can be \
             concluded by holding a different service's nodes to it.",
            ledger.host, metadata.ledger
        ));
        // A finding, not an inability: the comparison ran and disagreed. Named
        // against identity binding because that is the check that asks which
        // service the evidence belongs to.
        for check in &mut appraisal.checks {
            if check.name == "ledger-identity-binding" {
                check.state = CheckState::Fail;
            }
        }
        return appraisal;
    }

    // The one requirement that can notice a node left out of the bundle
    // altogether. Coverage is over the nodes the evidence names, so without
    // this a truncated bundle and a smaller ledger are the same thing.
    if let Some(expected) = bind.expect_node_count {
        if metadata.node_count != expected {
            return ResourceAppraisal::not_attempted(format!(
                "the evidence enumerates {} node(s), but the policy expects {expected}. \
                 Coverage is only ever over the nodes the evidence names, so a bundle with \
                 nodes missing cannot be told from a smaller ledger.",
                metadata.node_count
            ));
        }
    }

    let appraisal = match scitt_attest::appraise(&bundle, &policy_digest, &requirements) {
        Ok(a) => a,
        Err(e) => {
            return ResourceAppraisal::not_attempted(format!(
                "the evidence could not be appraised: {e}"
            ))
        }
    };

    let checks = appraisal
        .checks()
        .iter()
        .map(|(name, label, check)| AdapterCheck {
            name: (*name).to_string(),
            label: (*label).to_string(),
            state: map_state(check.state),
            detail: check.detail.clone(),
        })
        .collect();

    for node in &appraisal.nodes {
        if !node.attestation.is_pass() || !node.host_data_match.is_pass() {
            notes.push(format!(
                "node {}: attestation {}, policy {} — {}",
                node.node_id,
                map_state(node.attestation).as_str(),
                map_state(node.host_data_match).as_str(),
                node.detail
            ));
        }
    }

    // The scope is not decoration. Every part of the sentence bounds the
    // claim: *which* nodes — named, so a reader can tell a three-node ledger
    // from three nodes of a larger one — and whether they were observed by
    // this run or replayed from someone else's recording. The two readings
    // differ in what backs the anchor, so they must not share a sentence.
    let ids: Vec<&str> = appraisal.nodes.iter().map(|n| n.node_id.as_str()).collect();
    let scope = if metadata.observed {
        format!(
            "appraisal of {} node(s) [{}] observed at {} on {}, whose service identity was \
             confirmed against the public identity service; not a proof that those nodes are \
             still serving",
            metadata.node_count,
            ids.join(", "),
            metadata
                .collected_at
                .clone()
                .unwrap_or_else(|| "an unrecorded time".to_string()),
            metadata.ledger
        )
    } else {
        let collected = metadata
            .collected_at
            .clone()
            .unwrap_or_else(|| "an unrecorded time".to_string());
        format!(
            "offline evidence appraisal of {} node(s) [{}] recorded from {} at {collected}; \
             not an observation of the live ledger",
            metadata.node_count,
            ids.join(", "),
            metadata.ledger
        )
    };

    ResourceAppraisal {
        checks,
        scoped_pass: appraisal.scoped_pass(),
        scope,
        blocking: appraisal
            .blocking()
            .into_iter()
            .map(|(_, label)| label.to_string())
            .collect(),
        notes,
    }
}

/// Reduce a hostname to a comparable form.
///
/// Hostnames are case-insensitive and may carry a trailing root dot, and a
/// collector may reasonably have recorded a URL where the policy names a bare
/// host. Normalising those away avoids refusing a bundle over spelling; it
/// does not weaken the comparison, because everything it removes is a form
/// that denotes the same host. Ports are deliberately *not* stripped: a
/// different port is a different endpoint.
#[cfg(feature = "adapter-mst-ledger")]
fn normalise_host(raw: &str) -> String {
    let host = raw.trim();
    let host = host
        .strip_prefix("https://")
        .or_else(|| host.strip_prefix("http://"))
        .unwrap_or(host);
    let host = host.split('/').next().unwrap_or(host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Translate policy into the adapter's typed requirements.
#[cfg(feature = "adapter-mst-ledger")]
fn requirements(
    bind: &BindLedgerPolicy,
    trust: &TrustInputs,
) -> Result<scitt_attest::Requirements, String> {
    let mut min_tcb = Vec::with_capacity(bind.minimum_tcb.len());
    for entry in &bind.minimum_tcb {
        min_tcb.push(scitt_attest::TcbFloor {
            generation: entry.generation.clone(),
            reported_tcb: entry.value()?,
        });
    }
    Ok(scitt_attest::Requirements {
        uvm_did_x509: trust.uvm_issuer.clone(),
        uvm_feed: bind.uvm_feed.clone(),
        uvm_eku: trust.uvm_eku.clone(),
        min_uvm_svn: bind.min_uvm_svn,
        min_tcb,
    })
}

/// The adapter's states are the CLI's states, one for one.
///
/// Written out rather than shared, because the adapter defines its own
/// vocabulary precisely so it does not depend on this binary. A `From` in
/// either crate would recreate the coupling the split exists to avoid.
#[cfg(feature = "adapter-mst-ledger")]
fn map_state(state: scitt_attest::CheckState) -> CheckState {
    match state {
        scitt_attest::CheckState::Pass => CheckState::Pass,
        scitt_attest::CheckState::Fail => CheckState::Fail,
        scitt_attest::CheckState::NotChecked => CheckState::NotChecked,
        scitt_attest::CheckState::CannotEvaluate => CheckState::CannotEvaluate,
    }
}

#[cfg(feature = "adapter-mst-ledger")]
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every check must be named even when no appraisal ran.
    ///
    /// A run that simply omitted them would be indistinguishable from one
    /// where they did not apply, and the whole point of this path is that an
    /// unanswered question stays visible.
    #[test]
    fn an_appraisal_that_did_not_run_names_every_check_and_passes_none() {
        let a = ResourceAppraisal::not_attempted("no adapter");
        assert_eq!(a.checks.len(), 6);
        assert!(!a.scoped_pass);
        for check in &a.checks {
            assert_eq!(check.state, CheckState::CannotEvaluate);
            assert!(!check.detail.is_empty());
        }
        assert!(a.checks.iter().any(|c| c.name == "cce-policy-host-data"));
    }

    /// Hostname spelling must not decide a security check.
    ///
    /// Everything normalised away denotes the same host, so removing it
    /// cannot admit a different service. A port is left alone deliberately: a
    /// different port is a different endpoint, not a different spelling.
    #[cfg(feature = "adapter-mst-ledger")]
    #[test]
    fn host_comparison_ignores_spelling_but_not_identity() {
        let canonical = normalise_host("ledger.confidential-ledger.azure.com");
        for same in [
            "LEDGER.Confidential-Ledger.Azure.Com",
            "  ledger.confidential-ledger.azure.com  ",
            "ledger.confidential-ledger.azure.com.",
            "https://ledger.confidential-ledger.azure.com",
            "https://ledger.confidential-ledger.azure.com/",
        ] {
            assert_eq!(
                normalise_host(same),
                canonical,
                "{same} should compare equal"
            );
        }
        for different in [
            "other.confidential-ledger.azure.com",
            "ledger.confidential-ledger.azure.com.evil.test",
            "ledger.confidential-ledger.azure.com:8443",
        ] {
            assert_ne!(
                normalise_host(different),
                canonical,
                "{different} must not compare equal"
            );
        }
    }

    /// The names must match the adapter's, in both build configurations.
    #[test]
    fn the_check_names_are_stable_across_builds() {
        let names: Vec<&str> = scitt_attest_names().iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                "ledger-identity-binding",
                "snp-uvm-validation",
                "cce-policy-host-data",
                "node-coverage",
                "freshness",
                "connection-binding",
            ]
        );
    }
}
