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

use scitt_policy::adapters::acl::AzureConfidentialLedgerPolicy;
#[cfg(feature = "adapter-azure-confidential-ledger")]
use scitt_policy::adapters::acl::{BindLedgerPolicy, Encoding, TrustInputs};
#[cfg(feature = "adapter-azure-confidential-ledger")]
use scitt_receipt::base64::Alphabet;
use scitt_receipt::Sign1;

use super::{AdapterAssessment, EvidenceSource};
use crate::outcome::AdapterFinding;
use crate::outcome::{AdapterCheck, CheckState};
use crate::progress::Presentation;
use crate::progress::{Event, Sink, Stage, State};

pub fn check_event(check: &AdapterCheck, detail: String, findings: &[AdapterFinding]) -> Event {
    let mut event = Event::finding(
        Stage::Adapter,
        &check.name,
        None,
        crate::progress_state(check.state),
        detail,
    );
    if compact_limitation(check, findings).is_some() {
        event.presentation = Presentation::FinalLimitation;
        return event;
    }
    let count = findings
        .iter()
        .filter(|finding| finding.check == "cce-policy-host-data")
        .count();
    if count == 0 {
        return event;
    }
    match check.name.as_str() {
        "ledger-identity-binding" | "snp-uvm-validation" => event.detail(),
        "cce-policy-host-data" => event.brief(format!(
            "All {count} assessed nodes match expected policy commitment"
        )),
        "node-coverage" => event.brief("Required coverage of assessed snapshot satisfied"),
        _ => event,
    }
}

/// Only excluded, unevaluable checks after node appraisal are moved to the
/// final limitations. Prerequisite errors and future required checks stay visible.
pub fn compact_limitation(
    check: &AdapterCheck,
    findings: &[AdapterFinding],
) -> Option<&'static str> {
    if check.state != CheckState::CannotEvaluate
        || required_checks().contains(&check.name)
        || !findings
            .iter()
            .any(|finding| finding.check == "cce-policy-host-data")
    {
        return None;
    }
    match check.name.as_str() {
        "freshness" => Some("Report freshness was not established."),
        "connection-binding" => Some("Binding to the serving connection was not established."),
        _ => None,
    }
}

pub fn not_attempted(reason: impl Into<String>) -> AdapterAssessment {
    let reason = reason.into();
    let checks = check_names()
        .into_iter()
        .map(|(name, label)| AdapterCheck {
            name: name.to_string(),
            label: label.to_string(),
            state: CheckState::CannotEvaluate,
            detail: reason.clone(),
        })
        .collect();
    AdapterAssessment {
        checks,
        findings: Vec::new(),
        required_checks: required_checks(),
        scope: "no evidence was appraised".to_string(),
        notes: vec![reason],
    }
}

fn required_checks() -> Vec<String> {
    [
        "ledger-identity-binding",
        "snp-uvm-validation",
        "cce-policy-host-data",
        "node-coverage",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// The check names an appraisal reports, whether or not one ran.
///
/// Taken from the adapter when it is compiled in, so the two cannot drift. A
/// build without the adapter still has to name the checks it did not perform:
/// a run that omitted them entirely would be indistinguishable from one where
/// they were never relevant.
#[cfg(feature = "adapter-azure-confidential-ledger")]
fn check_names() -> Vec<(&'static str, &'static str)> {
    acl::CHECK_NAMES.to_vec()
}

#[cfg(not(feature = "adapter-azure-confidential-ledger"))]
fn check_names() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ledger-identity-binding", "Ledger identity/key binding"),
        ("snp-uvm-validation", "SNP and UVM validation"),
        ("cce-policy-host-data", "CCE policy / HOST_DATA"),
        ("node-coverage", "Enumerated-node coverage"),
        ("freshness", "Freshness"),
        ("connection-binding", "Connection binding"),
    ]
}

/// Appraise ledger evidence against an accepted statement.
///
/// `statement` is the parsed statement that already passed acceptance.
#[cfg(not(feature = "adapter-azure-confidential-ledger"))]
pub fn appraise_evidence(
    _source: EvidenceSource<'_>,
    _statement: &Sign1,
    _policy: &AzureConfidentialLedgerPolicy,
    progress: &mut dyn Sink,
) -> AdapterAssessment {
    // Not an error and not a failure: the question was asked and this binary
    // cannot answer it. Reported as `CannotEvaluate` so it exits 3 rather than
    // 0, because a build that silently skipped the appraisal would let a gate
    // pass on the strength of a check that never ran.
    progress.emit(Event::stage(
        Stage::Evidence,
        State::NotRun,
        "This build has no azure-confidential-ledger adapter",
    ));
    progress.emit(Event::stage(
        Stage::Adapter,
        State::NotRun,
        "Rebuild with --features adapter-azure-confidential-ledger",
    ));
    not_attempted(
        "this build was compiled without the azure-confidential-ledger adapter, so no ledger evidence can be \
         appraised. Rebuild with --features adapter-azure-confidential-ledger.",
    )
}

/// Appraise ledger evidence against an accepted statement.
#[cfg(feature = "adapter-azure-confidential-ledger")]
pub fn appraise_evidence(
    source: EvidenceSource<'_>,
    statement: &Sign1,
    policy: &AzureConfidentialLedgerPolicy,
    progress: &mut dyn Sink,
) -> AdapterAssessment {
    let AzureConfidentialLedgerPolicy {
        target: ledger,
        trust,
        binding: bind,
    } = policy;

    let requirements = match requirements(bind, trust) {
        Ok(r) => r,
        Err(why) => return not_attempted(why),
    };

    // The reference digest, from the statement that was accepted.
    progress.emit(Event::stage(
        Stage::Policy,
        State::Started,
        "Extracting embedded CCE policy and hashing exact decoded bytes...",
    ));
    let alphabet = match bind.encoding {
        Encoding::Base64 => Alphabet::Standard,
        Encoding::Base64url => Alphabet::UrlSafe,
    };
    let policy_bytes =
        match scitt_policy::claim::encoded_claim_bytes(statement, &bind.path, alphabet) {
            Ok(b) => b,
            Err(e) => {
                return not_attempted(format!(
                    "the statement's execution policy could not be read: {}",
                    e.describe()
                ))
            }
        };
    if let Some(max) = bind.max_decoded_bytes {
        if policy_bytes.len() > max {
            return not_attempted(format!(
                "the statement's execution policy is {} bytes, above the {max} the policy \
                 allows; its digest is not reported, because a claim this far from what was \
                 expected is more likely a wrong path than a large policy",
                policy_bytes.len()
            ));
        }
    }
    let policy_digest = scitt_receipt::sha256(&policy_bytes);
    progress.emit(Event::stage(
        Stage::Policy,
        State::Done,
        "Expected policy commitment derived",
    ));

    let mut notes = Vec::new();

    // An optional pin against a correctly signed statement for the wrong
    // build. Checked before the evidence, because if the statement is not the
    // one this gate intended then nothing the nodes report is relevant.
    if let Some(expected) = &bind.expect_policy_sha256 {
        let actual = hex(&policy_digest);
        if !actual.eq_ignore_ascii_case(expected) {
            let mut appraisal = not_attempted(format!(
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
            progress.emit(Event::stage(
                Stage::Evidence,
                State::Started,
                format!(
                    "Loading saved evidence from {} (not a live connection)...",
                    dir.display()
                ),
            ));
            super::load::load(dir).map_err(|e| format!("the evidence bundle is unusable: {e}"))
        }
        EvidenceSource::Live { save_to } => {
            // One deadline for the whole acquisition, started here. Reaching
            // an unreachable ledger is an inability, never a finding: the
            // question was asked and nothing answered it, which is not the
            // same as a node that answered badly.
            let deadline = std::time::Instant::now() + scitt_network::limits::TOTAL_DEADLINE;
            super::live::fetch(&ledger.host, deadline, progress)
                .map_err(|e| format!("evidence could not be collected from {}: {e}", ledger.host))
                .and_then(|(bundle, metadata)| {
                    progress.emit(Event::stage(
                        Stage::Evidence,
                        State::Done,
                        format!(
                            "Collected evidence for {} candidate nodes",
                            bundle.nodes.len()
                        ),
                    ));
                    match save_to {
                        Some(dir) => {
                            progress.emit(Event::stage(
                                Stage::Evidence,
                                State::Started,
                                format!("Saving collected evidence to {}...", dir.display()),
                            ));
                            super::load::save(dir, &bundle, &metadata)
                                .map(|()| {
                                    progress.emit(Event::stage(
                                        Stage::Evidence,
                                        State::Done,
                                        format!("Saved evidence to {}", dir.display()),
                                    ));
                                    (bundle, metadata)
                                })
                                .map_err(|e| {
                                    // A run asked for a copy of what it judged;
                                    // appraising without that copy is a different run.
                                    format!("the collected evidence could not be saved: {e}")
                                })
                        }
                        None => Ok((bundle, metadata)),
                    }
                })
        }
    };
    let (bundle, metadata) = match loaded {
        Ok(b) => b,
        Err(e) => {
            progress.emit(Event::stage(
                Stage::Evidence,
                State::CannotEvaluate,
                e.clone(),
            ));
            progress.emit(Event::stage(
                Stage::Adapter,
                State::NotRun,
                "Evidence acquisition did not complete",
            ));
            return not_attempted(e);
        }
    };
    if !metadata.observed {
        progress.emit(Event::stage(
            Stage::Evidence,
            State::Done,
            format!(
                "Loaded saved evidence for {} candidate nodes",
                bundle.nodes.len()
            ),
        ));
    }

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
        let mut appraisal = not_attempted(format!(
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
            return not_attempted(format!(
                "the evidence enumerates {} node(s), but the policy expects {expected}. \
                 Coverage is only ever over the nodes the evidence names, so a bundle with \
                 nodes missing cannot be told from a smaller ledger.",
                metadata.node_count
            ));
        }
    }

    let ids: Vec<_> = bundle
        .nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect();
    let labels = node_labels(&ids);
    let mut checklist = Event::stage(
        Stage::Adapter,
        State::Started,
        "Appraising each candidate node...",
    );
    checklist.presentation = Presentation::Checklist {
        checks: vec![
            "Authenticate SNP report using AMD endorsement certificates".into(),
            "Verify UVM endorsement and binding to reported measurement".into(),
            "Apply configured platform, TCB and UVM version requirements".into(),
            "Bind attested node key to target service identity".into(),
            "Compare policy commitment with statement-derived hash".into(),
        ],
        columns: vec![
            "Service binding".into(),
            "SNP / UVM".into(),
            "Policy match".into(),
        ],
        subject_width: labels
            .iter()
            .map(|label| label.chars().count())
            .max()
            .unwrap_or(21),
    };
    progress.emit(checklist);
    let mut index = 0;
    let appraisal = match acl::appraise_with(
        &bundle,
        &policy_digest,
        &requirements,
        &mut |node| {
            emit_node(node, &labels[index], progress);
            index += 1;
        },
    ) {
        Ok(a) => a,
        Err(e) => return not_attempted(format!("the evidence could not be appraised: {e}")),
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

    let findings = node_findings(&appraisal.nodes);
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

    AdapterAssessment {
        checks,
        findings,
        required_checks: required_checks(),
        scope,
        notes,
    }
}

#[cfg(feature = "adapter-azure-confidential-ledger")]
fn emit_node(node: &acl::NodeOutcome, label: &str, progress: &mut dyn Sink) {
    let mut row = Event::stage(Stage::Adapter, State::Done, label);
    row.presentation = Presentation::Row(vec![
        crate::progress_state(map_state(node.identity_binding)),
        crate::progress_state(map_state(node.attestation)),
        crate::progress_state(map_state(node.host_data_match)),
    ]);
    progress.emit(row);
    for finding in node_findings(std::slice::from_ref(node)) {
        progress.emit(node_event(finding, label));
    }
}

#[cfg(feature = "adapter-azure-confidential-ledger")]
fn node_event(finding: AdapterFinding, label: &str) -> Event {
    let summarized = matches!(
        finding.check.as_str(),
        "ledger-identity-binding" | "snp-uvm-validation" | "cce-policy-host-data"
    );
    let event = Event::finding_with_values(
        Stage::Adapter,
        finding.check,
        Some(finding.subject),
        crate::progress_state(finding.state),
        finding.detail,
        finding.expected,
        finding.observed,
    )
    .subject_label(label);
    if summarized {
        event.detail()
    } else {
        event
    }
}

#[cfg(feature = "adapter-azure-confidential-ledger")]
fn node_labels(ids: &[&str]) -> Vec<String> {
    ids.iter()
        .enumerate()
        .map(|(index, id)| {
            let chars: Vec<_> = id.chars().collect();
            let mut length = 8.min(chars.len());
            while length < chars.len()
                && ids.iter().enumerate().any(|(other, candidate)| {
                    other != index
                        && candidate
                            .chars()
                            .take(length)
                            .eq(chars[..length].iter().copied())
                })
            {
                length += 1;
            }
            let prefix: String = chars[..length].iter().collect();
            let label = if length < chars.len() {
                format!("{prefix}...")
            } else {
                prefix
            };
            // Very long or identical IDs still get distinct bounded row references.
            format!("#{} {}", index + 1, crate::progress::safe_text(&label, 72))
        })
        .collect()
}

#[cfg(feature = "adapter-azure-confidential-ledger")]
fn node_findings(nodes: &[acl::NodeOutcome]) -> Vec<AdapterFinding> {
    let mut findings = Vec::with_capacity(nodes.len() * 3);
    for node in nodes {
        findings.push(AdapterFinding {
            check: "ledger-identity-binding".into(),
            subject: node.node_id.clone(),
            state: map_state(node.identity_binding),
            detail: node.detail.clone(),
            expected: None,
            observed: None,
        });
        findings.push(AdapterFinding {
            check: "snp-uvm-validation".into(),
            subject: node.node_id.clone(),
            state: map_state(node.attestation),
            detail: node.detail.clone(),
            expected: None,
            observed: None,
        });
        findings.push(AdapterFinding {
            check: "cce-policy-host-data".into(),
            subject: node.node_id.clone(),
            state: map_state(node.host_data_match),
            detail: node.detail.clone(),
            expected: node.expected_policy_digest.clone(),
            observed: node.observed_host_data.clone(),
        });
    }
    findings
}

/// Reduce a hostname to a comparable form.
///
/// Hostnames are case-insensitive and may carry a trailing root dot, and a
/// collector may reasonably have recorded a URL where the policy names a bare
/// host. Normalising those away avoids refusing a bundle over spelling; it
/// does not weaken the comparison, because everything it removes is a form
/// that denotes the same host. Ports are deliberately *not* stripped: a
/// different port is a different endpoint.
#[cfg(feature = "adapter-azure-confidential-ledger")]
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
#[cfg(feature = "adapter-azure-confidential-ledger")]
fn requirements(
    bind: &BindLedgerPolicy,
    trust: &TrustInputs,
) -> Result<acl::Requirements, String> {
    let mut min_tcb = Vec::with_capacity(bind.minimum_tcb.len());
    for entry in &bind.minimum_tcb {
        min_tcb.push(acl::TcbFloor {
            generation: entry.generation.clone(),
            reported_tcb: entry.value()?,
        });
    }
    Ok(acl::Requirements {
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
#[cfg(feature = "adapter-azure-confidential-ledger")]
fn map_state(state: acl::CheckState) -> CheckState {
    match state {
        acl::CheckState::Pass => CheckState::Pass,
        acl::CheckState::Fail => CheckState::Fail,
        acl::CheckState::NotChecked => CheckState::NotChecked,
        acl::CheckState::CannotEvaluate => CheckState::CannotEvaluate,
    }
}

#[cfg(feature = "adapter-azure-confidential-ledger")]
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

    #[test]
    fn compact_only_defers_known_excluded_inabilities_after_appraisal() {
        let findings = [AdapterFinding {
            check: "cce-policy-host-data".into(),
            subject: "node".into(),
            state: CheckState::Pass,
            detail: "matched".into(),
            expected: None,
            observed: None,
        }];
        for name in [
            "freshness",
            "connection-binding",
            "unknown-check",
            "node-coverage",
        ] {
            for state in [
                CheckState::Pass,
                CheckState::Fail,
                CheckState::CannotEvaluate,
                CheckState::NotChecked,
            ] {
                let check = AdapterCheck {
                    name: name.into(),
                    label: name.into(),
                    state,
                    detail: "original detail".into(),
                };
                let deferred = matches!(name, "freshness" | "connection-binding")
                    && state == CheckState::CannotEvaluate;
                assert_eq!(compact_limitation(&check, &findings).is_some(), deferred);
                assert_eq!(
                    check_event(&check, check.detail.clone(), &findings).presentation
                        == Presentation::FinalLimitation,
                    deferred
                );
                assert!(
                    compact_limitation(&check, &[]).is_none(),
                    "prerequisite reasons must remain visible"
                );
            }
        }
    }

    #[test]
    fn unknown_and_nonpass_aggregate_checks_are_never_hidden() {
        for state in [
            CheckState::Pass,
            CheckState::Fail,
            CheckState::CannotEvaluate,
            CheckState::NotChecked,
        ] {
            let check = AdapterCheck {
                name: "future-check".into(),
                label: "Future check".into(),
                state,
                detail: "important".into(),
            };
            let event = check_event(&check, check.detail.clone(), &[]);
            assert_eq!(event.presentation, crate::progress::Presentation::Normal);
            assert_eq!(event.message, "important");
            assert_eq!(event.state, crate::progress_state(state));
        }
    }

    #[cfg(feature = "adapter-azure-confidential-ledger")]
    #[test]
    fn node_labels_are_visibly_shortened_unique_and_bounded() {
        let ids = ["12345678aaaa0000", "12345678aaab0000", "short", "short"];
        let labels = node_labels(&ids);
        assert_eq!(labels[0], "#1 12345678aaaa...");
        assert_eq!(labels[1], "#2 12345678aaab...");
        assert_eq!(labels[2], "#3 short");
        assert_eq!(labels[3], "#4 short");
        let long = "x".repeat(200);
        let labels = node_labels(&[&long, &long]);
        assert_ne!(labels[0], labels[1]);
        assert!(labels
            .iter()
            .all(|label| label.len() < 80 && label.ends_with("...")));
    }

    #[cfg(feature = "adapter-azure-confidential-ledger")]
    fn test_node() -> acl::NodeOutcome {
        use acl::{CheckState::Pass, NodeOutcome};
        NodeOutcome {
            node_id: "12345678abcdef0123456789".into(),
            identity_binding: Pass,
            attestation: Pass,
            host_data_match: Pass,
            expected_policy_digest: Some("expected-full-hash".into()),
            observed_host_data: Some("expected-full-hash".into()),
            detail: "measurement full-measurement".into(),
        }
    }

    #[cfg(feature = "adapter-azure-confidential-ledger")]
    #[test]
    fn successful_node_is_one_row_without_hashes_but_verbose_keeps_evidence() {
        let node = test_node();
        let mut bytes = Vec::new();
        let mut sink = crate::progress::Text::compact(
            &mut bytes,
            false,
            vec![(Stage::Adapter, "Appraise node evidence".into())],
        );
        emit_node(&node, "#1 12345678...", &mut sink);
        sink.finish().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(), 3, "{text}");
        assert_eq!(text.matches("PASS").count(), 3);
        assert!(text.contains("#1 12345678..."));
        for value in [
            "measurement",
            "expected-full-hash",
            "Expected:",
            "Observed:",
            &node.node_id,
        ] {
            assert!(!text.contains(value), "{text}");
        }
        let mut bytes = Vec::new();
        let mut sink = crate::progress::Text::new(&mut bytes, false);
        emit_node(&node, "#1 12345678...", &mut sink);
        sink.finish().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(&node.node_id));
        assert!(text.contains("measurement full-measurement"));
        assert!(text.contains("Expected: expected-full-hash"));
        assert!(text.contains("Observed: expected-full-hash"));
    }

    #[cfg(feature = "adapter-azure-confidential-ledger")]
    #[test]
    fn node_mismatch_expands_values_and_unevaluated_checks() {
        use acl::CheckState;
        let mut node = test_node();
        node.host_data_match = CheckState::Fail;
        node.attestation = CheckState::CannotEvaluate;
        node.observed_host_data = Some("different-full-hash".into());
        node.detail = "authenticated commitment differs; platform requirements not reached".into();
        let mut bytes = Vec::new();
        let mut sink = crate::progress::Text::compact(
            &mut bytes,
            false,
            vec![(Stage::Adapter, "Appraise".into())],
        );
        emit_node(&node, "#1 12345678...", &mut sink);
        sink.finish().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("FAIL cce-policy-host-data [#1 12345678...]"));
        assert!(text.contains("CANNOT EVALUATE snp-uvm-validation"));
        assert!(text.contains("platform requirements not reached"));
        assert!(text.contains("Expected: expected-full-hash"));
        assert!(text.contains("Observed: different-full-hash"));
    }

    #[cfg(feature = "adapter-azure-confidential-ledger")]
    #[test]
    fn new_node_findings_are_not_silently_absorbed_by_the_row() {
        let finding = AdapterFinding {
            check: "new-domain-check".into(),
            subject: "node".into(),
            state: CheckState::Pass,
            detail: "new result".into(),
            expected: None,
            observed: None,
        };
        assert_eq!(
            node_event(finding, "#1 node").presentation,
            Presentation::Normal
        );
    }

    /// Every check must be named even when no appraisal ran.
    ///
    /// A run that simply omitted them would be indistinguishable from one
    /// where they did not apply, and the whole point of this path is that an
    /// unanswered question stays visible.
    #[test]
    fn an_appraisal_that_did_not_run_names_every_check_and_passes_none() {
        let a = not_attempted("no adapter");
        assert_eq!(a.checks.len(), 6);
        assert!(!a.scoped_pass());
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
    #[cfg(feature = "adapter-azure-confidential-ledger")]
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
        let names: Vec<&str> = check_names().iter().map(|(n, _)| *n).collect();
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

    #[cfg(feature = "adapter-azure-confidential-ledger")]
    #[test]
    fn node_policy_findings_keep_expected_and_observed_digests() {
        let findings = node_findings(&[acl::NodeOutcome {
            node_id: "node-a".into(),
            identity_binding: acl::CheckState::Pass,
            attestation: acl::CheckState::Pass,
            host_data_match: acl::CheckState::Fail,
            expected_policy_digest: Some("expected".into()),
            observed_host_data: Some("observed".into()),
            detail: "different commitments".into(),
        }]);
        let policy = findings
            .iter()
            .find(|finding| finding.check == "cce-policy-host-data")
            .unwrap();
        assert_eq!(policy.subject, "node-a");
        assert_eq!(policy.state, CheckState::Fail);
        assert_eq!(policy.expected.as_deref(), Some("expected"));
        assert_eq!(policy.observed.as_deref(), Some("observed"));
    }
}
