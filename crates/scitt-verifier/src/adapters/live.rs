//! Collecting ledger evidence from the ledger itself.
//!
//! The counterpart to [`super::load`], and the reason online acquisition
//! is worth building at all. A saved bundle supplies its own
//! `service.pem` — the very certificate identity binding is checked against —
//! so a self-consistent bundle produced by somebody else's ledger satisfies
//! every check in the appraisal. The bundle is internally honest and answers a
//! question about the wrong service.
//!
//! Here the anchor cannot come from the evidence. It comes from
//! [`scitt_network::bootstrap`], which asks the public identity service which
//! certificate that ledger must present, over the public web PKI, and the
//! connection that carries the node reports is then pinned to exactly that
//! certificate. Substituting a ledger no longer substitutes the anchor with
//! it.
//!
//! What this still does not establish: freshness. CCF offers no
//! challenge-response attestation, so a node's report is a recording either
//! way — observed at a known time rather than at an unrecorded one, which is a
//! better record but not a live proof. Nor does it bind the connection to a
//! particular node: the endpoint load-balances, so the node that served the
//! response cannot be shown to be the node whose report it carried. Both
//! checks stay `CannotEvaluate` for a live run exactly as they do for a saved
//! one.

use std::collections::BTreeMap;
use std::time::Instant;

use scitt_adapter_mst_ledger::{EvidenceBundle, NodeEvidence};
use scitt_network::limits;
use serde::Deserialize;

use super::load::BundleMetadata;

/// One node's attestation, as `/node/quotes` reports it.
#[derive(Debug, Deserialize)]
struct Quote {
    node_id: String,
    /// The raw SNP attestation report.
    raw: String,
    /// The AMD certificate chain endorsing the report's signing key.
    endorsements: String,
    /// The COSE-signed UVM endorsement.
    #[serde(default)]
    uvm_endorsements: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QuotesResponse {
    quotes: Vec<Quote>,
}

/// One node's published certificate, as `/gov/service/nodes` reports it.
///
/// Note the spelling: the governance API is camelCase where `/node/quotes` is
/// snake_case. Two APIs, two conventions, and the join depends on reading each
/// one as it is actually served.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GovNode {
    node_id: String,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NodesResponse {
    value: Vec<GovNode>,
}

/// Collect evidence from a live ledger, anchored outside the ledger.
///
/// `host` must be the host the policy named. It is validated through
/// [`scitt_network::provider::route_for`], which refuses anything that is not a bare hostname
/// a shipped provider covers — deliberately stricter than the lenient
/// comparison used to match a saved bundle's recorded name, because this
/// string decides where a request goes.
///
/// `deadline` bounds this evidence collection, including both endpoint requests.
pub fn fetch(
    host: &str,
    deadline: Instant,
    progress: &mut dyn crate::progress::Sink,
) -> Result<(EvidenceBundle, BundleMetadata), String> {
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("could not timestamp evidence acquisition: {e}"))?;
    let observed_at = i64::try_from(observed_at.as_secs())
        .map_err(|e| format!("evidence acquisition time is out of range: {e}"))?;
    let collected = scitt_network::mst_ledger::collect_with(host, deadline, &mut |step| {
        progress.emit(collection_event(step));
    })
    .map_err(|e| format!("ledger evidence acquisition failed: {e}"))?;

    let bundle = assemble(
        &collected.quotes,
        &collected.nodes,
        super::load::pem_block(&collected.service_certificate_der).as_bytes(),
    )?;
    let node_count = bundle.nodes.len();

    Ok((
        bundle,
        BundleMetadata {
            ledger: collected.host,
            collected_at: Some(
                crate::display::utc_rfc3339(observed_at).unwrap_or_else(|| observed_at.to_string()),
            ),
            node_count,
            observed: true,
        },
    ))
}

fn collection_event(step: scitt_network::mst_ledger::CollectionStep) -> crate::progress::Event {
    use crate::progress::{Event, Stage, State};
    use scitt_network::mst_ledger::CollectionStep;
    let (state, message) = match step {
        CollectionStep::ResolvingIdentity => (State::Started, "Resolving service certificate through identity service..."),
        CollectionStep::Connecting => (State::Started, "Connecting using TLS pinned to that certificate; fetching SNP reports and UVM endorsements..."),
        CollectionStep::Authenticated => (State::Pass, "Connected to authenticated target"),
        CollectionStep::FetchingNodes => (State::Started, "Fetching node certificates..."),
    };
    Event::stage(Stage::Evidence, state, message)
}

/// Turn two responses into an evidence bundle.
///
/// Separated from the fetch so the decoding and joining rules can be tested
/// against recorded responses without a network.
fn assemble(
    quotes_body: &[u8],
    nodes_body: &[u8],
    service_certificate_pem: &[u8],
) -> Result<EvidenceBundle, String> {
    let quotes: QuotesResponse = serde_json::from_slice(quotes_body)
        .map_err(|e| format!("the ledger's node quotes could not be read: {e}"))?;
    let gov: NodesResponse = serde_json::from_slice(nodes_body)
        .map_err(|e| format!("the ledger's node list could not be read: {e}"))?;

    if quotes.quotes.is_empty() {
        return Err(
            "the ledger reported no nodes; evidence about no node establishes \
                    nothing"
                .to_string(),
        );
    }
    if quotes.quotes.len() > limits::MAX_NODES {
        return Err(format!(
            "the ledger reported {} nodes, above the {} this build will appraise",
            quotes.quotes.len(),
            limits::MAX_NODES
        ));
    }

    let mut certificates = BTreeMap::new();
    for node in gov.value {
        if let Some(pem) = node.certificate {
            certificates.insert(node.node_id, pem);
        }
    }

    let mut nodes = Vec::with_capacity(quotes.quotes.len());
    let mut seen = BTreeMap::new();
    for quote in &quotes.quotes {
        let id = quote.node_id.trim();
        if id.is_empty() {
            return Err("the ledger reported a node with no id".to_string());
        }
        if seen.insert(id.to_string(), ()).is_some() {
            return Err(format!(
                "the ledger reported node {id} more than once; one node's evidence must not \
                 be counted as several"
            ));
        }

        let snp_report = decode(&quote.raw, id, "attestation report")?;
        let amd_pem = decode(&quote.endorsements, id, "AMD endorsements")?;
        let uvm = quote.uvm_endorsements.as_deref().unwrap_or("");
        let uvm_endorsement = if uvm.trim().is_empty() {
            Vec::new()
        } else {
            decode(uvm, id, "UVM endorsement")?
        };

        // Asymmetry between the two responses is refused rather than patched
        // over. Without the node's certificate there is nothing to bind the
        // report's REPORT_DATA to, so the node would be appraised with its
        // decisive check unevaluated while still counting towards coverage —
        // a quieter outcome than the ledger deserves.
        let certificate_pem = match certificates.get(id) {
            Some(pem) => pem.as_bytes().to_vec(),
            None => {
                return Err(format!(
                    "the ledger attested node {id} but publishes no certificate for it, so \
                     its report cannot be bound to a key this service certified"
                ))
            }
        };

        let pem = String::from_utf8(amd_pem)
            .map_err(|_| format!("node {id}: the AMD endorsements are not text PEM"))?;
        let amd_endorsements = scitt_receipt::chain::parse_pem_certificates(&pem)
            .map_err(|e| format!("node {id}: AMD endorsements: {e}"))?;

        nodes.push(NodeEvidence {
            node_id: id.to_string(),
            certificate_pem,
            snp_report,
            amd_endorsements,
            uvm_endorsement,
        });
    }

    Ok(EvidenceBundle {
        service_certificate_pem: service_certificate_pem.to_vec(),
        nodes,
    })
}

/// Decode a field that may be hex or base64.
///
/// CCF builds differ: one ledger returns these fields hex-encoded and another
/// base64. The two alphabets overlap — hex's is a strict subset of base64's —
/// so a string of nothing but hex digits is *also* a syntactically valid
/// base64 string, and an even-length one usually decodes. Hex is preferred in
/// that case: base64 of several hundred bytes of binary contains an uppercase
/// letter outside `A-F`, a digit outside `0-9`, or `+`/`/` with overwhelming
/// probability, so a string that is entirely hex digits is base64 only by
/// coincidence.
///
/// Misreading the encoding is not a safety problem, which is why preferring
/// one is acceptable where guessing usually is not: the bytes go on to be
/// checked against an AMD signature and a certificate binding, so a wrong
/// decoding yields a refusal rather than a false pass.
fn decode(value: &str, node_id: &str, what: &str) -> Result<Vec<u8>, String> {
    let s = value.trim();
    if s.is_empty() {
        return Err(format!("node {node_id}: the {what} field is empty"));
    }

    if looks_like_hex(s) {
        if let Some(bytes) = decode_hex(s) {
            return Ok(bytes);
        }
    }

    scitt_receipt::base64::decode(scitt_receipt::base64::Alphabet::Standard, s)
        .map_err(|_| format!("node {node_id}: the {what} field is neither hex nor base64"))
}

fn looks_like_hex(s: &str) -> bool {
    s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_progress_never_claims_authentication_before_a_response() {
        use scitt_network::mst_ledger::CollectionStep::*;
        for step in [ResolvingIdentity, Connecting, FetchingNodes] {
            assert_eq!(
                collection_event(step).state,
                crate::progress::State::Started
            );
        }
        let authenticated = collection_event(Authenticated);
        assert_eq!(authenticated.state, crate::progress::State::Pass);
        assert_eq!(authenticated.message, "Connected to authenticated target");
        assert_eq!(authenticated.stage, crate::progress::Stage::Evidence);
    }

    /// Hex wins when a string could be read either way.
    ///
    /// Not arbitrary: every hex digit is also a base64 character, so real
    /// hex-encoded evidence would be unusable under any rule that refused the
    /// overlap, while real base64 of binary is never all hex digits.
    #[test]
    fn a_string_that_is_all_hex_digits_is_read_as_hex() {
        assert_eq!(decode("abcd", "n1", "report").unwrap(), b"\xab\xcd");
    }

    #[test]
    fn hex_and_base64_both_decode() {
        assert_eq!(
            decode("0a0b0c0d0e", "n1", "report").unwrap(),
            b"\n\x0b\x0c\r\x0e"
        );
        assert_eq!(decode("aGVsbG8h", "n1", "report").unwrap(), b"hello!");
    }

    #[test]
    fn a_field_in_neither_encoding_is_refused() {
        let err = decode("not encoded!!", "n1", "report").unwrap_err();
        assert!(err.contains("neither hex nor base64"), "{err}");
    }

    #[test]
    fn an_empty_field_is_refused() {
        let err = decode("  ", "n1", "report").unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn timestamps_render_as_utc() {
        assert_eq!(
            crate::display::utc_rfc3339(0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            crate::display::utc_rfc3339(1_788_201_057).as_deref(),
            Some("2026-08-31T18:30:57Z")
        );
    }

    /// A self-signed P-384 certificate, real enough for the PEM parser.
    const PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBWTCB4KADAgECAgEBMAoGCCqGSM49BAMDMBgxFjAUBgNVBAMMDWV2aWRlbmNl\n\
        LXRlc3QwHhcNMjAwMTAxMDAwMDAwWhcNNDAwMTAxMDAwMDAwWjAYMRYwFAYDVQQD\n\
        DA1ldmlkZW5jZS10ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWpAU/kIh2hVe\n\
        VUPJBVX62390gUXjtXfsBpzH2mltAiTFTW2+y2Nafk8mVmfPOcKdDuFNPlMB3n1I\n\
        VHjHFVsJEf8Mypl1tPPDNEk0GBJbJpnJAHYeoGH5GYrk9+imH6fAMAoGCCqGSM49\n\
        BAMDA2gAMGUCMQDXjCT/Q/zDdKM8seS8/xazzHBzj9WjM6eLs7lel8KWqSVgrbeL\n\
        +4bXIQlf5oN+EKECMBPUo9/dSdDHzQWZmHdtMgcNkqbgtSWuxNyHZ0aWS61SJnSo\n\
        DC9c8OJvA+fSSrP4AA==\n\
        -----END CERTIFICATE-----\n";

    fn quotes_json(node_id: &str) -> String {
        let endorsements = crate::adapters::load::base64_encode(PEM.as_bytes());
        format!(
            r#"{{"quotes":[{{"node_id":"{node_id}","raw":"0a0b0c0d",
               "endorsements":"{endorsements}","uvm_endorsements":"0a0b"}}]}}"#
        )
    }

    fn nodes_json(node_id: &str) -> String {
        let pem = PEM.replace('\n', "\\n");
        format!(r#"{{"value":[{{"nodeId":"{node_id}","certificate":"{pem}"}}]}}"#)
    }

    #[test]
    fn quotes_and_certificates_are_joined_by_node_id() {
        let id = "a".repeat(64);
        let bundle = assemble(
            quotes_json(&id).as_bytes(),
            nodes_json(&id).as_bytes(),
            PEM.as_bytes(),
        )
        .expect("bundle");
        assert_eq!(bundle.nodes.len(), 1);
        assert_eq!(bundle.nodes[0].node_id, id);
        assert_eq!(bundle.nodes[0].snp_report, b"\n\x0b\x0c\r");
        assert_eq!(bundle.nodes[0].amd_endorsements.len(), 1);
        assert!(!bundle.nodes[0].certificate_pem.is_empty());
    }

    /// An attested node with no published certificate is refused, not skipped.
    ///
    /// Its report could not be bound to any key the service certified, so it
    /// would count towards coverage while contributing no binding at all —
    /// a quieter outcome than the ledger deserves.
    #[test]
    fn an_attested_node_with_no_certificate_is_refused() {
        let id = "b".repeat(64);
        let err = assemble(
            quotes_json(&id).as_bytes(),
            br#"{"value":[]}"#,
            PEM.as_bytes(),
        )
        .unwrap_err();
        assert!(err.contains("publishes no certificate"), "{err}");
    }

    #[test]
    fn a_ledger_reporting_no_nodes_is_refused() {
        let err = assemble(br#"{"quotes":[]}"#, br#"{"value":[]}"#, PEM.as_bytes()).unwrap_err();
        assert!(err.contains("no nodes"), "{err}");
    }

    #[test]
    fn a_repeated_node_is_refused_rather_than_counted_twice() {
        let id = "c".repeat(64);
        let endorsements = crate::adapters::load::base64_encode(PEM.as_bytes());
        let node = format!(
            r#"{{"node_id":"{id}","raw":"0a0b0c0d","endorsements":"{endorsements}","uvm_endorsements":"0a0b"}}"#
        );
        let both = format!(r#"{{"quotes":[{node},{node}]}}"#);
        let err =
            assemble(both.as_bytes(), nodes_json(&id).as_bytes(), PEM.as_bytes()).unwrap_err();
        assert!(err.contains("more than once"), "{err}");
    }
}
