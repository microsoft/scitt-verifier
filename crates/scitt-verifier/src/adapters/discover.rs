//! Finding the statement a ledger's nodes say describes their build.
//!
//! A live appraisal asks whether the target's nodes enforce the policy a
//! statement embeds. Supplying that statement by hand means the operator has to
//! know which build the target runs, which is the thing they are trying to
//! find out. The nodes already say: each records a `buildEvidenceUrl` in its
//! node data.
//!
//! That value chooses the statement and is trusted for nothing else. It is
//! served over TLS pinned to the target's identity, but it is node data, not
//! attestation: no report covers it. So the URL is reduced to an issuer and a
//! transaction id, the issuer must be one the policy already accepts receipts
//! from, and the fetched bytes are then verified and appraised exactly as a
//! file would be. A target that names the wrong statement gets a failed
//! verification or a failed appraisal, never a pass it did not earn.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use scitt_network::acl::StatementStep;
use serde::Deserialize;

use crate::outcome::StatementSource;
use crate::progress::{Event, Sink, Stage, State};

/// Why no statement was obtained, and whose problem that is.
pub struct Failure {
    /// The run's configuration cannot work, as opposed to the target not
    /// supplying what it needed to.
    pub usage: bool,
    pub message: String,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            usage: true,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            usage: false,
            message: message.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GovNode {
    node_id: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    node_data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GovNodes {
    value: Vec<GovNode>,
    #[serde(default)]
    next_link: Option<String>,
}

/// Find, fetch and optionally save the statement the target's nodes name.
///
/// Returns the statement bytes and how they were obtained. Nothing here
/// verifies them; that is the caller's job, done the same way for every
/// statement whatever its origin.
pub fn discover(
    target: &str,
    allowlist: Option<&[String]>,
    save_to: Option<&Path>,
    progress: &mut dyn Sink,
) -> Result<(Vec<u8>, StatementSource), Failure> {
    // Refused before any request: without an allowlist there is no service
    // this run may fetch a statement from, whatever the nodes name.
    let Some(allowlist) = allowlist else {
        return Err(Failure::usage(
            "finding the statement requires an assertions.issuer allowlist in the policy, so \
             that the transparency service the target names is one you already accept",
        ));
    };

    let deadline = Instant::now() + scitt_network::limits::TOTAL_DEADLINE;
    progress.emit(Event::stage(
        Stage::Inputs,
        State::Started,
        format!("Reading node data from {target} to find the statement for its build..."),
    ));
    let nodes = scitt_network::acl::fetch_nodes(target, deadline).map_err(|e| {
        let message = format!("could not read the node list from {target}: {e}");
        if e.diagnostic.is_configuration() {
            Failure::usage(message)
        } else {
            Failure::unavailable(message)
        }
    })?;
    let (advertised_url, trusted_nodes) = advertised(&nodes).map_err(Failure::unavailable)?;
    progress.emit(Event::stage(
        Stage::Inputs,
        State::Done,
        format!("All {trusted_nodes} trusted node(s) name {advertised_url}"),
    ));

    let (issuer, transaction_id) = locate(&advertised_url, allowlist)?;
    progress.emit(Event::stage(
        Stage::Inputs,
        State::Started,
        format!("Fetching statement {transaction_id} from {issuer}..."),
    ));
    let fetched =
        scitt_network::acl::fetch_statement(&issuer, &transaction_id, deadline, &mut |step| {
            if let StatementStep::NotYetAvailable { attempt, retry_in } = step {
                progress.emit(Event::stage(
                    Stage::Inputs,
                    State::Started,
                    format!(
                        "{issuer} has not loaded the entry yet (attempt {attempt}); asking again \
                         in {}s...",
                        retry_in.as_secs()
                    ),
                ));
            }
        })
        .map_err(|e| {
            Failure::unavailable(format!(
                "could not fetch the statement the target names from {issuer}: {e}"
            ))
        })?;

    let sha256 = hex(&scitt_receipt::sha256(&fetched.bytes));
    if let Some(dir) = save_to {
        // Saved before verification, so a statement that then fails is still
        // on disk to be examined; that is when a copy matters most.
        let path = dir.join("statement.cose");
        std::fs::create_dir_all(dir)
            .and_then(|()| std::fs::write(&path, &fetched.bytes))
            .map_err(|e| {
                Failure::unavailable(format!(
                    "the fetched statement could not be saved to {}: {e}",
                    path.display()
                ))
            })?;
    }
    progress.emit(Event::stage(
        Stage::Inputs,
        State::Done,
        format!(
            "Fetched {} bytes (sha256 {sha256}) in {} attempt(s)",
            fetched.bytes.len(),
            fetched.attempts
        ),
    ));

    let source = StatementSource {
        target: target.to_string(),
        advertised_url,
        url: fetched.url,
        issuer,
        transaction_id,
        trusted_nodes,
        sha256,
        size: fetched.bytes.len(),
        attempts: fetched.attempts,
        fetched_at: crate::wall_clock(),
    };
    Ok((fetched.bytes, source))
}

/// The one location every trusted node names, and how many nodes that is.
///
/// Agreement is required rather than a majority taken. During an upgrade the
/// nodes run different builds; picking one statement would appraise every node
/// against it and report the others as failures of a build they never claimed
/// to run. A node naming nothing is likewise a stop: there is no statement it
/// could be appraised against.
fn advertised(nodes_body: &[u8]) -> Result<(String, usize), String> {
    let nodes: GovNodes = serde_json::from_slice(nodes_body)
        .map_err(|e| format!("the target's node list could not be read: {e}"))?;
    // A later page could hold a node that names something else.
    if nodes.next_link.is_some() {
        return Err(
            "the target's node list is paged, so not every node's statement could be compared"
                .into(),
        );
    }
    let trusted: Vec<&GovNode> = nodes
        .value
        .iter()
        .filter(|node| node.status.as_deref() == Some("Trusted"))
        .collect();
    if trusted.is_empty() {
        return Err("the target reported no trusted nodes".into());
    }
    if trusted.len() > scitt_network::limits::MAX_NODES {
        return Err(format!(
            "the target reported {} trusted nodes, above the {} this build will appraise",
            trusted.len(),
            scitt_network::limits::MAX_NODES
        ));
    }

    let mut named = BTreeSet::new();
    for node in &trusted {
        let url = node
            .node_data
            .as_ref()
            .and_then(|data| data.get("buildEvidenceUrl"))
            .and_then(|url| url.as_str());
        match url {
            Some(url) if !url.is_empty() => {
                named.insert(url.to_string());
            }
            _ => {
                return Err(format!(
                    "trusted node {} names no buildEvidenceUrl in its node data; pass the \
                     statement with --statement",
                    node.node_id
                ))
            }
        }
    }
    let mut named = named.into_iter();
    match (named.next(), named.next()) {
        (Some(url), None) => Ok((url, trusted.len())),
        (Some(first), Some(second)) => Err(format!(
            "the target's trusted nodes name {} different statements (including {first} and \
             {second}), as during an upgrade; pass the one to appraise with --statement",
            2 + named.count()
        )),
        (None, _) => unreachable!("every trusted node named a location"),
    }
}

/// Reduce an advertised location to the issuer and transaction id it may choose.
///
/// Only one shape is accepted. Anything else — another scheme, a port,
/// credentials, a query — would be the target choosing more than which entry
/// to fetch.
fn locate(url: &str, allowlist: &[String]) -> Result<(String, String), Failure> {
    let refuse = |why: &str| {
        Failure::unavailable(format!(
            "the target names {url}, which this build will not fetch: {why}"
        ))
    };
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| refuse("it is not an https URL"))?;
    let (host, path) = rest
        .split_once('/')
        .ok_or_else(|| refuse("it has no path"))?;
    let transaction_id = path
        .strip_prefix("entries/")
        .and_then(|p| p.strip_suffix("/statement"))
        .ok_or_else(|| refuse("its path is not /entries/<transaction id>/statement"))?;
    scitt_network::validate_host(host).map_err(|e| refuse(&e.detail))?;
    scitt_network::provider::validate_transaction_id(transaction_id)
        .map_err(|e| refuse(&e.detail))?;
    if !allowlist.iter().any(|allowed| allowed == host) {
        return Err(Failure::unavailable(format!(
            "the target names a statement on {host}, which is not in the policy's \
             assertions.issuer allowlist; add it if you accept receipts from that service"
        )));
    }
    Ok((host.to_string(), transaction_id.to_string()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str =
        "https://esrp-cts-cp.confidential-ledger.azure.com/entries/1225.551634/statement";
    const ISSUER: &str = "esrp-cts-cp.confidential-ledger.azure.com";

    fn node(id: &str, status: &str, url: Option<&str>) -> serde_json::Value {
        let data = match url {
            Some(url) => serde_json::json!({ "buildEvidenceUrl": url }),
            None => serde_json::json!({}),
        };
        serde_json::json!({ "nodeId": id, "status": status, "nodeData": data })
    }

    fn body(nodes: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "value": nodes })).unwrap()
    }

    #[test]
    fn trusted_nodes_that_agree_name_the_statement() {
        let nodes = body(vec![
            node("a", "Trusted", Some(URL)),
            node("b", "Trusted", Some(URL)),
            // A retired node's older build is not what the service runs now.
            node(
                "c",
                "Retired",
                Some("https://elsewhere/entries/1.1/statement"),
            ),
        ]);
        assert_eq!(advertised(&nodes).unwrap(), (URL.to_string(), 2));
    }

    #[test]
    fn nodes_naming_different_statements_stop_the_run() {
        let other = URL.replace("551634", "551635");
        let nodes = body(vec![
            node("a", "Trusted", Some(URL)),
            node("b", "Trusted", Some(&other)),
        ]);
        let err = advertised(&nodes).unwrap_err();
        assert!(err.contains("2 different statements"), "{err}");
    }

    #[test]
    fn a_trusted_node_naming_nothing_stops_the_run() {
        let nodes = body(vec![
            node("a", "Trusted", Some(URL)),
            node("b", "Trusted", None),
        ]);
        let err = advertised(&nodes).unwrap_err();
        assert!(
            err.contains("trusted node b names no buildEvidenceUrl"),
            "{err}"
        );
    }

    #[test]
    fn no_trusted_node_or_a_paged_list_stops_the_run() {
        let err = advertised(&body(vec![node("a", "Pending", Some(URL))])).unwrap_err();
        assert!(err.contains("no trusted nodes"), "{err}");
        let paged = serde_json::to_vec(&serde_json::json!({
            "value": [node("a", "Trusted", Some(URL))],
            "nextLink": "/gov/service/nodes?page=2",
        }))
        .unwrap();
        assert!(advertised(&paged).unwrap_err().contains("paged"));
    }

    #[test]
    fn an_allowlisted_location_reduces_to_issuer_and_transaction_id() {
        let (issuer, txid) = locate(URL, &[ISSUER.to_string()]).ok().unwrap();
        assert_eq!((issuer.as_str(), txid.as_str()), (ISSUER, "1225.551634"));
    }

    #[test]
    fn a_location_off_the_allowlist_is_refused() {
        let err = locate(URL, &["other.confidential-ledger.azure.com".to_string()])
            .err()
            .unwrap();
        assert!(!err.usage);
        assert!(
            err.message.contains("not in the policy's"),
            "{}",
            err.message
        );
    }

    /// Each could send the request somewhere, or ask for something, other than
    /// the one entry the URL appears to name.
    #[test]
    fn locations_of_any_other_shape_are_refused() {
        let allow = [ISSUER.to_string()];
        for bad in [
            "http://esrp-cts-cp.confidential-ledger.azure.com/entries/1.2/statement",
            "https://esrp-cts-cp.confidential-ledger.azure.com:8443/entries/1.2/statement",
            "https://user@esrp-cts-cp.confidential-ledger.azure.com/entries/1.2/statement",
            "https://esrp-cts-cp.confidential-ledger.azure.com/entries/1.2/statement?x=1",
            "https://esrp-cts-cp.confidential-ledger.azure.com/entries/1.2/receipt",
            "https://esrp-cts-cp.confidential-ledger.azure.com/entries/../keys/statement",
            "https://esrp-cts-cp.confidential-ledger.azure.com/entries/1.2/x/statement",
            "https://ESRP-CTS-CP.confidential-ledger.azure.com/entries/1.2/statement",
            "https://esrp-cts-cp.confidential-ledger.azure.com",
        ] {
            assert!(locate(bad, &allow).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn without_an_allowlist_nothing_is_requested() {
        let mut progress = crate::progress::Noop;
        let err = discover(
            "target.confidential-ledger.azure.com",
            None,
            None,
            &mut progress,
        )
        .err()
        .unwrap();
        assert!(err.usage);
    }
}
