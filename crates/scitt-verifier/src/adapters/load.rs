//! Reading a saved evidence bundle from disk.
//!
//! The only filesystem code on the appraisal path, kept at the edge so that
//! [`acl`] stays free of I/O and an offline replay and a future live
//! run reach the appraiser through the same types. Two runs over the same
//! evidence must not be able to disagree because one of them read it from a
//! different place.
//!
//! The node set comes from a manifest, never from whatever files happen to be
//! in the directory. Globbing would make the assessed membership a property of
//! the directory listing, so a node could be excluded from the result by
//! deleting its files — silently, because a smaller ledger and a truncated
//! bundle look identical from inside. The manifest makes the claimed set
//! explicit, and `expectNodeCount` in the policy is what turns a claim that is
//! too small into a failure.
//!
//! Nothing here authenticates anything. A manifest is untrusted input: it can
//! name any node IDs and any collection time it likes, and neither is evidence.
//! Its digests, where present, detect a bundle that has been disturbed on
//! disk; they say nothing about whether its contents are genuine. Every
//! cryptographic binding is recomputed during appraisal.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use acl::{EvidenceBundle, NodeEvidence};
use serde::Deserialize;

/// The manifest file a bundle must carry.
const MANIFEST: &str = "snapshot.json";

/// The manifest version this build understands.
///
/// An exact match, not a minimum. A later version may change what a field
/// means, and reading it with these rules would appraise something other than
/// what was recorded.
const SUPPORTED_VERSION: u32 = 1;

/// Bounds on what a bundle directory may cost to read.
///
/// A saved bundle is untrusted input: the manifest names the files and this
/// build reads them, so without a ceiling a bundle decides how much memory
/// this process allocates. The limits are generous against real evidence — an
/// SNP report is 1184 bytes, an AMD chain a few kilobytes, a UVM endorsement
/// tens of kilobytes — and exist to refuse the absurd, not to constrain the
/// plausible. Exceeding one is an error, never a finding: a bundle too large
/// to read was not appraised and unacceptable, it was not appraised at all.
mod limits {
    /// The manifest is JSON parsed into memory before anything is validated.
    pub const MANIFEST_BYTES: u64 = 1 << 20;
    /// One file named by the manifest.
    pub const FILE_BYTES: u64 = 4 << 20;
    /// Every file in the bundle together, so many small files cost no more
    /// than one large one.
    pub const TOTAL_BYTES: u64 = 64 << 20;
    /// Enumerated nodes. A CCF service is a consortium, not a cloud region.
    pub const NODES: usize = 1024;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Manifest {
    version: u32,
    /// The ledger the evidence was collected from, as the collector recorded it.
    ledger: String,
    /// When the collector says it gathered this.
    ///
    /// Reported alongside the appraisal time and never used as an input.
    /// Unauthenticated bundle metadata: it does not establish freshness, and
    /// nothing in this build treats it as though it could.
    #[serde(default)]
    collected_at: Option<String>,
    /// The ledger's service identity certificate, if the bundle carries one.
    ///
    /// Optional because this build does not yet bind reports to a service
    /// identity. Requiring a file nothing reads would imply a check that is
    /// not happening.
    #[serde(default)]
    service_certificate: Option<String>,
    nodes: Vec<ManifestNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestNode {
    id: String,
    report: FileRef,
    amd_endorsements: FileRef,
    uvm_endorsement: FileRef,
    /// The node's own certificate, if the bundle carries one.
    #[serde(default)]
    certificate: Option<FileRef>,
}

/// A file in the bundle, optionally with the digest it had when captured.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FileRef {
    path: String,
    #[serde(default)]
    sha256: Option<String>,
}

/// What a bundle said about itself, for the record.
///
/// Kept separate from the evidence so that nothing on the appraisal path can
/// reach for it by accident. These are claims, not findings.
#[derive(Debug, Clone)]
pub struct BundleMetadata {
    pub ledger: String,
    pub collected_at: Option<String>,
    pub node_count: usize,
    /// Whether this run obtained the evidence itself.
    ///
    /// A saved bundle is a recording someone else made: its recorded ledger
    /// name and collection time are claims. Evidence this run fetched was
    /// observed, at a time this run knows, from a ledger this run
    /// authenticated. The difference does not change any check — it changes
    /// what the scope sentence may honestly say about them.
    pub observed: bool,
}

/// Read a bundle directory into memory.
pub fn load(dir: &Path) -> Result<(EvidenceBundle, BundleMetadata), String> {
    // Resolved once, so that every later containment check compares against a
    // real location rather than the spelling the caller used. Without this a
    // bundle reached through a symlinked directory would compare its files
    // against a root that does not exist on disk.
    let root = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut budget = Budget::new();

    let manifest_path = root.join(MANIFEST);
    let raw = read_capped(&manifest_path, limits::MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&raw)
        .map_err(|e| format!("{} is not a usable manifest: {e}", manifest_path.display()))?;

    if manifest.version != SUPPORTED_VERSION {
        return Err(format!(
            "{} declares manifest version {}, and this build understands only version {}. \
             Reading it with these rules could appraise something other than what was recorded.",
            manifest_path.display(),
            manifest.version,
            SUPPORTED_VERSION
        ));
    }
    if manifest.ledger.trim().is_empty() {
        return Err(format!("{}: ledger is empty", manifest_path.display()));
    }
    // Zero nodes is refused here as well as in the appraiser. Every rule about
    // agreement is vacuously true of an empty set, and a bundle that enumerates
    // nothing would otherwise travel some distance before anyone noticed.
    if manifest.nodes.is_empty() {
        return Err(format!(
            "{} enumerates no nodes; evidence about no node establishes nothing",
            manifest_path.display()
        ));
    }
    // Checked before any file is opened, because the cost of reading a bundle
    // is decided by this number and the manifest is untrusted.
    if manifest.nodes.len() > limits::NODES {
        return Err(format!(
            "{} enumerates {} nodes, and this build reads at most {}",
            manifest_path.display(),
            manifest.nodes.len(),
            limits::NODES
        ));
    }

    let mut seen = BTreeSet::new();
    for node in &manifest.nodes {
        if node.id.trim().is_empty() {
            return Err(format!(
                "{}: a node has an empty id",
                manifest_path.display()
            ));
        }
        // A repeated id would let one node's evidence be counted twice, which
        // turns a single agreeing node into unanimous agreement across a
        // ledger that was never assessed.
        if !seen.insert(node.id.clone()) {
            return Err(format!(
                "{}: node id {:?} appears more than once; one node's evidence must not be \
                 counted as several",
                manifest_path.display(),
                node.id
            ));
        }
    }

    let service_certificate_pem = match &manifest.service_certificate {
        Some(rel) => read_within(&root, rel, &mut budget)?,
        None => Vec::new(),
    };

    let mut nodes = Vec::with_capacity(manifest.nodes.len());
    for node in &manifest.nodes {
        let snp_report = read_ref(&root, &node.report, &node.id, "report", &mut budget)?;
        let amd_pem = read_ref(
            &root,
            &node.amd_endorsements,
            &node.id,
            "amdEndorsements",
            &mut budget,
        )?;
        let uvm_endorsement = read_ref(
            &root,
            &node.uvm_endorsement,
            &node.id,
            "uvmEndorsement",
            &mut budget,
        )?;
        let certificate_pem = match &node.certificate {
            Some(r) => read_ref(&root, r, &node.id, "certificate", &mut budget)?,
            None => Vec::new(),
        };

        // Converted here rather than in the appraiser so that the appraiser
        // receives certificates, not a file format. The order is preserved as
        // written: the verifier takes them positionally, and reordering them
        // to look tidy would surface as an invalid chain rather than as a
        // misread file.
        let pem = String::from_utf8(amd_pem)
            .map_err(|_| format!("node {}: the AMD endorsement file is not text PEM", node.id))?;
        let amd_endorsements = scitt_receipt::chain::parse_pem_certificates(&pem)
            .map_err(|e| format!("node {}: AMD endorsements: {e}", node.id))?;

        nodes.push(NodeEvidence {
            node_id: node.id.clone(),
            certificate_pem,
            snp_report,
            amd_endorsements,
            uvm_endorsement,
        });
    }

    let metadata = BundleMetadata {
        ledger: manifest.ledger,
        collected_at: manifest.collected_at,
        node_count: nodes.len(),
        observed: false,
    };
    Ok((
        EvidenceBundle {
            service_certificate_pem,
            nodes,
        },
        metadata,
    ))
}

/// Write a collected bundle to disk in the same form [`load`] reads.
///
/// Deliberately the same manifest and the same layout, so a saved copy of a
/// live run can be replayed later and reach the same appraisal. A copy that
/// could not be re-read would record that a run happened without recording
/// what it judged.
///
/// The digests are written for every file. They do not make the bundle
/// trustworthy — nothing signs the manifest — but they are what lets a later
/// replay say "this was disturbed" instead of appraising altered bytes.
pub fn save(dir: &Path, bundle: &EvidenceBundle, metadata: &BundleMetadata) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let write = |name: &str, bytes: &[u8]| -> Result<serde_json::Value, String> {
        let path = dir.join(name);
        std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(serde_json::json!({ "path": name, "sha256": hex(&scitt_receipt::sha256(bytes)) }))
    };

    let mut nodes = Vec::with_capacity(bundle.nodes.len());
    for node in &bundle.nodes {
        // The node id is a ledger-supplied string that becomes a filename, so
        // it is reduced to characters that cannot escape the directory or
        // mean something to a shell. Real CCF node ids are hex; anything else
        // would not be one, and quietly writing it as a path would be the
        // bundle deciding where this run writes.
        let stem: String = node
            .node_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(64)
            .collect();
        if stem.is_empty() {
            return Err(format!(
                "node id {:?} contains nothing usable as a filename",
                node.node_id
            ));
        }

        let mut entry = serde_json::Map::new();
        entry.insert("id".into(), node.node_id.clone().into());
        entry.insert(
            "report".into(),
            write(&format!("{stem}-report.bin"), &node.snp_report)?,
        );

        // Re-encoded as one PEM file in the order the appraiser took them,
        // because that order is load-bearing and a replay must see the same.
        let mut amd = String::new();
        for der in &node.amd_endorsements {
            amd.push_str(&pem_block(der));
        }
        entry.insert(
            "amdEndorsements".into(),
            write(&format!("{stem}-amd.pem"), amd.as_bytes())?,
        );
        entry.insert(
            "uvmEndorsement".into(),
            write(&format!("{stem}-uvm.cose"), &node.uvm_endorsement)?,
        );
        if !node.certificate_pem.is_empty() {
            entry.insert(
                "certificate".into(),
                write(&format!("{stem}-node.pem"), &node.certificate_pem)?,
            );
        }
        nodes.push(serde_json::Value::Object(entry));
    }

    let mut manifest = serde_json::Map::new();
    manifest.insert("version".into(), SUPPORTED_VERSION.into());
    manifest.insert("ledger".into(), metadata.ledger.clone().into());
    if let Some(at) = &metadata.collected_at {
        manifest.insert("collectedAt".into(), at.clone().into());
    }
    if !bundle.service_certificate_pem.is_empty() {
        std::fs::write(dir.join("service.pem"), &bundle.service_certificate_pem)
            .map_err(|e| format!("{}: {e}", dir.join("service.pem").display()))?;
        manifest.insert("serviceCertificate".into(), "service.pem".into());
    }
    manifest.insert("nodes".into(), serde_json::Value::Array(nodes));

    let text = serde_json::to_string_pretty(&serde_json::Value::Object(manifest))
        .map_err(|e| format!("the manifest could not be written: {e}"))?;
    let path = dir.join(MANIFEST);
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Wrap one DER certificate as a PEM block.
pub fn pem_block(der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

pub fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn read_ref(
    root: &Path,
    file: &FileRef,
    node_id: &str,
    field: &str,
    budget: &mut Budget,
) -> Result<Vec<u8>, String> {
    let bytes = read_within(root, &file.path, budget)
        .map_err(|e| format!("node {node_id}, {field}: {e}"))?;
    if let Some(expected) = &file.sha256 {
        let actual = hex(&scitt_receipt::sha256(&bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            // Not a finding about the ledger: the file on disk is not the file
            // that was captured, so this run has nothing to say about the node.
            return Err(format!(
                "node {node_id}, {field}: {} has digest {actual}, but the manifest recorded \
                 {expected}. The bundle has been disturbed since capture.",
                file.path
            ));
        }
    }
    Ok(bytes)
}

/// What is left of the bundle-wide read allowance.
struct Budget {
    remaining: u64,
}

impl Budget {
    fn new() -> Self {
        Self {
            remaining: limits::TOTAL_BYTES,
        }
    }

    fn spend(&mut self, bytes: u64, path: &Path) -> Result<(), String> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(|| {
            format!(
                "reading {} would exceed the {} byte bundle limit",
                path.display(),
                limits::TOTAL_BYTES
            )
        })?;
        Ok(())
    }
}

/// Read one file, refusing one larger than `max`.
///
/// The length is taken from the open handle rather than from a prior `metadata`
/// call, and the read is capped regardless of what the length said: a file can
/// grow between the two, and on some platforms a length is a hint. The cap is
/// what bounds the allocation; the length check only avoids reading megabytes
/// to discover that.
fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    if len > max {
        return Err(format!(
            "{} is {len} bytes, and this build reads at most {max}",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(len.min(max) as usize);
    let read = file
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if read as u64 > max {
        return Err(format!(
            "{} is larger than the {max} bytes this build reads",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Read a manifest-named file, refusing any path that leaves the bundle.
///
/// A manifest is untrusted input. Without this, a bundle could name
/// `../../.ssh/id_rsa` and have its contents read, or an absolute path
/// anywhere on the machine.
///
/// The lexical component check is not sufficient on its own, and is kept only
/// because it names the problem precisely: `node/../../secret` is refused for
/// what it says rather than for where it landed. A path made entirely of
/// ordinary components can still leave the directory by following a symlink,
/// so where it resolves to is checked as well — that check is the one that
/// holds, and it is made before the bytes are read.
fn read_within(root: &Path, relative: &str, budget: &mut Budget) -> Result<Vec<u8>, String> {
    let candidate = Path::new(relative);
    // `has_root` as well as `is_absolute`, because they disagree across
    // platforms: `/etc/passwd` is absolute on Unix but merely rooted on
    // Windows, where a path needs a drive prefix to be absolute. A bundle is
    // meant to be portable, so the same manifest must be refused for the same
    // stated reason wherever it is read.
    if candidate.is_absolute() || candidate.has_root() {
        return Err(format!(
            "{relative:?} is an absolute path; a manifest may only name files inside the bundle"
        ));
    }
    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(format!(
                    "{relative:?} leaves the bundle directory; a manifest may only name files \
                     inside it"
                ))
            }
        }
    }
    let path: PathBuf = root.join(candidate);
    let resolved = std::fs::canonicalize(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !resolved.starts_with(root) {
        return Err(format!(
            "{relative:?} resolves to {}, which is outside the bundle directory; a link may \
             not take a manifest somewhere its own path could not",
            resolved.display()
        ));
    }
    let bytes = read_capped(&resolved, limits::FILE_BYTES)?;
    budget.spend(bytes.len() as u64, &resolved)?;
    Ok(bytes)
}

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
    use std::fs;

    fn write(dir: &Path, name: &str, bytes: &[u8]) {
        fs::write(dir.join(name), bytes).unwrap();
    }

    /// A real, parseable certificate.
    ///
    /// Not a placeholder blob: the loader converts the PEM through the same
    /// parser the rest of the tool uses, which validates the DER. A fake would
    /// exercise the error path in every test that was meant to exercise the
    /// success one. Self-signed over a throwaway P-384 key; nothing verifies
    /// against it and nothing needs to.
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

    fn bundle(
        manifest: &str,
    ) -> (
        tempdir::Dir,
        Result<(EvidenceBundle, BundleMetadata), String>,
    ) {
        let dir = tempdir::Dir::new();
        write(dir.path(), MANIFEST, manifest.as_bytes());
        write(dir.path(), "n1-report.bin", b"report");
        write(dir.path(), "n1-amd.pem", PEM.as_bytes());
        write(dir.path(), "n1-uvm.cose", b"uvm");
        let got = load(dir.path());
        (dir, got)
    }

    fn one_node() -> String {
        r#"{
          "version": 1,
          "ledger": "l.example",
          "nodes": [
            { "id": "n1",
              "report": { "path": "n1-report.bin" },
              "amdEndorsements": { "path": "n1-amd.pem" },
              "uvmEndorsement": { "path": "n1-uvm.cose" } }
          ]
        }"#
        .to_string()
    }

    #[test]
    fn a_well_formed_bundle_loads() {
        let (_d, got) = bundle(&one_node());
        let (evidence, meta) = got.expect("bundle");
        assert_eq!(evidence.nodes.len(), 1);
        assert_eq!(evidence.nodes[0].node_id, "n1");
        assert_eq!(evidence.nodes[0].snp_report, b"report");
        assert_eq!(evidence.nodes[0].amd_endorsements.len(), 1);
        assert_eq!(meta.ledger, "l.example");
        assert_eq!(meta.node_count, 1);
    }

    /// The node set is the manifest's, not the directory's.
    ///
    /// Files nobody named are not evidence. If the listing decided membership,
    /// a bundle could be made to look unanimous by deleting the node that
    /// disagreed.
    #[test]
    fn files_the_manifest_does_not_name_are_not_assessed() {
        let dir = tempdir::Dir::new();
        write(dir.path(), MANIFEST, one_node().as_bytes());
        write(dir.path(), "n1-report.bin", b"report");
        write(dir.path(), "n1-amd.pem", PEM.as_bytes());
        write(dir.path(), "n1-uvm.cose", b"uvm");
        // A second node's files, present but unlisted.
        write(dir.path(), "n2-report.bin", b"other");
        write(dir.path(), "n2-amd.pem", PEM.as_bytes());
        write(dir.path(), "n2-uvm.cose", b"other");

        let (evidence, meta) = load(dir.path()).expect("bundle");
        assert_eq!(evidence.nodes.len(), 1);
        assert_eq!(meta.node_count, 1);
    }

    #[test]
    fn a_manifest_naming_a_path_outside_the_bundle_is_refused() {
        let manifest = one_node().replace(r#""n1-report.bin""#, r#""../secret""#);
        let (_d, got) = bundle(&manifest);
        let err = got.unwrap_err();
        assert!(err.contains("leaves the bundle"), "{err}");
    }

    #[test]
    fn a_manifest_naming_an_absolute_path_is_refused() {
        let manifest = one_node().replace(r#""n1-report.bin""#, r#""/etc/passwd""#);
        let (_d, got) = bundle(&manifest);
        let err = got.unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    /// A path made only of ordinary components can still leave the directory.
    ///
    /// The lexical check passes `escape.bin` without complaint; where it
    /// resolves to is the question. Skipped where the platform will not let
    /// this process create a symlink at all — on Windows that needs developer
    /// mode or elevation — because a test that cannot build the attack cannot
    /// report anything about the defence either way.
    #[test]
    fn a_link_that_leaves_the_bundle_is_refused() {
        let outside = tempdir::Dir::new();
        write(outside.path(), "secret", b"not yours");

        let dir = tempdir::Dir::new();
        let manifest = one_node().replace(r#""n1-report.bin""#, r#""escape.bin""#);
        write(dir.path(), MANIFEST, manifest.as_bytes());
        write(dir.path(), "n1-amd.pem", PEM.as_bytes());
        write(dir.path(), "n1-uvm.cose", b"uvm");

        let target = outside.path().join("secret");
        let link = dir.path().join("escape.bin");
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&target, &link).is_ok();
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&target, &link).is_ok();
        if !made {
            return;
        }

        let err = load(dir.path()).unwrap_err();
        assert!(err.contains("outside the bundle"), "{err}");
    }

    /// The manifest decides how much this process reads, and it is untrusted.
    #[test]
    fn a_file_larger_than_the_limit_is_refused() {
        let dir = tempdir::Dir::new();
        write(dir.path(), MANIFEST, one_node().as_bytes());
        write(
            dir.path(),
            "n1-report.bin",
            &vec![0u8; (limits::FILE_BYTES + 1) as usize],
        );
        write(dir.path(), "n1-amd.pem", PEM.as_bytes());
        write(dir.path(), "n1-uvm.cose", b"uvm");
        let err = load(dir.path()).unwrap_err();
        assert!(err.contains("reads at most"), "{err}");
    }

    /// Refused before a single file is opened: the count is what decides the
    /// cost, so it is checked where it is read.
    #[test]
    fn more_nodes_than_the_limit_are_refused() {
        let entries: Vec<String> = (0..=limits::NODES)
            .map(|i| {
                format!(
                    r#"{{ "id": "n{i}", "report": {{ "path": "n1-report.bin" }},
                       "amdEndorsements": {{ "path": "n1-amd.pem" }},
                       "uvmEndorsement": {{ "path": "n1-uvm.cose" }} }}"#
                )
            })
            .collect();
        let manifest = format!(
            r#"{{ "version": 1, "ledger": "l.example", "nodes": [{}] }}"#,
            entries.join(",")
        );
        let (_d, got) = bundle(&manifest);
        let err = got.unwrap_err();
        assert!(err.contains("reads at most"), "{err}");
    }

    /// The manifest itself is parsed into memory, so it is bounded too.
    #[test]
    fn a_manifest_larger_than_the_limit_is_refused() {
        let dir = tempdir::Dir::new();
        write(
            dir.path(),
            MANIFEST,
            &vec![b' '; (limits::MANIFEST_BYTES + 1) as usize],
        );
        let err = load(dir.path()).unwrap_err();
        assert!(err.contains("reads at most"), "{err}");
    }

    #[test]
    fn a_repeated_node_id_is_refused_rather_than_counted_twice() {
        let manifest = one_node().replace(
            r#""nodes": ["#,
            r#""nodes": [
            { "id": "n1",
              "report": { "path": "n1-report.bin" },
              "amdEndorsements": { "path": "n1-amd.pem" },
              "uvmEndorsement": { "path": "n1-uvm.cose" } },"#,
        );
        let (_d, got) = bundle(&manifest);
        let err = got.unwrap_err();
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn an_empty_node_list_is_refused() {
        let manifest = r#"{ "version": 1, "ledger": "l", "nodes": [] }"#;
        let (_d, got) = bundle(manifest);
        let err = got.unwrap_err();
        assert!(err.contains("no nodes"), "{err}");
    }

    #[test]
    fn a_future_manifest_version_is_refused_rather_than_guessed_at() {
        let manifest = one_node().replace(r#""version": 1"#, r#""version": 2"#);
        let (_d, got) = bundle(&manifest);
        let err = got.unwrap_err();
        assert!(err.contains("version 2"), "{err}");
    }

    #[test]
    fn a_recorded_digest_that_no_longer_matches_is_refused() {
        let manifest = one_node().replace(
            r#"{ "path": "n1-report.bin" }"#,
            r#"{ "path": "n1-report.bin", "sha256": "00".repeat }"#,
        );
        // Build the bad-digest manifest without string gymnastics.
        let manifest = manifest.replace(r#""00".repeat"#, &format!("\"{}\"", "0".repeat(64)));
        let (_d, got) = bundle(&manifest);
        let err = got.unwrap_err();
        assert!(err.contains("disturbed since capture"), "{err}");
    }

    #[test]
    fn a_matching_recorded_digest_is_accepted() {
        let digest = hex(&scitt_receipt::sha256(b"report"));
        let manifest = one_node().replace(
            r#"{ "path": "n1-report.bin" }"#,
            &format!(r#"{{ "path": "n1-report.bin", "sha256": "{digest}" }}"#),
        );
        let (_d, got) = bundle(&manifest);
        assert!(got.is_ok(), "{:?}", got.err());
    }

    #[test]
    fn an_unknown_manifest_member_is_refused() {
        let manifest = one_node().replace(r#""version": 1"#, r#""version": 1, "trusted": true"#);
        let (_d, got) = bundle(&manifest);
        let err = got.unwrap_err();
        assert!(err.contains("trusted"), "{err}");
    }

    /// A saved copy of a live run must appraise to the same evidence.
    ///
    /// The point of `--save-evidence` is that a verdict can be re-examined
    /// later. A copy that did not load, or loaded as something else, would
    /// record that a run happened without recording what it judged.
    #[test]
    fn a_saved_bundle_reloads_to_the_same_evidence() {
        let der = scitt_receipt::chain::parse_pem_certificates(PEM).unwrap();
        let bundle = EvidenceBundle {
            service_certificate_pem: PEM.as_bytes().to_vec(),
            nodes: vec![NodeEvidence {
                node_id: "a".repeat(64),
                certificate_pem: PEM.as_bytes().to_vec(),
                snp_report: b"report".to_vec(),
                amd_endorsements: der.clone(),
                uvm_endorsement: b"uvm".to_vec(),
            }],
        };
        let meta = BundleMetadata {
            ledger: "l.example".into(),
            collected_at: Some("2026-01-01T00:00:00Z".into()),
            node_count: 1,
            observed: true,
        };

        let dir = tempdir::Dir::new();
        save(dir.path(), &bundle, &meta).expect("save");
        let (again, meta_again) = load(dir.path()).expect("reload");

        assert_eq!(again.nodes.len(), 1);
        assert_eq!(again.nodes[0].node_id, bundle.nodes[0].node_id);
        assert_eq!(again.nodes[0].snp_report, bundle.nodes[0].snp_report);
        assert_eq!(
            again.nodes[0].uvm_endorsement,
            bundle.nodes[0].uvm_endorsement
        );
        assert_eq!(again.nodes[0].amd_endorsements, der);
        assert_eq!(
            again.service_certificate_pem,
            bundle.service_certificate_pem
        );
        assert_eq!(meta_again.ledger, "l.example");
        assert_eq!(
            meta_again.collected_at.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        // A reloaded bundle is a recording, whatever it was when collected.
        assert!(!meta_again.observed);
    }

    /// A node id is ledger-supplied and becomes a filename.
    #[test]
    fn a_node_id_cannot_choose_where_the_save_writes() {
        let bundle = EvidenceBundle {
            service_certificate_pem: Vec::new(),
            nodes: vec![NodeEvidence {
                node_id: "../../etc".into(),
                certificate_pem: Vec::new(),
                snp_report: b"r".to_vec(),
                amd_endorsements: Vec::new(),
                uvm_endorsement: b"u".to_vec(),
            }],
        };
        let meta = BundleMetadata {
            ledger: "l".into(),
            collected_at: None,
            node_count: 1,
            observed: true,
        };
        let dir = tempdir::Dir::new();
        save(dir.path(), &bundle, &meta).expect("save");
        // The separators are gone, so nothing was written outside the bundle.
        assert!(dir.path().join("etc-report.bin").exists());
    }

    /// A tiny scratch directory, removed on drop.
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let path =
                    std::env::temp_dir().join(format!("scitt-evidence-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
