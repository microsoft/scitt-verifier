//! The evidence this crate appraises, as types rather than files.
//!
//! Nothing here opens a path. A caller reads the bytes — from a saved bundle
//! on disk today, from a live ledger later — and hands them over. That keeps
//! the appraisal identical in both cases, which is the point: an offline
//! replay and a live run must not be able to reach different conclusions about
//! the same evidence.

/// Evidence gathered from one ledger, covering one membership snapshot.
#[derive(Debug, Clone)]
pub struct EvidenceBundle {
    /// The ledger's service identity certificate, in PEM form.
    ///
    /// The root of the binding chain: it signs each node certificate, and the
    /// node certificate's key is what a report's `REPORT_DATA` commits to. It
    /// must have been obtained from a source the consumer independently
    /// trusts, not from the ledger being assessed.
    pub service_certificate_pem: Vec<u8>,
    /// One entry per node in the assessed snapshot.
    pub nodes: Vec<NodeEvidence>,
}

/// One node's evidence.
#[derive(Debug, Clone)]
pub struct NodeEvidence {
    /// The node identifier as the ledger reported it.
    ///
    /// Treated as a label for reporting, never as proof of anything. The
    /// binding that matters is computed from the certificate and the report.
    pub node_id: String,
    /// The node's certificate, in PEM form.
    pub certificate_pem: Vec<u8>,
    /// The raw SEV-SNP attestation report.
    pub snp_report: Vec<u8>,
    /// AMD endorsement certificates, ordered `[vcek, ask, ark]`.
    ///
    /// The order is load-bearing: the verifier takes them positionally, so a
    /// wrong order surfaces as an invalid chain rather than as a bad argument.
    pub amd_endorsements: Vec<Vec<u8>>,
    /// The UVM endorsement, as a COSE_Sign1 document.
    pub uvm_endorsement: Vec<u8>,
}
