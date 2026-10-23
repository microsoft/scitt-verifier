use crate::evidence::Evidence;
use tav_caci::synchronous as tav;

pub(crate) fn verify(evidence: &Evidence) -> Result<[u8; 32], String> {
    let chain: Vec<&[u8]> = evidence.chain.iter().map(Vec::as_slice).collect();
    let report = tav::verify_attestation(&evidence.report, &chain)
        .map_err(|e| format!("SNP attestation verification: {e:?}"))?;
    Ok(report.host_data)
}
