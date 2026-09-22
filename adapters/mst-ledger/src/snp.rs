//! Staged SNP and UVM verification for one node.
//!
//! Three calls, in a fixed order, because the attestation library requires it:
//! the report and its AMD collateral are authenticated first, the UVM
//! endorsement is authenticated independently, and only then are the two
//! appraised together against the consumer's requirements.
//!
//! Two things the library does *not* do are done here, and both are the kind
//! of gap that reports success rather than failure if left alone:
//!
//! 1. **The EKU predicate is enforced here.** The library's `did:x509` handling
//!    pins the chain root and discards everything after `::`, so a DID that
//!    names `::eku:…` is parsed and then not checked. A root pin alone does
//!    not distinguish signing roles, and the UVM endorsement was observed
//!    sharing a root with statement signing — differing *only* in EKU. So a
//!    root-only check would accept a statement-signing certificate as a UVM
//!    endorsement.
//! 2. **An empty TCB floor is refused rather than passed.** The library skips
//!    the TCB comparison entirely when the floor is empty, so an unconfigured
//!    floor silently accepts any TCB. A consumer who configured nothing must
//!    not get a pass that looks like one who configured a floor and met it.

use crate::bundle::NodeEvidence;
use crate::Requirements;
use tav_caci::snp::report::TcbVersionRaw;
use tav_caci::snp::Cpuid;
use tav_caci::{synchronous as tav, AciError};

/// The AMD endorsement chain length the library requires, as `[vcek, ask, ark]`.
const AMD_ENDORSEMENT_COUNT: usize = 3;

/// What one node's evidence established.
///
/// Reaching this struct means the report's signature, its AMD chain, and the
/// UVM endorsement all authenticated. It does *not* mean the node met the
/// consumer's requirements — see [`Self::requirement_failure`]. The two are
/// separated because the fields below are trustworthy either way: they came
/// out of a report whose signature verified, so they can be reported even when
/// the node is being rejected. Collapsing the two would throw away the
/// authenticated `REPORT_DATA` and `HOST_DATA` of every rejected node, and
/// leave an operator told only that "something did not authenticate" when the
/// truth is "these are certainly your ledger's nodes, and they are enforcing a
/// different policy".
#[derive(Debug)]
pub(crate) struct VerifiedNode {
    /// The authenticated policy digest the node reports it is enforcing.
    pub host_data: [u8; 32],
    /// The authenticated launch measurement.
    pub measurement: [u8; 48],
    /// The authenticated `REPORT_DATA`, whose first 32 bytes CCF sets to
    /// `sha256(SubjectPublicKeyInfo)` of the node's own key.
    ///
    /// Carried out of verification rather than re-read from the raw report so
    /// that the bytes the identity binding compares are provably the bytes
    /// whose signature and AMD chain verified.
    pub report_data: [u8; 64],
    /// Why the node failed the consumer's requirements, if it did.
    ///
    /// `None` means every configured requirement was met.
    pub requirement_failure: Option<String>,
}

/// Run the three staged verifications for one node.
///
/// `policy_digest` is passed through to the library so that it, too, enforces
/// the `HOST_DATA` comparison. The caller compares separately for *reporting*
/// — the library collapses every requirement failure into one opaque variant,
/// and telling a policy mismatch from a TCB shortfall by matching on its
/// message would be guesswork. Enforcement is therefore duplicated on purpose:
/// the library fails closed, and this crate explains why.
pub(crate) fn verify_node(
    evidence: &NodeEvidence,
    policy_digest: &[u8; 32],
    requirements: &Requirements,
) -> Result<VerifiedNode, String> {
    // An empty floor is the library's skip-everything case; refuse it before
    // any evidence is looked at, so the refusal cannot be mistaken for a
    // finding about this node.
    let minimum_tcb = tcb_floor(requirements)?;

    if evidence.amd_endorsements.len() != AMD_ENDORSEMENT_COUNT {
        return Err(format!(
            "expected {AMD_ENDORSEMENT_COUNT} AMD endorsement certificates ordered \
             [vcek, ask, ark], got {}",
            evidence.amd_endorsements.len()
        ));
    }
    let endorsements: Vec<&[u8]> = evidence
        .amd_endorsements
        .iter()
        .map(|c| c.as_slice())
        .collect();

    // Stage 1: the report signature, the vcek -> ask -> ark chain, and the
    // report's TCB against the VCEK.
    let report = tav::verify_attestation(&evidence.snp_report, &endorsements)
        .map_err(|e| format!("SNP attestation did not verify: {}", describe(&e)))?;

    // Stage 2: the UVM endorsement's own signature and chain, anchored to the
    // did:x509 the consumer configured.
    let uvm = tav::verify_uvm_endorsement(&evidence.uvm_endorsement, &requirements.uvm_did_x509)
        .map_err(|e| format!("UVM endorsement did not verify: {}", describe(&e)))?;

    // The predicate the library dropped. Done after stage 2 so it runs against
    // an endorsement whose signature and chain already authenticated: checking
    // an EKU on an unverified certificate would prove nothing.
    enforce_uvm_eku(evidence, requirements)?;

    // Stage 3: platform requirements, plus the library's own HOST_DATA check.
    // The report is `Copy`, so passing it by value here leaves it usable for
    // the reporting below — no second verification pass is needed.
    //
    // Its failure is returned alongside the authenticated report rather than
    // in place of it. Everything this function has established so far is a
    // fact about a signed report, and stays true whether or not the consumer
    // is willing to accept the node.
    let requirement_failure = tav::verify_caci_attestation(
        report,
        minimum_tcb,
        vec![*policy_digest],
        &uvm,
        &requirements.uvm_feed,
        requirements.min_uvm_svn,
    )
    .err()
    .map(|e| {
        format!(
            "node did not meet the configured requirements: {}",
            describe(&e)
        )
    });

    Ok(VerifiedNode {
        host_data: report.host_data,
        measurement: report.measurement,
        report_data: report.report_data,
        requirement_failure,
    })
}

/// Translate the consumer's TCB floor into the library's representation.
///
/// Refuses an empty floor, and refuses a generation name it does not know
/// rather than dropping it. A dropped entry would not fail — the library
/// simply would not find a matching generation and would move on, which is the
/// same fail-open an empty floor produces.
fn tcb_floor(requirements: &Requirements) -> Result<Vec<(Cpuid, TcbVersionRaw)>, String> {
    if requirements.min_tcb.is_empty() {
        return Err(
            "no minimum TCB is configured; an empty floor is not a floor, and would accept \
             any reported TCB"
                .to_string(),
        );
    }
    requirements
        .min_tcb
        .iter()
        .map(|floor| {
            let cpuid = cpuid_for(&floor.generation)?;
            Ok((
                cpuid,
                TcbVersionRaw {
                    raw: floor.reported_tcb.to_le_bytes(),
                },
            ))
        })
        .collect()
}

/// A CPUID that identifies the named generation.
///
/// The library takes a floor keyed by CPUID and converts it to a generation
/// internally, comparing only against a node of the *same* generation. A wrong
/// mapping therefore does not raise an error: the floor is simply never
/// matched against anything, and every node passes the TCB check. The tests
/// below pin each mapping against the library's own decoder for that reason.
fn cpuid_for(generation: &str) -> Result<Cpuid, String> {
    // Encoded per the CPUID layout the library decodes: extended_family in
    // bits 20-27, extended_model in bits 16-19, base_family in bits 8-11,
    // base_model in bits 4-7. Family is base + extended; model is
    // (extended_model << 4) | base_model.
    let raw: u32 = match generation.to_ascii_lowercase().as_str() {
        "milan" => 0x00A0_0F00, // family 0x19, model 0x00
        "genoa" => 0x00A1_0F00, // family 0x19, model 0x10
        "turin" => 0x00B0_0F00, // family 0x1A, model 0x00
        other => {
            return Err(format!(
                "unknown CPU generation '{other}' in the configured TCB floor; expected one of \
                 milan, genoa, turin"
            ))
        }
    };
    Ok(Cpuid::from(raw))
}

/// Enforce the EKU predicate the attestation library parses and ignores.
///
/// Resolved against the endorsement's own `x5chain`, using the same `did:x509`
/// resolver the statement path uses, so the two agree about what a DID means.
fn enforce_uvm_eku(evidence: &NodeEvidence, requirements: &Requirements) -> Result<(), String> {
    use scitt_receipt::didx509;

    if requirements.uvm_eku.is_empty() {
        return Err(
            "no UVM endorsement EKU is configured; the attestation library pins only the \
             chain root, and the UVM endorsement shares its root with statement signing, \
             so without an EKU a statement-signing certificate would be accepted"
                .to_string(),
        );
    }

    let sign1 = scitt_receipt::Sign1::parse(&evidence.uvm_endorsement)
        .map_err(|e| format!("the UVM endorsement is not a COSE_Sign1 document: {e}"))?;
    let chain = sign1.x5chain();
    if chain.is_empty() {
        return Err(
            "the UVM endorsement carries no x5chain to resolve its did:x509 against".into(),
        );
    }

    // Built from the configured anchor and the configured EKU rather than from
    // anything the endorsement asserts about itself. An endorsement does not
    // get to nominate the EKU that would make it acceptable.
    let did = format!(
        "{}::eku:{}",
        requirements.uvm_did_x509, requirements.uvm_eku
    );
    let parsed = didx509::parse(&did)
        .map_err(|e| format!("the configured UVM did:x509 is not usable as written: {e}"))?;

    match didx509::resolve(&parsed, &chain) {
        Ok(didx509::Resolution::Matched { .. }) => Ok(()),
        Ok(didx509::Resolution::Mismatch(why)) => Err(format!(
            "the UVM endorsement does not satisfy the configured did:x509: {why}"
        )),
        // Kept apart from a mismatch deliberately, and still an error. "I do
        // not know how to check this" is not evidence that the endorsement is
        // acceptable, and treating it as one would let a predicate this build
        // does not implement wave a node through.
        Ok(didx509::Resolution::Unsupported(what)) => Err(format!(
            "the configured UVM did:x509 uses something this build cannot check: {what}"
        )),
        Err(e) => Err(format!(
            "the UVM endorsement's did:x509 could not be resolved: {e}"
        )),
    }
}

/// A short description of a library error.
///
/// Rendered through `Debug` because the error type does not implement
/// `Display`. Never matched on: these strings are for an operator to read, and
/// branching on them would couple this crate to an upstream message.
fn describe(error: &AciError) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TcbFloor;
    use tav_caci::snp::Generation;

    fn requirements(min_tcb: Vec<TcbFloor>) -> Requirements {
        Requirements {
            uvm_did_x509: "did:x509:0:sha256:abc".into(),
            uvm_feed: "ContainerPlat-AMD-UVM".into(),
            uvm_eku: "1.3.6.1.4.1.311.76.59.1.2".into(),
            min_uvm_svn: 100,
            min_tcb,
        }
    }

    /// The mapping this module invents must agree with the library's decoder.
    ///
    /// This is the test that matters most in the file. The floor is matched by
    /// generation, and a mismatch is skipped rather than failed, so a wrong
    /// CPUID here would disable the TCB check silently and every node would
    /// pass it.
    #[test]
    fn each_generation_name_maps_to_a_cpuid_the_library_decodes_the_same_way() {
        for (name, expected) in [
            ("milan", Generation::Milan),
            ("genoa", Generation::Genoa),
            ("turin", Generation::Turin),
        ] {
            let cpuid = cpuid_for(name).expect(name);
            let decoded = Generation::from_cpuid(&cpuid)
                .unwrap_or_else(|e| panic!("{name} maps to a CPUID the library rejects: {e}"));
            assert_eq!(decoded, expected, "{name}");
        }
    }

    #[test]
    fn generation_names_are_case_insensitive_but_not_invented() {
        assert!(cpuid_for("Genoa").is_ok());
        assert!(cpuid_for("GENOA").is_ok());
        let err = cpuid_for("rome").unwrap_err();
        assert!(err.contains("unknown CPU generation"), "{err}");
    }

    #[test]
    fn an_empty_tcb_floor_is_refused_rather_than_skipped() {
        let err = tcb_floor(&requirements(Vec::new())).unwrap_err();
        assert!(err.contains("empty floor is not a floor"), "{err}");
    }

    #[test]
    fn an_unknown_generation_in_the_floor_fails_rather_than_being_dropped() {
        // Dropping it would leave a floor that matches no node, which is the
        // same fail-open as configuring none at all.
        let err = tcb_floor(&requirements(vec![TcbFloor {
            generation: "rome".into(),
            reported_tcb: 1,
        }]))
        .unwrap_err();
        assert!(err.contains("unknown CPU generation"), "{err}");
    }

    /// The configured floor must land in the report's own field layout.
    ///
    /// `TcbFloor.reported_tcb` is a `u64` for the consumer's convenience, but
    /// the report stores eight independent single-byte version numbers and the
    /// comparison is componentwise. Getting the byte order wrong would not
    /// error: it would scatter the configured versions across the wrong
    /// fields, and compare a microcode floor against a bootloader number.
    ///
    /// The value below is a reported TCB observed on a live Genoa ledger node
    /// (2026-09-22), decoded here through the library's own accessor. It pins
    /// the little-endian choice to an external fact rather than restating
    /// `to_le_bytes` back to itself.
    #[test]
    fn a_configured_floor_decodes_into_the_fields_the_report_uses() {
        let floors = tcb_floor(&requirements(vec![TcbFloor {
            generation: "genoa".into(),
            reported_tcb: 0x5417_0000_0000_000a,
        }]))
        .unwrap();

        let decoded = floors[0].1.as_milan_genoa();
        assert_eq!(decoded.boot_loader, 10);
        assert_eq!(decoded.tee, 0);
        assert_eq!(decoded.snp, 23);
        assert_eq!(decoded.microcode, 0x54);
    }

    #[test]
    fn a_configured_floor_survives_translation() {
        let floors = tcb_floor(&requirements(vec![
            TcbFloor {
                generation: "genoa".into(),
                reported_tcb: 0x0102_0304_0506_0708,
            },
            TcbFloor {
                generation: "milan".into(),
                reported_tcb: 7,
            },
        ]))
        .unwrap();
        assert_eq!(floors.len(), 2);
        assert_eq!(floors[0].1.raw, 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(
            Generation::from_cpuid(&floors[0].0).unwrap(),
            Generation::Genoa
        );
        assert_eq!(
            Generation::from_cpuid(&floors[1].0).unwrap(),
            Generation::Milan
        );
    }

    #[test]
    fn an_unconfigured_eku_is_refused_before_any_chain_is_looked_at() {
        let mut req = requirements(vec![TcbFloor {
            generation: "genoa".into(),
            reported_tcb: 1,
        }]);
        req.uvm_eku = String::new();
        let evidence = NodeEvidence {
            node_id: "n".into(),
            certificate_pem: Vec::new(),
            snp_report: Vec::new(),
            amd_endorsements: Vec::new(),
            uvm_endorsement: Vec::new(),
        };
        let err = enforce_uvm_eku(&evidence, &req).unwrap_err();
        assert!(
            err.contains("no UVM endorsement EKU is configured"),
            "{err}"
        );
    }

    #[test]
    fn a_wrong_number_of_amd_endorsements_is_refused_by_position_not_by_chain_failure() {
        // The library takes these positionally, so the wrong count must be
        // caught here; passing two through would surface as an invalid chain
        // and read like a trust failure rather than a malformed bundle.
        let evidence = NodeEvidence {
            node_id: "n".into(),
            certificate_pem: Vec::new(),
            snp_report: Vec::new(),
            amd_endorsements: vec![vec![1], vec![2]],
            uvm_endorsement: Vec::new(),
        };
        let err = verify_node(
            &evidence,
            &[0u8; 32],
            &requirements(vec![TcbFloor {
                generation: "genoa".into(),
                reported_tcb: 1,
            }]),
        )
        .unwrap_err();
        assert!(err.contains("[vcek, ask, ark]"), "{err}");
    }
}
