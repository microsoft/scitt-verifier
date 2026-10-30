//! Appraisal of an AMD SEV-SNP attestation report against the device an
//! accepted hardware BOM statement describes.
//!
//! The question answered here is narrow: *is the chip that signed this fresh
//! SNP report the device whose serial number this statement records?*
//!
//! What it deliberately does not answer, because nothing here establishes it:
//!
//! * **What software the guest runs.** The launch measurement is not compared
//!   with any endorsed value, so a pass says which chip answered, not which
//!   guest image asked it to.
//! * **That the BOM is true.** The statement was accepted, so its issuer and
//!   registration are verified. Whether the manufacturer recorded the right
//!   parts is the manufacturer's claim.
//! * **That the serial and the hardware ID are the same identifier by
//!   definition.** This profile compares them byte for byte. That they are
//!   meant to agree is the manufacturer's convention, not something a report
//!   or a certificate proves.
//! * **Revocation.** AMD's chain is validated to the pinned root; no
//!   revocation list is consulted.
//!
//! Like the other adapters, this crate reports checks and cannot express a
//! verdict. It reads no file, reads no clock and makes no request.

use serde_json::Value;
use tav_caci::snp::report::{AttestationReport, TcbVersionForGeneration, TcbVersionRaw};
use tav_caci::snp::Generation;
use tav_caci::synchronous as tav;
use tav_crypto::CertificateBackend;

/// The only profile this build understands: an SPDX 3 hardware BOM in JSON-LD
/// whose `@graph` holds `hardware_PhysicalHardware` nodes.
///
/// A profile is code, not configuration: it decides which statement fields
/// mean what. A policy naming any other profile is refused as unsupported
/// rather than read under this one's rules.
pub const PROFILE_SPDX3_HBOM: &str = "spdx3-hbom";

/// The VCEK extension carrying the hardware ID the certificate was issued for.
const HWID_OID: &str = "1.3.6.1.4.1.3704.1.4";

const NODE_TYPE: &str = "hardware_PhysicalHardware";

/// Below this a nonce is guessable enough that a report produced in advance
/// could carry it. Sixteen bytes is the shortest value that is not.
const MIN_NONCE_BYTES: usize = 16;

/// `REPORT_DATA` is 64 bytes, so no longer nonce can be in it.
const MAX_NONCE_BYTES: usize = 64;

/// Stable machine names and labels, in report order.
pub const CHECK_NAMES: [(&str, &str); 5] = [
    ("device-claim", "Statement device claim"),
    ("snp-report", "SNP report and AMD chain"),
    ("tcb-floor", "Minimum TCB"),
    ("freshness", "Report freshness"),
    ("device-binding", "Device binding"),
];

/// Three states, not four: every check is attempted when this adapter is
/// selected, so "nobody asked" never arises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Pass,
    Fail,
    CannotEvaluate,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub state: CheckState,
    pub detail: String,
}

impl Check {
    fn pass(detail: impl Into<String>) -> Self {
        Self {
            state: CheckState::Pass,
            detail: detail.into(),
        }
    }
    fn fail(detail: impl Into<String>) -> Self {
        Self {
            state: CheckState::Fail,
            detail: detail.into(),
        }
    }
    fn cannot(detail: impl Into<String>) -> Self {
        Self {
            state: CheckState::CannotEvaluate,
            detail: detail.into(),
        }
    }
}

/// One compared value, kept structured so a reader sees both sides.
#[derive(Debug, Clone)]
pub struct Finding {
    pub check: &'static str,
    pub subject: String,
    pub state: CheckState,
    pub detail: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
}

/// Fields, not a list, so a check cannot be forgotten at a construction site.
#[derive(Debug, Clone)]
pub struct Appraisal {
    /// The accepted statement names exactly one device of the configured
    /// category, with a serial this profile can compare.
    pub device_claim: Check,
    /// The report's signature verified under a VCEK that chains to AMD's
    /// pinned root for its generation, and the VCEK certifies its TCB.
    pub snp_report: Check,
    /// The authenticated TCB meets the floor configured for its generation.
    pub tcb_floor: Check,
    /// The authenticated `REPORT_DATA` carries the supplied nonce.
    pub freshness: Check,
    /// The chip that signed the report is the device the statement names.
    pub device_binding: Check,
    pub findings: Vec<Finding>,
    /// Facts that do not bear on the claim, reported so they are not mistaken
    /// for having been checked.
    pub informational: Vec<String>,
}

impl Appraisal {
    /// Every check unable to run, for one reason.
    pub fn unevaluated(reason: &str) -> Self {
        Self {
            device_claim: Check::cannot(reason),
            snp_report: Check::cannot(reason),
            tcb_floor: Check::cannot(reason),
            freshness: Check::cannot(reason),
            device_binding: Check::cannot(reason),
            findings: Vec::new(),
            informational: Vec::new(),
        }
    }

    /// Checks in [`CHECK_NAMES`] order.
    pub fn checks(&self) -> [(&'static str, &'static str, &Check); 5] {
        [
            (CHECK_NAMES[0].0, CHECK_NAMES[0].1, &self.device_claim),
            (CHECK_NAMES[1].0, CHECK_NAMES[1].1, &self.snp_report),
            (CHECK_NAMES[2].0, CHECK_NAMES[2].1, &self.tcb_floor),
            (CHECK_NAMES[3].0, CHECK_NAMES[3].1, &self.freshness),
            (CHECK_NAMES[4].0, CHECK_NAMES[4].1, &self.device_binding),
        ]
    }
}

/// A minimum reported TCB for one processor generation.
pub struct TcbFloor<'a> {
    /// `milan`, `genoa` or `turin`.
    pub generation: &'a str,
    /// The raw 64-bit value in the report's byte order, read little-endian.
    pub reported_tcb: u64,
}

/// What the relying party requires, translated from its policy by the caller.
pub struct Requirements<'a> {
    pub profile: &'a str,
    /// The `typeFromSource` of the one device the statement must describe,
    /// compared exactly. A BOM lists several parts, some sharing a serial, so
    /// the category is what says which one the chip is.
    pub category: &'a str,
    pub minimum_tcb: &'a [TcbFloor<'a>],
}

/// The accepted statement's payload, as the caller could obtain it.
pub enum Payload<'a> {
    /// Embedded and declared JSON.
    Json(&'a [u8]),
    /// Embedded but declared as something else, or with no content type.
    NotJson(String),
    /// Not available to appraise at all, for example a detached payload.
    Unavailable(String),
}

/// Operator-supplied evidence. Any of it may be absent.
pub struct Evidence<'a> {
    /// The raw SNP report, as the guest's `/dev/sev-guest` returned it.
    pub report: Option<&'a [u8]>,
    /// The VCEK, PEM or DER.
    pub vcek: Option<&'a [u8]>,
    /// AMD's `cert_chain` as KDS serves it: the ASK, then the ARK, in PEM.
    pub cert_chain: Option<&'a [u8]>,
    /// The nonce the guest was asked to place in `REPORT_DATA`, as hex text.
    pub nonce: Option<&'a [u8]>,
}

struct Claim {
    serial: Vec<u8>,
    serial_text: String,
}

struct Authenticated {
    report: AttestationReport,
    generation: Generation,
    hwid: Option<Vec<u8>>,
}

pub fn appraise(payload: Payload<'_>, evidence: Evidence<'_>, req: &Requirements<'_>) -> Appraisal {
    if req.profile != PROFILE_SPDX3_HBOM {
        return Appraisal::unevaluated(&format!(
            "profile {:?} is not supported by this build; supported: {PROFILE_SPDX3_HBOM}",
            req.profile
        ));
    }

    let mut findings = Vec::new();
    let mut informational = Vec::new();

    // Both halves are appraised even when one fails, so an operator learns
    // everything wrong with a run at once rather than one problem per attempt.
    let claim = read_claim(payload, req.category);
    let device_claim = match &claim {
        Ok((_, detail)) => Check::pass(detail.clone()),
        Err(check) => check.clone(),
    };

    let authenticated = authenticate(&evidence);
    let snp_report = match &authenticated {
        Ok(auth) => {
            informational.push(format!(
                "launch measurement {} (not compared with any endorsed value)",
                hex_lower(&auth.report.measurement)
            ));
            Check::pass(format!(
                "signed by a {} VCEK that chains to AMD's pinned root, and the VCEK \
                 certifies the reported TCB",
                auth.generation
            ))
        }
        Err(check) => check.clone(),
    };

    let (tcb_floor, freshness, device_binding) = match &authenticated {
        Err(_) => {
            let why = "the SNP report was not authenticated, so nothing it says can be relied on";
            (Check::cannot(why), Check::cannot(why), Check::cannot(why))
        }
        Ok(auth) => (
            check_tcb(auth, req.minimum_tcb, &mut findings),
            check_freshness(&auth.report.report_data, evidence.nonce, &mut findings),
            match &claim {
                Ok((claim, _)) => check_binding(claim, auth, &mut findings),
                Err(_) => Check::cannot(
                    "the statement's device claim was not established, so there is no \
                     serial to compare the chip with",
                ),
            },
        ),
    };

    Appraisal {
        device_claim,
        snp_report,
        tcb_floor,
        freshness,
        device_binding,
        findings,
        informational,
    }
}

fn read_claim(payload: Payload<'_>, category: &str) -> Result<(Claim, String), Check> {
    let bytes = match payload {
        Payload::Json(bytes) => bytes,
        Payload::NotJson(ct) => {
            return Err(Check::cannot(format!(
                "the statement's payload is declared {ct}, not JSON, so this profile cannot \
                 read a hardware BOM from it"
            )))
        }
        Payload::Unavailable(why) => return Err(Check::cannot(why)),
    };
    let document = scitt_policy::parse_payload_json(bytes)
        .map_err(|e| Check::fail(format!("the statement's payload is not usable JSON: {e}")))?;
    let graph = document
        .get("@graph")
        .and_then(Value::as_array)
        .ok_or_else(|| Check::fail("the statement's payload has no @graph array"))?;

    let matches: Vec<&Value> = graph
        .iter()
        .filter(|node| node.get("type").and_then(Value::as_str) == Some(NODE_TYPE))
        .filter(|node| has_category(node, category))
        .collect();
    let node = match matches.as_slice() {
        [node] => *node,
        [] => {
            return Err(Check::fail(format!(
                "the statement describes no {NODE_TYPE} of category {category:?}"
            )))
        }
        many => {
            // Refused rather than picking one. Which device the chip is would
            // then depend on document order, which the issuer did not sign
            // as meaning anything.
            return Err(Check::fail(format!(
                "the statement describes {} {NODE_TYPE} nodes of category {category:?}, so \
                 which device the chip should be is ambiguous",
                many.len()
            )));
        }
    };

    let serial_text = node
        .get("hardware_serialNumber")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Check::fail(format!(
                "the {category:?} device in the statement has no hardware_serialNumber"
            ))
        })?;
    let serial = decode_hex(serial_text).ok_or_else(|| {
        Check::fail(format!(
            "the {category:?} device's serial {serial_text:?} is not hexadecimal, so it \
             cannot name an SNP hardware ID under this profile"
        ))
    })?;

    let field = |name: &str| node.get(name).and_then(Value::as_str).unwrap_or("-");
    let detail = format!(
        "{category} part {} revision {} serial {serial_text}",
        field("hardware_partNumber"),
        field("hardware_hardwareVersion"),
    );
    Ok((
        Claim {
            serial,
            serial_text: serial_text.to_string(),
        },
        detail,
    ))
}

fn has_category(node: &Value, category: &str) -> bool {
    node.get("hardware_category")
        .and_then(Value::as_array)
        .is_some_and(|categories| {
            categories
                .iter()
                .any(|c| c.get("typeFromSource").and_then(Value::as_str) == Some(category))
        })
}

fn authenticate(evidence: &Evidence<'_>) -> Result<Authenticated, Check> {
    let (report, vcek, chain) = match (evidence.report, evidence.vcek, evidence.cert_chain) {
        (Some(r), Some(v), Some(c)) => (r, v, c),
        _ => {
            let missing: Vec<&str> = [
                ("SNP report", evidence.report.is_none()),
                ("VCEK", evidence.vcek.is_none()),
                ("AMD certificate chain", evidence.cert_chain.is_none()),
            ]
            .iter()
            .filter(|(_, absent)| *absent)
            .map(|(name, _)| *name)
            .collect();
            return Err(Check::cannot(format!(
                "not supplied: {}",
                missing.join(", ")
            )));
        }
    };
    let (ask, ark) = split_chain(chain).map_err(Check::cannot)?;

    // The ARK supplied here is compared with the one pinned in the library for
    // the report's generation, so a chain to some other root fails rather
    // than being trusted because it came in the bundle.
    let report = tav::verify_attestation(report, &[vcek, ask, ark])
        .map_err(|e| Check::fail(format!("the SNP report did not verify: {e}")))?;
    let generation = report.cpu_generation().map_err(|e| {
        Check::fail(format!(
            "the report names a processor generation this build cannot decode: {e}"
        ))
    })?;
    let hwid = read_hwid(vcek).map_err(Check::fail)?;
    Ok(Authenticated {
        report,
        generation,
        hwid,
    })
}

/// The ASK and ARK out of KDS's `cert_chain`, in that order.
fn split_chain(pem: &[u8]) -> Result<(&[u8], &[u8]), String> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    let starts: Vec<usize> = pem
        .windows(BEGIN.len())
        .enumerate()
        .filter(|(_, w)| *w == BEGIN)
        .map(|(i, _)| i)
        .collect();
    match starts.as_slice() {
        [ask, ark] => Ok((&pem[*ask..*ark], &pem[*ark..])),
        other => Err(format!(
            "AMD's cert_chain must hold two PEM certificates, the ASK then the ARK; found {}",
            other.len()
        )),
    }
}

fn read_hwid(vcek: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let cert = tav_crypto::Crypto::from_pem(vcek)
        .or_else(|_| tav_crypto::Crypto::from_der(vcek))
        .map_err(|e| format!("the VCEK could not be parsed: {e}"))?;
    let value = tav_crypto::Crypto::get_extension_value_by_oid(&cert, HWID_OID)
        .map_err(|e| format!("the VCEK's hardware-ID extension could not be read: {e}"))?;
    Ok(value.map(unwrap_hwid))
}

/// Some encoders wrap the hardware ID in an OCTET STRING. Unwrapped only when
/// the payload is itself a supported ID length (8 or 64 bytes), so a raw ID
/// that happens to begin with `04 06` or `04 3e` is left alone.
fn unwrap_hwid(value: Vec<u8>) -> Vec<u8> {
    match value.as_slice() {
        [0x04, len, rest @ ..]
            if usize::from(*len) == rest.len() && matches!(rest.len(), 8 | 64) =>
        {
            rest.to_vec()
        }
        _ => value,
    }
}

fn check_tcb(auth: &Authenticated, floors: &[TcbFloor<'_>], findings: &mut Vec<Finding>) -> Check {
    if floors.is_empty() {
        return Check::cannot(
            "no minimum TCB is configured; an empty floor is not a floor, and would accept \
             any firmware",
        );
    }
    let mut applicable = None;
    for floor in floors {
        match generation_named(floor.generation) {
            Some(g) if g == auth.generation => applicable = Some(floor),
            Some(_) => {}
            None => {
                return Check::cannot(format!(
                    "unknown processor generation {:?} in the configured TCB floor",
                    floor.generation
                ))
            }
        }
    }
    // A floor for another generation says nothing about this report, so it
    // must not stand in for one. Not a failure: nothing was learned about the
    // chip, the question just was not configured for it.
    let Some(floor) = applicable else {
        return Check::cannot(format!(
            "the report is from a {} part, but no minimum TCB is configured for that \
             generation",
            auth.generation
        ));
    };
    let minimum = TcbVersionRaw {
        raw: floor.reported_tcb.to_le_bytes(),
    };
    let reported = auth.report.reported_tcb;
    let observed = format!("{:#018x}", u64::from_le_bytes(reported.raw));
    let expected = format!("{:#018x}", floor.reported_tcb);
    // Ordered per component: a TCB that is ahead in one and behind in another
    // is not at least the floor, and compares as neither.
    if TcbVersionForGeneration::new(minimum, auth.generation)
        <= TcbVersionForGeneration::new(reported, auth.generation)
    {
        Check::pass(format!(
            "{} reported TCB {observed} meets the floor {expected}",
            auth.generation
        ))
    } else {
        findings.push(Finding {
            check: "tcb-floor",
            subject: "reported_tcb".into(),
            state: CheckState::Fail,
            detail: "the reported TCB is below the configured floor in at least one component"
                .into(),
            expected: Some(format!(">= {expected}")),
            observed: Some(observed.clone()),
        });
        Check::fail(format!(
            "{} reported TCB {observed} is below the floor {expected}",
            auth.generation
        ))
    }
}

fn generation_named(name: &str) -> Option<Generation> {
    match name.to_ascii_lowercase().as_str() {
        "milan" => Some(Generation::Milan),
        "genoa" => Some(Generation::Genoa),
        "turin" => Some(Generation::Turin),
        _ => None,
    }
}

/// Whether the authenticated `REPORT_DATA` begins with the supplied nonce.
///
/// Separated so it can be tested without a report whose signature verifies.
fn check_freshness(
    report_data: &[u8; 64],
    nonce: Option<&[u8]>,
    findings: &mut Vec<Finding>,
) -> Check {
    let Some(raw) = nonce else {
        return Check::cannot(
            "no nonce was supplied, so the report could have been produced at any time",
        );
    };
    let text = String::from_utf8_lossy(raw);
    // Windows PowerShell writes a byte-order mark and a newline by default;
    // neither is part of the value.
    let text = text.trim_start_matches('\u{feff}').trim();
    let Some(nonce) = decode_hex(text) else {
        return Check::cannot("the supplied nonce is not hexadecimal");
    };
    if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&nonce.len()) {
        return Check::cannot(format!(
            "the supplied nonce is {} bytes; it must be {MIN_NONCE_BYTES} to {MAX_NONCE_BYTES}",
            nonce.len()
        ));
    }
    // All zeros is what the guest reports when it was given no nonce at all,
    // so matching it shows nothing about when the report was made.
    if nonce.iter().all(|b| *b == 0) {
        return Check::cannot("the supplied nonce is all zeros, which is no nonce");
    }
    if report_data[..nonce.len()] == nonce[..] {
        Check::pass(format!(
            "REPORT_DATA begins with the supplied {}-byte nonce",
            nonce.len()
        ))
    } else {
        findings.push(Finding {
            check: "freshness",
            subject: "report_data".into(),
            state: CheckState::Fail,
            detail: "the report was not produced for the supplied nonce".into(),
            expected: Some(hex_lower(&nonce)),
            observed: Some(hex_lower(&report_data[..nonce.len()])),
        });
        Check::fail("REPORT_DATA does not carry the supplied nonce")
    }
}

/// The hardware ID length a VCEK carries for each generation. Turin
/// certificates name the chip by its first 8 bytes; earlier ones by all 64.
fn hwid_len(generation: Generation) -> usize {
    match generation {
        Generation::Turin => 8,
        Generation::Milan | Generation::Genoa => 64,
    }
}

fn check_binding(claim: &Claim, auth: &Authenticated, findings: &mut Vec<Finding>) -> Check {
    // Without a hardware ID the signing key is not tied to one chip — a VLEK
    // is shared across a provider's fleet — so nothing identifies the device.
    let Some(hwid) = &auth.hwid else {
        return Check::fail(
            "the VCEK carries no hardware ID, so the report's signer is not tied to a chip",
        );
    };
    let len = hwid_len(auth.generation);
    if hwid.len() != len {
        return Check::fail(format!(
            "the VCEK's hardware ID is {} bytes; a {} VCEK names its chip in {len}",
            hwid.len(),
            auth.generation
        ));
    }
    if hwid.iter().all(|b| *b == 0) {
        return Check::fail("the VCEK's hardware ID is all zeros, which names no chip");
    }
    // The library makes this comparison too, but tolerates forms this profile
    // does not need. Restated exactly, because it is the link the whole claim
    // rests on.
    let chip_id = &auth.report.chip_id;
    if chip_id[..len] != hwid[..] || chip_id[len..].iter().any(|b| *b != 0) {
        return Check::fail("the report's CHIP_ID is not the chip the VCEK was issued for");
    }
    if claim.serial == *hwid {
        Check::pass(format!(
            "the statement's serial {} is the hardware ID of the chip that signed the report",
            claim.serial_text
        ))
    } else {
        findings.push(Finding {
            check: "device-binding",
            subject: "hardware_serialNumber".into(),
            state: CheckState::Fail,
            detail: "the report was signed by a different chip than the statement describes".into(),
            expected: Some(claim.serial_text.clone()),
            observed: Some(hex_upper(hwid)),
        });
        Check::fail(format!(
            "the report was signed by chip {}, not {}",
            hex_upper(hwid),
            claim.serial_text
        ))
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests;
