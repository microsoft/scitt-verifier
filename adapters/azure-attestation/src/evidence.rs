use crate::{Appraisal, CheckState, Finding};
use scitt_receipt::base64::{decode, Alphabet};
use serde::Deserialize;
use tav_crypto::CertificateBackend;

const MAX_JSON: usize = 16 * 1024 * 1024;
const MAX_KEYS: usize = 64;
const MAX_CERT: usize = 1024 * 1024;
const MAX_CHAIN: usize = 8;
const EVIDENCE_OID: &str = "1.3.6.1.4.1.311.105.1000.1";
const TYPE_OID: &str = "1.3.6.1.4.1.311.105.1000.2";

#[derive(Deserialize)]
struct KeySet {
    keys: Vec<Key>,
}

#[derive(Deserialize)]
struct Key {
    x5c: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawEvidence {
    snp_report: String,
    vcek_cert_chain: String,
}

pub(crate) struct Evidence {
    pub report: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}

fn bounded_decode(text: &str, alphabet: Alphabet, limit: usize) -> Result<Vec<u8>, String> {
    if text.len() > limit.div_ceil(3) * 4 {
        return Err(format!("encoded value exceeds {limit} decoded bytes"));
    }
    let bytes = decode(alphabet, text)?;
    if bytes.len() > limit {
        return Err(format!("decoded value exceeds {limit} bytes"));
    }
    Ok(bytes)
}

// The extension asserts one DER UTF8String. Accepting other wrappers could
// disagree with the issuer about which bytes constitute its value.
fn utf8_string(der: &[u8]) -> Result<&str, String> {
    if der.first() != Some(&0x0c) {
        return Err("MAA extension is not a DER UTF8String".into());
    }
    let first = *der.get(1).ok_or("truncated DER UTF8String")?;
    let (length, offset) = if first < 128 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || der.len() < 2 + count || der[2] == 0 {
            return Err("invalid DER UTF8String length".into());
        }
        let length = der[2..2 + count]
            .iter()
            .fold(0usize, |n, b| (n << 8) | usize::from(*b));
        if length < 128 {
            return Err("nonminimal DER UTF8String length".into());
        }
        (length, 2 + count)
    };
    if der.len().checked_sub(offset) != Some(length) {
        return Err("DER UTF8String length does not cover exactly its value".into());
    }
    core::str::from_utf8(&der[offset..]).map_err(|_| "MAA extension is not UTF-8".into())
}

fn parse_evidence(raw: &[u8]) -> Result<Evidence, String> {
    let raw: RawEvidence =
        serde_json::from_str(utf8_string(raw)?).map_err(|e| format!("MAA evidence JSON: {e}"))?;
    let report = bounded_decode(&raw.snp_report, Alphabet::UrlSafe, 1184)?;
    if report.len() != 1184 {
        return Err(format!(
            "SNP report must be 1184 bytes, got {}",
            report.len()
        ));
    }
    let pem = bounded_decode(&raw.vcek_cert_chain, Alphabet::UrlSafe, MAX_CERT)?;
    let pem = core::str::from_utf8(&pem).map_err(|_| "AMD chain is not UTF-8 PEM")?;
    let chain = scitt_receipt::chain::parse_pem_certificates(pem)
        .map_err(|e| format!("AMD certificate chain: {e}"))?;
    if chain.len() != 3 {
        return Err("AMD chain must contain exactly [vcek, ask, ark]".into());
    }
    Ok(Evidence { report, chain })
}

fn key_evidence(key: &Key) -> Result<Option<Evidence>, String> {
    if key.x5c.is_empty() || key.x5c.len() > MAX_CHAIN {
        return Err(format!("x5c must contain 1..={MAX_CHAIN} certificates"));
    }
    let mut evidence = None;
    for (index, encoded) in key.x5c.iter().enumerate() {
        let der = bounded_decode(encoded, Alphabet::Standard, MAX_CERT)?;
        let cert = <tav_crypto::Crypto as CertificateBackend>::from_der(&der)
            .map_err(|e| format!("invalid x5c certificate: {e}"))?;
        let raw = <tav_crypto::Crypto as CertificateBackend>::get_extension_value_by_oid(
            &cert,
            EVIDENCE_OID,
        )
        .map_err(|e| format!("reading MAA evidence extension: {e}"))?;
        let kind =
            <tav_crypto::Crypto as CertificateBackend>::get_extension_value_by_oid(&cert, TYPE_OID)
                .map_err(|e| format!("reading MAA evidence type: {e}"))?;
        match (raw, kind) {
            (None, None) => {}
            (Some(raw), Some(kind)) if index == 0 => {
                if utf8_string(&kind)? != "acisevsnp" {
                    return Err("unsupported MAA evidence type; expected acisevsnp".into());
                }
                evidence = Some(parse_evidence(&raw)?);
            }
            (Some(_), Some(_)) => {
                return Err("MAA evidence is on a non-leaf x5c certificate".into());
            }
            _ => return Err("MAA evidence and type extensions must both be present".into()),
        }
    }
    Ok(evidence)
}

fn finding(
    appraisal: &mut Appraisal,
    check: &'static str,
    subject: &str,
    state: CheckState,
    detail: impl Into<String>,
) {
    appraisal.findings.push(Finding {
        check,
        subject: subject.into(),
        state,
        detail: detail.into(),
        expected: None,
        observed: None,
    });
}

pub(crate) fn appraise(json: &[u8], digest: &[u8; 32]) -> Appraisal {
    let mut appraisal = crate::unevaluated("no evidence-bearing certificate report was appraised");
    let keys = if json.len() > MAX_JSON {
        Err(format!("certificate response exceeds {MAX_JSON} bytes"))
    } else {
        serde_json::from_slice::<KeySet>(json)
            .map_err(|e| format!("certificate response JSON: {e}"))
            .and_then(|set| {
                if set.keys.is_empty() || set.keys.len() > MAX_KEYS {
                    Err(format!(
                        "certificate response must contain 1..={MAX_KEYS} keys"
                    ))
                } else {
                    Ok(set.keys)
                }
            })
    };
    match keys {
        Err(error) => finding(
            &mut appraisal,
            "maa-certificate-coverage",
            "response",
            CheckState::Fail,
            error,
        ),
        Ok(keys) => {
            let mut reports = 0;
            for (index, key) in keys.iter().enumerate() {
                let subject = format!("certificate[{index}]");
                match key_evidence(key) {
                    Err(error) => incomplete(&mut appraisal, &subject, &error),
                    Ok(None) => appraisal.notes.push(format!(
                        "{subject}: no MAA evidence extensions; excluded from report-evidence scope"
                    )),
                    Ok(Some(evidence)) => {
                        reports += 1;
                        appraise_report(&mut appraisal, &subject, &evidence, digest);
                    }
                }
            }
            if reports == 0 {
                finding(
                    &mut appraisal,
                    "maa-certificate-coverage",
                    "response",
                    CheckState::CannotEvaluate,
                    "no evidence-bearing certificate reports; ordinary certificates are excluded, not attested",
                );
            }
        }
    }
    for check in &mut appraisal.checks {
        let findings: Vec<_> = appraisal
            .findings
            .iter()
            .filter(|f| f.check == check.name)
            .collect();
        if findings.is_empty() {
            continue;
        }
        check.state = if findings.iter().any(|f| f.state == CheckState::Fail) {
            CheckState::Fail
        } else if findings
            .iter()
            .any(|f| f.state == CheckState::CannotEvaluate)
        {
            CheckState::CannotEvaluate
        } else {
            CheckState::Pass
        };
        check.detail = findings
            .iter()
            .map(|f| format!("{}: {}", f.subject, f.detail))
            .collect::<Vec<_>>()
            .join("; ");
    }
    appraisal
}

fn appraise_report(
    appraisal: &mut Appraisal,
    subject: &str,
    evidence: &Evidence,
    digest: &[u8; 32],
) {
    match crate::snp::verify(evidence) {
        Err(error) => incomplete(appraisal, subject, &error),
        Ok(host_data) => {
            finding(
                appraisal,
                "snp-validation",
                subject,
                CheckState::Pass,
                "SNP report signature and AMD collateral authenticated; this is not guest execution or platform policy appraisal",
            );
            finding(
                appraisal,
                "cce-policy-host-data",
                subject,
                if host_data == *digest { CheckState::Pass } else { CheckState::Fail },
                "compared authenticated HOST_DATA to SHA256 of the exact decoded security-policy-base64 bytes supplied by the caller",
            );
            let comparison = appraisal
                .findings
                .last_mut()
                .expect("finding just inserted");
            comparison.expected = Some(hex(digest));
            comparison.observed = Some(hex(&host_data));
            finding(
                appraisal,
                "maa-certificate-coverage",
                subject,
                CheckState::Pass,
                "certificate report evidence was appraised; this does not authenticate its signing key or service association",
            );
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn incomplete(appraisal: &mut Appraisal, subject: &str, detail: &str) {
    for check in ["snp-validation", "maa-certificate-coverage"] {
        finding(appraisal, check, subject, CheckState::Fail, detail);
    }
    finding(
        appraisal,
        "cce-policy-host-data",
        subject,
        CheckState::CannotEvaluate,
        "no authenticated report was available for this certificate",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_CERTS: &[u8] = include_bytes!("../../../corpus/fixtures/maa-certs.json");

    fn public_policy_digest() -> [u8; 32] {
        [
            0x01, 0x78, 0x24, 0x0e, 0xff, 0x4e, 0xf9, 0x68, 0xef, 0xdc, 0xd7, 0x35, 0xb8, 0xbc,
            0xee, 0x63, 0x57, 0x8c, 0x4e, 0xb9, 0xe4, 0x26, 0x41, 0x78, 0xf7, 0x47, 0xdf, 0x14,
            0x9b, 0xf5, 0x7b, 0xff,
        ]
    }

    fn appraise_public(json: &[u8]) -> Appraisal {
        appraise(json, &public_policy_digest())
    }

    fn state(appraisal: &Appraisal, name: &str) -> CheckState {
        appraisal
            .checks
            .iter()
            .find(|c| c.name == name)
            .unwrap()
            .state
    }

    fn all_pass(appraisal: &Appraisal) {
        assert_eq!(appraisal.checks.len(), 3);
        assert!(
            appraisal.checks.iter().all(|c| c.state == CheckState::Pass),
            "{appraisal:#?}"
        );
    }

    #[test]
    fn malformed_duplicate_and_empty_responses_fail_closed() {
        for json in [
            b"not JSON".as_slice(),
            br#"{"keys":[]}"#,
            br#"{"keys":[],"keys":[]}"#,
            br#"{"keys":[{"x5c":[]}]}"#,
            br#"{"keys":[{"x5c":["bm90IGEgY2VydA=="]}]}"#,
        ] {
            let result = appraise(json, &[0; 32]);
            assert_eq!(state(&result, "maa-certificate-coverage"), CheckState::Fail);
            assert_ne!(state(&result, "snp-validation"), CheckState::Pass);
        }
    }

    #[test]
    fn response_key_count_and_certificate_sizes_are_bounded() {
        let oversized = vec![b' '; MAX_JSON + 1];
        assert_eq!(
            state(&appraise(&oversized, &[0; 32]), "maa-certificate-coverage"),
            CheckState::Fail
        );
        let keys = vec![serde_json::json!({"x5c": []}); MAX_KEYS + 1];
        let json = serde_json::to_vec(&serde_json::json!({"keys": keys})).unwrap();
        assert_eq!(
            state(&appraise(&json, &[0; 32]), "maa-certificate-coverage"),
            CheckState::Fail
        );
        assert!(bounded_decode(
            &"A".repeat(MAX_CERT.div_ceil(3) * 4 + 1),
            Alphabet::Standard,
            MAX_CERT
        )
        .is_err());
    }

    #[test]
    fn der_utf8_requires_exact_minimal_wrapper() {
        assert_eq!(utf8_string(b"\x0c\x02{}").unwrap(), "{}");
        for invalid in [
            b"{}".as_slice(),
            b"\x04\x02{}",
            b"\x0c\x81\x02{}",
            b"\x0c\x80{}",
            b"\x0c\x02{}x",
            b"\x0c\x01\xff",
        ] {
            assert!(utf8_string(invalid).is_err());
        }
    }

    fn ordinary_certificate() -> serde_json::Value {
        let pem = include_str!("../../../corpus/fixtures/mst-test-service-cert.pem");
        let encoded = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        serde_json::json!({"x5c": [encoded]})
    }

    #[test]
    fn ordinary_certificates_are_excluded_and_no_report_never_passes() {
        let json =
            serde_json::to_vec(&serde_json::json!({"keys": [ordinary_certificate()]})).unwrap();
        let result = appraise_public(&json);
        assert!(result
            .checks
            .iter()
            .all(|c| c.state == CheckState::CannotEvaluate));
        assert!(result
            .notes
            .iter()
            .any(|n| n.contains("certificate[0]") && n.contains("excluded")));
    }

    #[test]
    fn a_malformed_certificate_is_not_skipped_alongside_an_ordinary_certificate() {
        let json = serde_json::to_vec(&serde_json::json!({
            "keys": [ordinary_certificate(), {"x5c": []}]
        }))
        .unwrap();
        let result = appraise_public(&json);
        assert_eq!(state(&result, "maa-certificate-coverage"), CheckState::Fail);
        assert_eq!(state(&result, "snp-validation"), CheckState::Fail);
    }

    #[test]
    fn public_snapshot_authenticates_both_reports_and_matches_the_policy_digest() {
        assert_eq!(
            hex(&scitt_receipt::sha256(PUBLIC_CERTS)),
            "a9da33b4b00055eb912654f9685d8168eb873970a9e729a8a2f1d268c718f160"
        );
        let result = appraise_public(PUBLIC_CERTS);
        all_pass(&result);
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|f| f.check == "snp-validation")
                .count(),
            2
        );
        assert_eq!(
            result
                .notes
                .iter()
                .filter(|n| n.contains("no MAA evidence extensions"))
                .count(),
            2
        );
        for comparison in result
            .findings
            .iter()
            .filter(|f| f.check == "cce-policy-host-data")
        {
            assert_eq!(comparison.expected, Some(hex(&public_policy_digest())));
            assert_eq!(comparison.observed, comparison.expected);
        }
    }

    fn standard_encode(bytes: &[u8]) -> String {
        let mut encoded = tav_crypto::base64::base64_encode_no_padding(bytes)
            .replace('-', "+")
            .replace('_', "/");
        while encoded.len() % 4 != 0 {
            encoded.push('=');
        }
        encoded
    }

    fn certificate_der(json: &serde_json::Value, index: usize) -> Vec<u8> {
        decode(
            Alphabet::Standard,
            json["keys"][index]["x5c"][0].as_str().unwrap(),
        )
        .unwrap()
    }

    fn raw_evidence(der: &[u8]) -> RawEvidence {
        let cert = <tav_crypto::Crypto as CertificateBackend>::from_der(der).unwrap();
        let raw = <tav_crypto::Crypto as CertificateBackend>::get_extension_value_by_oid(
            &cert,
            EVIDENCE_OID,
        )
        .unwrap()
        .unwrap();
        serde_json::from_str(utf8_string(&raw).unwrap()).unwrap()
    }

    #[test]
    fn public_key_and_kid_mutations_do_not_change_the_report_only_claim() {
        let mut json: serde_json::Value = serde_json::from_slice(PUBLIC_CERTS).unwrap();
        json["keys"][0]["kid"] = serde_json::json!("unrelated-mutable-label");
        json["keys"][0]["n"] = serde_json::json!("unrelated-public-key-metadata");
        let mut der = certificate_der(&json, 0);
        let spki = scitt_receipt::spki_from_certificate_der(&der).unwrap();
        let offset = der.windows(spki.len()).position(|w| w == spki).unwrap();
        der[offset + spki.len() - 1] ^= 2;
        json["keys"][0]["x5c"][0] = serde_json::json!(standard_encode(&der));
        let result = appraise_public(&serde_json::to_vec(&json).unwrap());
        all_pass(&result);
        assert!(result
            .notes
            .iter()
            .any(|n| n.contains("identity are not established")));
    }

    #[test]
    fn malformed_or_unsupported_later_evidence_cannot_hide_behind_a_passing_report() {
        for unsupported_type in [false, true] {
            let mut json: serde_json::Value = serde_json::from_slice(PUBLIC_CERTS).unwrap();
            let last = json["keys"].as_array().unwrap().len() - 1;
            let mut der = certificate_der(&json, last);
            let target = if unsupported_type {
                "acisevsnp".to_string()
            } else {
                raw_evidence(&der).snp_report
            };
            let offset = der
                .windows(target.len())
                .position(|w| w == target.as_bytes())
                .unwrap();
            der[offset] = b'?';
            json["keys"][last]["x5c"][0] = serde_json::json!(standard_encode(&der));
            let result = appraise_public(&serde_json::to_vec(&json).unwrap());
            assert_eq!(
                state(&result, "maa-certificate-coverage"),
                CheckState::Fail,
                "{result:#?}"
            );
            assert_eq!(state(&result, "snp-validation"), CheckState::Fail);
            let crypto: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.check == "snp-validation")
                .collect();
            assert_eq!(crypto.len(), 2);
            assert_eq!(crypto[0].state, CheckState::Pass);
            assert_eq!(crypto[1].state, CheckState::Fail);
        }
    }

    #[test]
    fn modified_report_fails_without_skipping_the_other_report() {
        let mut json: serde_json::Value = serde_json::from_slice(PUBLIC_CERTS).unwrap();
        let mut der = certificate_der(&json, 0);
        let raw = raw_evidence(&der);
        let mut report = decode(Alphabet::UrlSafe, &raw.snp_report).unwrap();
        report[672] ^= 1;
        let mut modified = tav_crypto::base64::base64_encode_no_padding(&report);
        while modified.len() < raw.snp_report.len() {
            modified.push('=');
        }
        assert_eq!(modified.len(), raw.snp_report.len());
        let offset = der
            .windows(raw.snp_report.len())
            .position(|w| w == raw.snp_report.as_bytes())
            .unwrap();
        der[offset..offset + modified.len()].copy_from_slice(modified.as_bytes());
        json["keys"][0]["x5c"][0] = serde_json::json!(standard_encode(&der));
        let result = appraise_public(&serde_json::to_vec(&json).unwrap());
        assert_eq!(
            state(&result, "snp-validation"),
            CheckState::Fail,
            "{result:#?}"
        );
        assert_eq!(state(&result, "maa-certificate-coverage"), CheckState::Fail);
        let crypto: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.check == "snp-validation")
            .collect();
        assert_eq!(crypto.len(), 2);
        assert_eq!(crypto[0].state, CheckState::Fail);
        assert_eq!(crypto[1].state, CheckState::Pass);
    }

    #[test]
    fn another_policy_digest_fails_but_report_authenticity_still_passes() {
        let result = appraise(PUBLIC_CERTS, &[0; 32]);
        assert_eq!(
            state(&result, "cce-policy-host-data"),
            CheckState::Fail,
            "{result:#?}"
        );
        assert_eq!(state(&result, "snp-validation"), CheckState::Pass);
        for comparison in result
            .findings
            .iter()
            .filter(|f| f.check == "cce-policy-host-data")
        {
            assert_eq!(comparison.expected, Some(hex(&[0; 32])));
            assert_eq!(comparison.observed, Some(hex(&public_policy_digest())));
        }
    }

    fn der_utf8(text: &[u8]) -> Vec<u8> {
        let mut result = vec![0x0c];
        if text.len() < 128 {
            result.push(u8::try_from(text.len()).unwrap());
        } else {
            let bytes = text.len().to_be_bytes();
            let bytes = &bytes[bytes.iter().position(|b| *b != 0).unwrap()..];
            result.push(0x80 | u8::try_from(bytes.len()).unwrap());
            result.extend_from_slice(bytes);
        }
        result.extend_from_slice(text);
        result
    }

    #[test]
    fn endorsements_are_not_required_or_interpreted() {
        let json: serde_json::Value = serde_json::from_slice(PUBLIC_CERTS).unwrap();
        let raw = raw_evidence(&certificate_der(&json, 0));
        for endorsements in [
            None,
            Some(serde_json::json!("not base64")),
            Some(serde_json::json!({"uninterpreted": true})),
        ] {
            let mut minimal = serde_json::json!({
                "SnpReport": raw.snp_report,
                "VcekCertChain": raw.vcek_cert_chain,
            });
            if let Some(value) = endorsements {
                minimal["Endorsements"] = value;
            }
            let evidence =
                parse_evidence(&der_utf8(&serde_json::to_vec(&minimal).unwrap())).unwrap();
            assert_eq!(
                crate::snp::verify(&evidence).unwrap(),
                public_policy_digest()
            );
        }
    }

    #[test]
    fn missing_or_malformed_required_snp_and_amd_fields_are_refused() {
        let json: serde_json::Value = serde_json::from_slice(PUBLIC_CERTS).unwrap();
        let raw = raw_evidence(&certificate_der(&json, 0));
        for invalid in [
            serde_json::json!({"SnpReport": raw.snp_report}),
            serde_json::json!({"VcekCertChain": raw.vcek_cert_chain}),
            serde_json::json!({"SnpReport": "?", "VcekCertChain": raw.vcek_cert_chain}),
            serde_json::json!({"SnpReport": raw.snp_report, "VcekCertChain": "?"}),
            serde_json::json!({"SnpReport": raw.snp_report, "VcekCertChain": standard_encode(b"not a PEM chain")}),
        ] {
            assert!(parse_evidence(&der_utf8(&serde_json::to_vec(&invalid).unwrap())).is_err());
        }
    }
}
