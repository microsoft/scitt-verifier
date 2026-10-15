use super::*;

// Public fixtures from microsoft/TEE-Attestation-Verification at the pinned
// revision; see tests/fixtures/README.md. Their REPORT_DATA is all zeros, so
// they exercise every check but freshness end to end, and freshness is tested
// on its own below.
const REPORT: &[u8] = include_bytes!("../tests/fixtures/turin_attestation_report.bin");
const VCEK: &[u8] = include_bytes!("../tests/fixtures/turin_vcek.pem");
const ASK: &[u8] = include_bytes!("../tests/fixtures/turin_kds_ask.pem");
const ARK: &[u8] = include_bytes!("../tests/fixtures/turin_kds_ark.pem");

/// The fixture's reported TCB, as a floor it exactly meets.
const FIXTURE_TCB: u64 = 0x5100_0000_0401_0101;

fn chain() -> Vec<u8> {
    [ASK, ARK].concat()
}

/// The chip ID the fixture report was signed by, read from the report rather
/// than written here, so no test string names a real device.
fn fixture_serial() -> String {
    hex_upper(&REPORT[0x1A0..0x1A8])
}

/// An invented BOM in the profile's shape, describing one packaged part with
/// the given serial and an unrelated die that shares it.
fn bom(serial: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"type": "CreationInfo", "@id": "_:c"},
            {
                "type": NODE_TYPE,
                "spdxId": "urn:example:part",
                "hardware_partNumber": "EXAMPLE-PART-1",
                "hardware_hardwareVersion": "A0",
                "hardware_serialNumber": serial,
                "hardware_category": [{"type": "DefinedType", "typeFromSource": "packaged soc"}]
            },
            {
                "type": NODE_TYPE,
                "spdxId": "urn:example:die",
                "hardware_serialNumber": serial,
                "hardware_category": [{"type": "DefinedType", "typeFromSource": "io die"}]
            }
        ]
    }))
    .unwrap()
}

const TURIN_FLOOR: [TcbFloor<'static>; 1] = [TcbFloor {
    generation: "turin",
    reported_tcb: FIXTURE_TCB,
}];

fn requirements<'a>(floor: &'a [TcbFloor<'a>]) -> Requirements<'a> {
    Requirements {
        profile: PROFILE_SPDX3_HBOM,
        category: "packaged soc",
        minimum_tcb: floor,
    }
}

fn run(payload: &[u8], report: &[u8], chain: &[u8], floor: &[TcbFloor<'_>]) -> Appraisal {
    appraise(
        Payload::Json(payload),
        Evidence {
            report: Some(report),
            vcek: Some(VCEK),
            cert_chain: Some(chain),
            nonce: None,
        },
        &requirements(floor),
    )
}

fn states(a: &Appraisal) -> Vec<(&'static str, CheckState)> {
    a.checks().iter().map(|(n, _, c)| (*n, c.state)).collect()
}

#[test]
fn the_fixture_report_is_bound_to_a_statement_naming_its_chip() {
    let a = run(&bom(&fixture_serial()), REPORT, &chain(), &TURIN_FLOOR);
    assert_eq!(
        states(&a),
        vec![
            ("device-claim", CheckState::Pass),
            ("snp-report", CheckState::Pass),
            ("tcb-floor", CheckState::Pass),
            // No nonce: the fixture was made without one.
            ("freshness", CheckState::CannotEvaluate),
            ("device-binding", CheckState::Pass),
        ],
        "{a:#?}"
    );
    assert!(a.findings.is_empty());
    assert!(a.informational.iter().any(|n| n.contains("not compared")));
}

#[test]
fn a_lowercase_serial_names_the_same_chip() {
    let a = run(
        &bom(&fixture_serial().to_ascii_lowercase()),
        REPORT,
        &chain(),
        &TURIN_FLOOR,
    );
    assert_eq!(a.device_binding.state, CheckState::Pass);
}

#[test]
fn a_statement_for_another_chip_fails_binding_and_shows_both() {
    let a = run(&bom("0011223344556677"), REPORT, &chain(), &TURIN_FLOOR);
    assert_eq!(a.device_claim.state, CheckState::Pass);
    assert_eq!(a.snp_report.state, CheckState::Pass);
    assert_eq!(a.device_binding.state, CheckState::Fail);
    let finding = a
        .findings
        .iter()
        .find(|f| f.check == "device-binding")
        .unwrap();
    assert_eq!(finding.expected.as_deref(), Some("0011223344556677"));
    assert_eq!(finding.observed.as_deref(), Some(fixture_serial().as_str()));
}

#[test]
fn a_tampered_report_authenticates_nothing() {
    let mut report = REPORT.to_vec();
    report[0x90] ^= 0x01; // measurement
    let a = run(&bom(&fixture_serial()), &report, &chain(), &TURIN_FLOOR);
    assert_eq!(a.snp_report.state, CheckState::Fail);
    for check in [&a.tcb_floor, &a.freshness, &a.device_binding] {
        assert_eq!(check.state, CheckState::CannotEvaluate);
    }
}

#[test]
fn a_report_claiming_another_chip_id_fails_authentication() {
    let mut report = REPORT.to_vec();
    report[0x1A0] ^= 0xFF;
    let a = run(
        &bom(&hex_upper(&report[0x1A0..0x1A8])),
        &report,
        &chain(),
        &TURIN_FLOOR,
    );
    assert_eq!(a.snp_report.state, CheckState::Fail);
    assert_eq!(a.device_binding.state, CheckState::CannotEvaluate);
}

#[test]
fn a_chain_not_ending_at_the_pinned_root_fails() {
    // The ASK in the ARK's place: well-formed, AMD-issued, and not the root.
    let a = run(
        &bom(&fixture_serial()),
        REPORT,
        &[ASK, ASK].concat(),
        &TURIN_FLOOR,
    );
    assert_eq!(a.snp_report.state, CheckState::Fail, "{a:#?}");
}

#[test]
fn a_chain_with_the_wrong_number_of_certificates_cannot_be_evaluated() {
    for chain in [ASK.to_vec(), [ASK, ARK, ARK].concat(), Vec::new()] {
        let a = run(&bom(&fixture_serial()), REPORT, &chain, &TURIN_FLOOR);
        assert_eq!(a.snp_report.state, CheckState::CannotEvaluate);
    }
}

#[test]
fn missing_evidence_is_cannot_evaluate_never_a_pass() {
    let a = appraise(
        Payload::Json(&bom(&fixture_serial())),
        Evidence {
            report: Some(REPORT),
            vcek: None,
            cert_chain: Some(&chain()),
            nonce: None,
        },
        &requirements(&TURIN_FLOOR),
    );
    assert_eq!(a.snp_report.state, CheckState::CannotEvaluate);
    assert!(a.snp_report.detail.contains("VCEK"));
    assert_eq!(a.device_binding.state, CheckState::CannotEvaluate);
}

#[test]
fn a_tcb_below_the_floor_fails() {
    // One component (microcode, the top byte) ahead of the fixture.
    let floor = [TcbFloor {
        generation: "turin",
        reported_tcb: 0x5200_0000_0401_0101,
    }];
    let a = run(&bom(&fixture_serial()), REPORT, &chain(), &floor);
    assert_eq!(a.tcb_floor.state, CheckState::Fail);
    assert!(a.findings.iter().any(|f| f.check == "tcb-floor"));
}

#[test]
fn a_tcb_ahead_in_one_component_and_behind_in_another_is_not_at_least_the_floor() {
    let floor = [TcbFloor {
        generation: "turin",
        reported_tcb: 0x5000_0000_0501_0101,
    }];
    let a = run(&bom(&fixture_serial()), REPORT, &chain(), &floor);
    assert_eq!(a.tcb_floor.state, CheckState::Fail);
}

#[test]
fn a_floor_for_another_generation_does_not_stand_in_for_this_one() {
    let genoa = [TcbFloor {
        generation: "genoa",
        reported_tcb: 0,
    }];
    let a = run(&bom(&fixture_serial()), REPORT, &chain(), &genoa);
    assert_eq!(a.tcb_floor.state, CheckState::CannotEvaluate);
    let a = run(&bom(&fixture_serial()), REPORT, &chain(), &[]);
    assert_eq!(a.tcb_floor.state, CheckState::CannotEvaluate);
    let unknown = [TcbFloor {
        generation: "venice",
        reported_tcb: 0,
    }];
    let a = run(&bom(&fixture_serial()), REPORT, &chain(), &unknown);
    assert_eq!(a.tcb_floor.state, CheckState::CannotEvaluate);
}

#[test]
fn freshness_requires_the_nonce_at_the_start_of_report_data() {
    let nonce: Vec<u8> = (1..=32).collect();
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&nonce);
    let text = hex_lower(&nonce);

    let mut findings = Vec::new();
    assert_eq!(
        check_freshness(&data, Some(text.as_bytes()), &mut findings).state,
        CheckState::Pass
    );
    // As Windows PowerShell writes it: a BOM, uppercase, a trailing newline.
    let written = format!("\u{feff}{}\r\n", text.to_ascii_uppercase());
    assert_eq!(
        check_freshness(&data, Some(written.as_bytes()), &mut findings).state,
        CheckState::Pass
    );
    assert!(findings.is_empty());

    let mut other = data;
    other[5] ^= 1;
    assert_eq!(
        check_freshness(&other, Some(text.as_bytes()), &mut findings).state,
        CheckState::Fail
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].expected.as_deref(), Some(text.as_str()));
}

#[test]
fn an_unusable_nonce_cannot_establish_freshness() {
    let data = [0u8; 64];
    let mut findings = Vec::new();
    for nonce in [
        None,
        Some("zz".repeat(32)),
        Some("ab".repeat(15)),
        Some("ab".repeat(65)),
        Some("00".repeat(32)),
        Some("abc".into()),
    ] {
        let check = check_freshness(&data, nonce.as_deref().map(str::as_bytes), &mut findings);
        assert_eq!(check.state, CheckState::CannotEvaluate, "{nonce:?}");
    }
    assert!(findings.is_empty());
}

#[test]
fn the_fixture_with_its_empty_nonce_is_not_fresh() {
    let a = appraise(
        Payload::Json(&bom(&fixture_serial())),
        Evidence {
            report: Some(REPORT),
            vcek: Some(VCEK),
            cert_chain: Some(&chain()),
            nonce: Some("00".repeat(32).as_bytes()),
        },
        &requirements(&TURIN_FLOOR),
    );
    assert_eq!(a.freshness.state, CheckState::CannotEvaluate);
}

#[test]
fn a_vcek_without_a_hardware_id_binds_no_chip() {
    let report = tav::verify_attestation(REPORT, &[VCEK, ASK, ARK]).unwrap();
    let claim = Claim {
        serial: REPORT[0x1A0..0x1A8].to_vec(),
        serial_text: fixture_serial(),
    };
    let mut auth = Authenticated {
        report,
        generation: Generation::Turin,
        hwid: None,
    };
    let mut findings = Vec::new();
    assert_eq!(
        check_binding(&claim, &auth, &mut findings).state,
        CheckState::Fail
    );
    auth.hwid = Some(vec![0; 8]);
    assert_eq!(
        check_binding(&claim, &auth, &mut findings).state,
        CheckState::Fail
    );
    auth.hwid = Some(REPORT[0x1A0..0x1E0].to_vec());
    assert_eq!(
        check_binding(&claim, &auth, &mut findings).state,
        CheckState::Fail,
        "a Turin VCEK names its chip in 8 bytes"
    );
    auth.hwid = Some(REPORT[0x1A0..0x1A8].to_vec());
    assert_eq!(
        check_binding(&claim, &auth, &mut findings).state,
        CheckState::Pass
    );
}

#[test]
fn the_statement_must_name_exactly_one_device_of_the_category() {
    let serial = fixture_serial();
    let mut doc: Value = serde_json::from_slice(&bom(&serial)).unwrap();
    let graph = doc["@graph"].as_array_mut().unwrap();
    graph.push(graph[1].clone());
    let two = serde_json::to_vec(&doc).unwrap();
    let a = run(&two, REPORT, &chain(), &TURIN_FLOOR);
    assert_eq!(a.device_claim.state, CheckState::Fail);
    assert!(a.device_claim.detail.contains("ambiguous"));
    assert_eq!(a.device_binding.state, CheckState::CannotEvaluate);
    // The report is still appraised, so the operator learns about it too.
    assert_eq!(a.snp_report.state, CheckState::Pass);

    let other = appraise(
        Payload::Json(&bom(&serial)),
        Evidence {
            report: None,
            vcek: None,
            cert_chain: None,
            nonce: None,
        },
        &Requirements {
            category: "compute die",
            ..requirements(&TURIN_FLOOR)
        },
    );
    assert_eq!(other.device_claim.state, CheckState::Fail);
}

#[test]
fn a_claim_this_profile_cannot_read_is_never_a_pass() {
    for (payload, state) in [
        (b"{\"@graph\":3}".to_vec(), CheckState::Fail),
        (b"[]".to_vec(), CheckState::Fail),
        (bom("not-hex!"), CheckState::Fail),
        (bom(""), CheckState::Fail),
        (br#"{"@graph":[],"@graph":[]}"#.to_vec(), CheckState::Fail),
    ] {
        let a = run(&payload, REPORT, &chain(), &TURIN_FLOOR);
        assert_eq!(
            a.device_claim.state,
            state,
            "{}",
            String::from_utf8_lossy(&payload)
        );
        assert_ne!(a.device_binding.state, CheckState::Pass);
    }
    for payload in [
        Payload::NotJson("application/cbor".into()),
        Payload::Unavailable("detached".into()),
    ] {
        let a = appraise(
            payload,
            Evidence {
                report: Some(REPORT),
                vcek: Some(VCEK),
                cert_chain: Some(&chain()),
                nonce: None,
            },
            &requirements(&TURIN_FLOOR),
        );
        assert_eq!(a.device_claim.state, CheckState::CannotEvaluate);
        assert_eq!(a.device_binding.state, CheckState::CannotEvaluate);
    }
}

#[test]
fn an_unsupported_profile_evaluates_nothing() {
    let a = appraise(
        Payload::Json(&bom(&fixture_serial())),
        Evidence {
            report: Some(REPORT),
            vcek: Some(VCEK),
            cert_chain: Some(&chain()),
            nonce: None,
        },
        &Requirements {
            profile: "spdx3-hbom/v9",
            ..requirements(&TURIN_FLOOR)
        },
    );
    assert!(a
        .checks()
        .iter()
        .all(|(_, _, c)| c.state == CheckState::CannotEvaluate));
}
