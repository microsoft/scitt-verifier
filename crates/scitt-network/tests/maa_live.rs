#[test]
#[ignore = "requires network access; set SCITT_LIVE_MAA"]
fn acquires_maa_certificates_and_service_version() {
    let host = std::env::var("SCITT_LIVE_MAA")
        .expect("set SCITT_LIVE_MAA to the MAA hostname to run this test");
    let acquired = scitt_network::maa::collect(&host).expect("authenticated MAA acquisition");
    let document: serde_json::Value =
        serde_json::from_slice(&acquired.certs_json).expect("JSON response");
    assert!(!document["keys"].as_array().expect("keys array").is_empty());
    assert!(
        acquired
            .service_version
            .as_deref()
            .is_some_and(|v| !v.is_empty()),
        "service build header was absent or empty"
    );
}
