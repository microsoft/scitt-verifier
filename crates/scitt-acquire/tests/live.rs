//! End-to-end acquisition against a real ledger.
//!
//! Ignored by default. Everything else in this workspace runs without a
//! network, and a test suite that quietly depends on one is a test suite that
//! fails for reasons unrelated to the change being reviewed.
//!
//! Run it deliberately:
//!
//! ```console
//! SCITT_LIVE_LEDGER=<name>.confidential-ledger.azure.com \
//!   cargo test -p scitt-acquire --test live -- --ignored --nocapture
//! ```
//!
//! What this covers that the offline tests cannot: that the identity service
//! still answers in the shape this build parses, that a CCF service certificate
//! is accepted as a TLS root by the chosen provider, and that a real ledger's
//! key set actually satisfies the service-key binding rule. Each of those is a
//! claim about a system outside this repository.

use scitt_acquire::{acquire, Diagnostic};

fn ledger() -> Option<String> {
    std::env::var("SCITT_LIVE_LEDGER")
        .ok()
        .filter(|s| !s.is_empty())
}

#[test]
#[ignore = "requires network access to a real ledger; set SCITT_LIVE_LEDGER"]
fn acquires_and_binds_against_a_real_ledger() {
    let Some(issuer) = ledger() else {
        panic!("set SCITT_LIVE_LEDGER to the ledger hostname to run this test");
    };

    let acquired = match acquire(&issuer, 0) {
        Ok(a) => a,
        Err(f) => panic!(
            "acquisition failed [{}]: {}",
            f.error.diagnostic.code(),
            f.error
        ),
    };

    let p = &acquired.provenance;
    println!("issuer      : {}", p.issuer);
    println!("provider    : {}", p.provider);
    println!("identity    : {}", p.identity_url);
    println!("keyset      : {}", p.keyset_url);
    println!("cert sha256 : {:?}", p.service_cert_sha256);
    println!("keys sha256 : {:?}", p.keyset_sha256);
    println!("service kid : {:?}", p.service_key_kid);
    println!("keys        : {}", acquired.keys.keys.len());

    assert_eq!(acquired.issuer, issuer);
    assert!(!acquired.keyset_bytes.is_empty());
    assert!(p.service_cert_sha256.is_some());
    assert!(p.keyset_sha256.is_some());

    // The binding the whole flow exists to establish: the authenticated
    // ledger's own key is in the set it served, and its identifier is derived
    // from the key material rather than asserted.
    let kid = p.service_key_kid.as_deref().expect("service key kid");
    let key = acquired
        .keys
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .expect("service key present in the acquired set");
    assert!(
        key.kid_bound_to_key,
        "service key identifier is not derived from its material"
    );
}

/// The same ledger name, reached without the identity service vouching for it,
/// must not authenticate. This is the substitution the flow is built to refuse.
#[test]
#[ignore = "requires network access; set SCITT_LIVE_LEDGER"]
fn a_ledger_that_is_not_allowlisted_still_needs_a_known_provider() {
    let Some(issuer) = ledger() else {
        panic!("set SCITT_LIVE_LEDGER to the ledger hostname to run this test");
    };

    // Same host, different apparent authority. No provider in this build covers
    // it, so it must fail before any packet is sent.
    let masqueraded = issuer.replace(".confidential-ledger.azure.com", ".example.test");
    let failed = acquire(&masqueraded, 0).unwrap_err();
    assert_eq!(failed.error.diagnostic, Diagnostic::UnsupportedProvider);
    assert!(failed.provenance.identity_url.is_empty());
}
