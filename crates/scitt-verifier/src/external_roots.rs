use std::collections::BTreeSet;
use std::time::Instant;

use scitt_network::roots::{self, Observation};
use scitt_policy::{ExternalRootSource, ExternalRoots, Policy};

use crate::progress::{self, Sink};

fn urls(policy: &Policy) -> BTreeSet<String> {
    policy
        .assertions
        .external_signatures
        .iter()
        .flatten()
        .filter_map(|rule| rule.require_chain_to_root_from_https.clone())
        .chain(
            policy
                .assertions
                .require_chain_to_root_from_https
                .iter()
                .cloned(),
        )
        .collect()
}

pub fn validate(policy: &Policy) -> Result<(), String> {
    let selected = urls(policy);
    if selected.len() > scitt_network::limits::MAX_ROOT_SOURCES {
        return Err(format!(
            "{} root endpoints were selected; the limit is {}",
            selected.len(),
            scitt_network::limits::MAX_ROOT_SOURCES
        ));
    }
    for url in selected {
        roots::validate_url(&url).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn acquire(policy: &Policy, deadline: Instant, progress: &mut dyn Sink) -> Vec<Observation> {
    acquire_with(policy, |url| {
        progress.emit(
            progress::Event::finding(
                progress::Stage::ReceiptKeys,
                "root-sources",
                Some(url.to_string()),
                progress::State::Started,
                "acquiring policy-authorized signing roots over HTTPS",
            )
            .detail(),
        );
        let observation = roots::acquire(url, crate::wall_clock(), deadline);
        let (state, detail) = match &observation.outcome {
            Ok(bundle) => (
                progress::State::Done,
                format!(
                    "{} signing root certificate(s) acquired",
                    bundle.root_sha256.len()
                ),
            ),
            Err(error) => (progress::State::CannotEvaluate, error.to_string()),
        };
        progress.emit(progress::Event::finding(
            progress::Stage::ReceiptKeys,
            "root-sources",
            Some(url.to_string()),
            state,
            detail,
        ));
        observation
    })
}

fn acquire_with(policy: &Policy, mut fetch: impl FnMut(&str) -> Observation) -> Vec<Observation> {
    urls(policy).iter().map(|url| fetch(url)).collect()
}

pub fn policy_sources(observations: &[Observation]) -> Vec<ExternalRootSource> {
    observations
        .iter()
        .map(|observation| ExternalRootSource {
            url: observation.url.clone(),
            outcome: observation
                .outcome
                .as_ref()
                .map(|bundle| ExternalRoots {
                    acquired_at: observation.acquired_at,
                    response_sha256: bundle.sha256.clone(),
                    encoding: bundle.encoding.as_str().into(),
                    root_sha256: bundle.root_sha256.clone(),
                })
                .map_err(|error| format!("[{}] {error}", error.diagnostic.code())),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scitt_network::{AcquireError, Diagnostic};

    fn policy(urls: &[&str]) -> Policy {
        Policy::from_json(
            &serde_json::to_vec(&serde_json::json!({
                "policyId": "synthetic-root-sources",
                "policyVersion": "1",
                "assertions": { "externalSignatures": urls.iter().map(|url| {
                    serde_json::json!({
                        "path": ["external-signature", 0],
                        "signedOver": "payload",
                        "requireChainToRootFromHttps": url,
                    })
                }).collect::<Vec<_>>() },
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn requests_are_deduplicated_and_selected_only_by_policy() {
        let mut policy = policy(&[
            "https://b.example/roots.pem",
            "https://a.example/roots.pem",
            "https://b.example/roots.pem",
        ]);
        policy.assertions.require_chain_to_root_from_https =
            Some("https://a.example/roots.pem".into());
        validate(&policy).unwrap();
        let mut requested = Vec::new();
        let observations = acquire_with(&policy, |url| {
            requested.push(url.to_string());
            Observation {
                url: url.into(),
                acquired_at: 7,
                outcome: Err(AcquireError::new(Diagnostic::Transport, "synthetic outage")),
            }
        });
        assert_eq!(
            requested,
            ["https://a.example/roots.pem", "https://b.example/roots.pem"]
        );
        let inputs = policy_sources(&observations);
        assert_eq!(inputs.len(), 2);
        assert!(inputs.iter().all(|source| source
            .outcome
            .as_ref()
            .unwrap_err()
            .contains("synthetic outage")));
    }

    #[test]
    fn all_destinations_and_the_total_count_are_validated_before_acquisition() {
        let invalid = policy(&[
            "https://a.example/roots.pem",
            "https://user@b.example/roots.pem",
        ]);
        assert!(validate(&invalid).unwrap_err().contains("unusable"));
        let mut invalid_statement = policy(&["https://a.example/roots.pem"]);
        invalid_statement
            .assertions
            .require_chain_to_root_from_https =
            Some("https://user@publisher.example/root.crt".into());
        assert!(validate(&invalid_statement)
            .unwrap_err()
            .contains("unusable"));

        let urls: Vec<String> = (0..=scitt_network::limits::MAX_ROOT_SOURCES)
            .map(|i| format!("https://roots-{i}.example/roots.pem"))
            .collect();
        let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
        assert!(validate(&policy(&urls)).unwrap_err().contains("limit"));
        let mut combined = policy(&urls[..scitt_network::limits::MAX_ROOT_SOURCES]);
        combined.assertions.require_chain_to_root_from_https =
            Some("https://publisher.example/root.crt".into());
        assert!(validate(&combined).unwrap_err().contains("limit"));
    }

    #[test]
    fn statement_root_authorization_reaches_json_and_only_removes_the_appropriate_gaps() {
        use crate::cli::{self, BindingMode, Command};
        use crate::outcome::{Acquisition, Assessment, BindingResult, Category, Trust, Verdict};

        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/critical-eku/expected.json"))
                .unwrap();
        let policy = Policy::from_json(
            &serde_json::to_vec(&serde_json::json!({
                "policyId": "synthetic-publisher-roots",
                "policyVersion": "1",
                "assertions": {
                    "requireChainToRootFromHttps": "https://publisher.example/root.crt",
                    "requireEku": expected["leafEkuOids"],
                    "certificateValidAtSigningTime": true,
                },
            }))
            .unwrap(),
        )
        .unwrap();
        let statement = include_bytes!("../tests/fixtures/critical-eku/valid.cose");
        let der = scitt_receipt::Sign1::parse(statement)
            .unwrap()
            .x5chain()
            .last()
            .unwrap()
            .clone();
        let keys = scitt_receipt::LedgerKeySet::from_cose_key_set(include_bytes!(
            "../tests/fixtures/critical-eku/keys.cbor"
        ))
        .unwrap();
        let facts = scitt_receipt::verify_statement_with(
            statement,
            &keys,
            &scitt_receipt::VerifyOptions {
                chain: Some(scitt_receipt::chain::Options {
                    required_eku: policy.assertions.require_eku.clone().unwrap(),
                    ..Default::default()
                }),
            },
        )
        .unwrap();
        let arguments = [
            "verify",
            "--statement",
            "statement.cose",
            "--policy",
            "policy.json",
            "--online",
        ]
        .map(String::from);
        let Command::Verify(args) = cli::parse(&arguments).unwrap() else {
            panic!("expected verification arguments")
        };
        for authorized in [false, true] {
            let observations = acquire_with(&policy, |url| Observation {
                url: url.into(),
                acquired_at: 7,
                outcome: Ok(roots::RootBundle {
                    bytes: der.clone(),
                    sha256: scitt_receipt::sha256_hex(&der),
                    root_sha256: vec![if authorized {
                        scitt_receipt::sha256_hex(&der)
                    } else {
                        "00".repeat(32)
                    }],
                    encoding: roots::Encoding::Der,
                }),
            });
            let decision = policy.evaluate_statement_with_external_roots(
                &facts,
                0,
                &policy_sources(&observations),
            );
            let verdict = crate::decide(
                &facts,
                &BindingResult::not_requested(),
                &decision,
                BindingMode::None,
                false,
            );
            assert_eq!(
                verdict,
                if authorized {
                    Verdict::StatementTransparent
                } else {
                    Verdict::PolicyFailed
                }
            );
            let gaps = crate::gaps(&args, Some(&facts), Some(&decision));
            assert_eq!(
                gaps.iter()
                    .any(|gap| gap.code == "CertificateChainNotAnchoredExternally"),
                !authorized
            );
            assert!(gaps
                .iter()
                .any(|gap| gap.code == "RootSourceFreshnessNotChecked"));
            assert!(gaps.iter().any(|gap| gap.code == "RevocationNotChecked"));
            let mut assessment = Assessment::incomplete(
                verdict,
                Trust::acquired_key_set(),
                crate::outcome::Diagnostic::warning("Placeholder", Category::Trust, "", ""),
                gaps,
            );
            assessment.facts = Some(facts.clone());
            assessment.decision = Some(decision);
            assessment.primary = None;
            assessment.diagnostics.clear();
            assessment.acquisition = Some(Acquisition {
                selected: Vec::new(),
                acquired: Vec::new(),
                failed: Vec::new(),
                not_attempted: None,
                configurations: Vec::new(),
                external_roots: observations,
            });
            let record = crate::record::build(&args, &assessment, 0);
            let projected = crate::record::facts(&args, &assessment, 0);
            let signer = &record["signedStatement"];
            assert_eq!(signer["rootSourceMatched"], authorized);
            assert_eq!(signer["rootSource"]["material"]["encoding"], "der");
            assert_eq!(signer["certificateChain"]["anchoredExternally"], false);
            assert_eq!(signer["certificateChain"]["pathLength"], 3);
            assert_eq!(
                signer["rootSource"],
                projected["signedStatement"]["rootSource"]
            );
            assert_eq!(
                signer["rootSourceMatched"],
                projected["signedStatement"]["rootSourceMatched"]
            );
            assert_eq!(record["acquisition"]["rootSources"][0]["encoding"], "der");
            assert_eq!(
                record["acquisition"]["rootSources"][0]["responseSha256"],
                scitt_receipt::sha256_hex(&der)
            );
            let mut text = Vec::new();
            crate::report::verify(&mut text, &assessment, true, false).unwrap();
            let text = String::from_utf8(text).unwrap();
            assert_eq!(
                text.contains("No independent publisher authorization"),
                !authorized,
                "{text}"
            );
        }
    }

    #[test]
    fn authenticated_roots_reach_verdicts_limitations_and_both_json_projections() {
        use crate::cli::{self, BindingMode, Command};
        use crate::outcome::{Acquisition, Assessment, BindingResult, Category, Trust, Verdict};

        let urls = ["https://supplier.example/roots.pem"];
        let pem = include_bytes!("../tests/fixtures/external-chain/roots.pem");
        let roots = scitt_receipt::chain::parse_pem_certificates(std::str::from_utf8(pem).unwrap())
            .unwrap();
        let keys = scitt_receipt::LedgerKeySet::from_cose_key_set(include_bytes!(
            "../tests/fixtures/external-chain/keys.cbor"
        ))
        .unwrap();
        let facts = scitt_receipt::verify_statement(
            include_bytes!("../tests/fixtures/external-chain/valid.cose"),
            &keys,
        )
        .unwrap();
        let arguments = [
            "verify",
            "--statement",
            "statement.cose",
            "--policy",
            "policy.json",
            "--online",
        ]
        .map(String::from);
        let Command::Verify(args) = cli::parse(&arguments).unwrap() else {
            panic!("expected verification arguments")
        };
        for unanchored_rule in [false, true] {
            let mut policy = policy(&urls);
            if unanchored_rule {
                let rules = policy.assertions.external_signatures.as_mut().unwrap();
                let mut unanchored = rules[0].clone();
                unanchored.require_chain_to_root_from_https = None;
                rules.push(unanchored);
            }
            let observations = acquire_with(&policy, |url| Observation {
                url: url.into(),
                acquired_at: 7,
                outcome: Ok(roots::RootBundle {
                    bytes: pem.to_vec(),
                    sha256: scitt_receipt::sha256_hex(pem),
                    root_sha256: roots
                        .iter()
                        .map(|der| scitt_receipt::sha256_hex(der))
                        .collect(),
                    encoding: roots::Encoding::Pem,
                }),
            });
            let decision = policy.evaluate_statement_with_external_roots(
                &facts,
                0,
                &policy_sources(&observations),
            );
            let binding = BindingResult::not_requested();
            let verdict = crate::decide(&facts, &binding, &decision, BindingMode::None, false);
            assert_eq!(verdict, Verdict::StatementTransparent);
            let gaps = crate::gaps(&args, Some(&facts), Some(&decision));
            assert_eq!(
                gaps.iter()
                    .any(|gap| gap.code == "ExternalSignerChainNotValidated"),
                unanchored_rule,
            );
            assert!(gaps
                .iter()
                .any(|gap| gap.code == "RootSourceFreshnessNotChecked"));
            let mut assessment = Assessment::incomplete(
                verdict,
                Trust::acquired_key_set(),
                crate::outcome::Diagnostic::warning("Placeholder", Category::Trust, "", ""),
                gaps,
            );
            assessment.facts = Some(facts.clone());
            assessment.decision = Some(decision);
            assessment.primary = None;
            assessment.diagnostics.clear();
            assessment.acquisition = Some(Acquisition {
                selected: Vec::new(),
                acquired: Vec::new(),
                failed: Vec::new(),
                not_attempted: None,
                configurations: Vec::new(),
                external_roots: observations,
            });
            let record = crate::record::build(&args, &assessment, 0);
            let projected = crate::record::facts(&args, &assessment, 0);
            let acquisition = &record["acquisition"]["rootSources"][0];
            assert_eq!(acquisition["status"], "acquired");
            assert_eq!(acquisition["acquiredAt"], 7);
            assert_eq!(acquisition["authentication"], "https-webpki");
            assert_eq!(
                acquisition["responseSha256"],
                scitt_receipt::sha256_hex(pem)
            );
            assert_eq!(acquisition["encoding"], "pem");
            let evidence = &record["signedStatement"]["externalSignatures"][0];
            assert_eq!(evidence["rootSourceMatched"], true);
            assert_eq!(evidence["rootSource"]["material"]["acquiredAt"], 7);
            assert_eq!(projected["acquisition"], record["acquisition"]);
            assert_eq!(
                projected["signedStatement"]["externalSignatures"],
                record["signedStatement"]["externalSignatures"],
            );
        }
    }
}
