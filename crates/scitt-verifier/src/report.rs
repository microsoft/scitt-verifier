//! Human-readable output.
//!
//! The design rule: a person reading this in a CI log at 2am should be able to
//! tell, without scrolling, whether to deploy — and if not, whether the problem
//! is the artifact or their own configuration.

use scitt_policy::{Outcome, PolicyDecision};
use scitt_receipt::{KeyLookup, Sign1, StatementFacts};

use crate::evidence::BindingResult;
use crate::Verdict;

pub fn verify(
    facts: &StatementFacts,
    decision: &PolicyDecision,
    binding: &BindingResult,
    verdict: Verdict,
) {
    println!("Statement");
    println!("  claim digest        {}", facts.claim_digest);
    println!("  signed bytes        {}", facts.signed_statement_len);
    println!(
        "  algorithm           {}",
        facts
            .alg
            .map(scitt_receipt::labels::alg::name)
            .unwrap_or_else(|| "(none)".into())
    );
    println!("  signature           {}", tri(facts.signature_valid));
    if let Some(subject) = &facts.leaf_subject {
        println!("  signer              {subject}");
    }
    if let Some(iss) = &facts.cwt.iss {
        println!("  cwt iss             {iss}");
    }
    if let Some(sub) = &facts.cwt.sub {
        println!("  cwt sub             {sub}");
    }

    println!();
    if facts.receipts.is_empty() {
        println!("Receipts");
        println!("  none — this statement is signed, but not transparent");
    }
    for (index, r) in facts.receipts.iter().enumerate() {
        println!("Receipt {}", index + 1);
        println!(
            "  issuer              {}",
            r.issuer.as_deref().unwrap_or("(none)")
        );
        println!(
            "  kid                 {}",
            r.kid.as_deref().unwrap_or("(none)")
        );
        println!(
            "  registered at       {}",
            r.registered_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "(none)".into())
        );
        println!(
            "  merkle root         {}",
            r.root.as_deref().unwrap_or("(not computed)")
        );
        println!(
            "  key lookup          {}",
            r.key_lookup
                .as_ref()
                .map(describe_lookup)
                .unwrap_or("(not attempted)")
        );
        println!("  root signature      {}", tri(r.root_signature_valid));
        println!("  bound to statement  {}", tri(r.bound_to_statement));
        for problem in &r.problems {
            println!("  ! {problem}");
        }
    }

    println!();
    println!("Artifact binding");
    println!("  {}", binding.detail);

    println!();
    println!("Policy {} v{}", decision.policy_id, decision.policy_version);
    for r in &decision.results {
        let mark = match r.outcome {
            Outcome::Pass => "pass",
            Outcome::Fail => "FAIL",
            Outcome::CannotEvaluate => "????",
        };
        println!("  [{mark}] {} — {}", r.name, r.detail);
    }

    for problem in &facts.problems {
        println!("  ! {problem}");
    }

    println!();
    println!(
        "Verdict: {} (exit {})",
        verdict.as_str(),
        verdict.exit_code()
    );
    // Spelled out because this is the case people misread. A non-zero exit that
    // does not mean "compromised" still means "do not proceed".
    if verdict == Verdict::CannotEvaluate {
        println!("  This is not a pass. The tool could not answer the question;");
        println!("  the usual causes are stale trust material or an unsupported feature.");
    }
}

pub fn inspect(statement: &Sign1) -> scitt_receipt::Result<()> {
    println!("COSE_Sign1");
    println!("  tagged              {}", statement.was_tagged);
    println!(
        "  algorithm           {}",
        statement
            .alg()
            .map(scitt_receipt::labels::alg::name)
            .unwrap_or_else(|_| "(none)".into())
    );
    println!(
        "  kid                 {}",
        statement.kid().unwrap_or_else(|| "(none)".into())
    );
    println!(
        "  payload             {}",
        statement
            .payload
            .as_ref()
            .map(|p| format!("{} bytes", p.len()))
            .unwrap_or_else(|| "detached".into())
    );
    println!(
        "  x5chain             {} certificate(s)",
        statement.x5chain().len()
    );
    println!("  receipts            {}", statement.receipts().len());
    println!(
        "  claim digest        {}",
        scitt_receipt::cbor::hex(&statement.claim_digest()?)
    );
    println!(
        "  signed bytes        {}",
        statement.signed_statement_bytes()?.len()
    );

    if let Some(cwt) = statement.cwt() {
        println!("CWT claims");
        println!(
            "  iss                 {}",
            cwt.iss.unwrap_or_else(|| "(none)".into())
        );
        println!(
            "  sub                 {}",
            cwt.sub.unwrap_or_else(|| "(none)".into())
        );
        println!(
            "  iat                 {}",
            cwt.iat
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(none)".into())
        );
    }

    if let Ok(Some((subject, issuer))) = statement.leaf_names() {
        println!("Signing certificate");
        println!("  subject             {subject}");
        println!("  issuer              {issuer}");
    }

    println!();
    println!("inspect does not verify anything. Use `verify` to make a decision.");
    Ok(())
}

/// Render a tri-state honestly.
///
/// `None` prints as "not checked", never as a blank or a dash that could be
/// skimmed as a pass.
fn tri(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "valid",
        Some(false) => "INVALID",
        None => "not checked",
    }
}

fn describe_lookup(lookup: &KeyLookup) -> &'static str {
    match lookup {
        KeyLookup::Found => "found",
        KeyLookup::UnknownKid => "unknown kid — trust material may be stale",
        KeyLookup::Revoked => "REVOKED",
        KeyLookup::IssuerMismatch => "issuer mismatch — these keys are for another service",
    }
}
