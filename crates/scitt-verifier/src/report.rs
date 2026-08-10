//! Human-readable output.
//!
//! The design rule: a person reading this in a CI log at 2am should be able to
//! tell, without scrolling, whether to deploy — and if not, whether the problem
//! is the artifact or their own configuration.
//!
//! That rule is why the verdict comes first. An earlier version printed the
//! full statement, receipt, binding, and policy detail before the one line
//! anybody actually needed, which meant the answer was the last thing on
//! screen — and in a long pipeline log, often the part scrolled past.

use scitt_policy::{Outcome, PolicyDecision};
use scitt_receipt::{KeyLookup, Sign1, StatementFacts};

use crate::outcome::{Assessment, CheckState, Verdict};

pub fn verify(a: &Assessment) {
    headline(a);
    println!();
    detail(a);
}

/// Everything a reader needs in order to act, before any evidence.
fn headline(a: &Assessment) {
    println!("{} {}", a.verdict.banner(), a.verdict.as_str());
    println!();

    if let Some(d) = &a.primary {
        println!("Primary diagnostic:  {} ({})", d.code, d.category.as_str());
        println!("  {}", d.message);
        println!();
    }

    if let Some(decision) = &a.decision {
        println!(
            "Policy document:     {} v{}",
            decision.policy_id, decision.policy_version
        );
    }
    println!(
        "Trust material:      {}{}",
        a.trust.describe(),
        a.trust
            .issuer_scope
            .as_ref()
            .map(|s| format!(", scoped to {s}"))
            .unwrap_or_else(|| ", not scoped to an issuer".into())
    );

    // Named "decision" rather than "policy" so it cannot be misread as a
    // second mention of the policy document above it.
    println!(
        "Statement signature: {}",
        a.checks.statement_signature.label()
    );
    println!(
        "Receipt inclusion:   {}",
        a.checks.receipt_inclusion.label()
    );
    println!("Artifact binding:    {}", a.checks.artifact_binding.label());
    println!("Policy decision:     {}", a.checks.policy.label());

    // The distinction the verdict exists to make. A pass that never looked at
    // an artifact is a pass about a file, not about a deployment.
    if a.verdict == Verdict::StatementTransparent {
        println!();
        println!("NOTICE: artifact binding was not requested. This run says the statement is");
        println!("        transparent; it does not say which artifact it describes.");
    }

    if let Some(d) = &a.primary {
        println!();
        println!("Action: {}", d.action);
    }

    // Spelled out because this is the case people misread. A non-zero exit that
    // does not mean "compromised" still means "do not proceed".
    if a.verdict == Verdict::CannotEvaluate {
        println!();
        println!("This is not a pass. The tool could not answer the question;");
        println!("the usual causes are stale trust material or an unsupported feature.");
    }
}

fn detail(a: &Assessment) {
    println!("Details");

    if let Some(facts) = &a.facts {
        statement_detail(facts);
        receipts_detail(facts);
    } else {
        println!();
        println!("  The run stopped before any statement facts were established.");
    }

    println!();
    println!("  Artifact binding");
    println!("    {}", a.binding.detail);

    if let Some(decision) = &a.decision {
        policy_detail(decision);
    }

    if a.diagnostics.len() > 1 {
        println!();
        println!("  Diagnostics");
        for d in &a.diagnostics {
            println!("    [{}] {}", d.code, d.message);
        }
    }

    if !a.not_checked.is_empty() {
        println!();
        println!("  Not checked");
        for g in &a.not_checked {
            println!("    [{}] {}", g.code, g.message);
            println!("      impact: {}", g.impact);
        }
    }

    if !a.trust.limitations.is_empty() {
        println!();
        println!("  Trust limitations");
        for l in &a.trust.limitations {
            println!("    - {l}");
        }
    }
}

fn statement_detail(facts: &StatementFacts) {
    println!();
    println!("  Statement");
    println!("    claim digest        {}", facts.claim_digest);
    println!("    signed bytes        {}", facts.signed_statement_len);
    println!(
        "    algorithm           {}",
        facts
            .alg
            .map(scitt_receipt::labels::alg::name)
            .unwrap_or_else(|| "(none)".into())
    );
    println!("    signature           {}", tri(facts.signature_valid));
    if let Some(subject) = &facts.leaf_subject {
        println!("    signer              {subject}");
    }
    if let Some(iss) = &facts.cwt.iss {
        println!("    cwt iss             {iss}");
    }
    if let Some(sub) = &facts.cwt.sub {
        println!("    cwt sub             {sub}");
    }

    for problem in &facts.problems {
        println!("    ! {problem}");
    }
}

fn receipts_detail(facts: &StatementFacts) {
    if facts.receipts.is_empty() {
        println!();
        println!("  Receipts");
        println!("    none — this statement is signed, but not transparent");
        return;
    }
    for (index, r) in facts.receipts.iter().enumerate() {
        println!();
        println!("  Receipt {}", index + 1);
        println!(
            "    issuer              {}",
            r.issuer.as_deref().unwrap_or("(none)")
        );
        println!(
            "    kid                 {}",
            r.kid.as_deref().unwrap_or("(none)")
        );
        println!(
            "    registered at       {}",
            r.registered_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "(none)".into())
        );
        println!(
            "    merkle root         {}",
            r.root.as_deref().unwrap_or("(not computed)")
        );
        println!(
            "    key lookup          {}",
            r.key_lookup
                .as_ref()
                .map(describe_lookup)
                .unwrap_or("(not attempted)")
        );
        println!("    root signature      {}", tri(r.root_signature_valid));
        println!("    bound to statement  {}", tri(r.bound_to_statement));
        for problem in &r.problems {
            println!("    ! {problem}");
        }
    }
}

fn policy_detail(decision: &PolicyDecision) {
    println!();
    println!(
        "  Policy {} v{}",
        decision.policy_id, decision.policy_version
    );
    for r in &decision.results {
        // Spelled out rather than symbolic. "????" was memorable but told an
        // auditor nothing about whether the rule was skipped or unanswerable.
        let mark = match r.outcome {
            Outcome::Pass => CheckState::Pass,
            Outcome::Fail => CheckState::Fail,
            Outcome::CannotEvaluate => CheckState::CannotEvaluate,
        };
        println!("    [{}] {} — {}", mark.label(), r.name, r.detail);
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
