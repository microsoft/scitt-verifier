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
use scitt_receipt::{CborValue, KeyLookup, Sign1, StatementFacts};

use crate::outcome::{Assessment, CheckState, Verdict};

/// Text longer than this is summarised unless `--verbose` is given.
const TEXT_LIMIT: usize = 64;

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

    // Everything the primary diagnostic did not already say. Gating on
    // `len() > 1` hid a lone diagnostic whenever it was not the primary one,
    // which is precisely when a reader most needs to see it.
    let primary = a.primary.as_ref();
    let rest: Vec<_> = a
        .diagnostics
        .iter()
        .filter(|d| !primary.is_some_and(|p| p.code == d.code && p.message == d.message))
        .collect();
    if !rest.is_empty() {
        println!();
        println!("  Diagnostics");
        for d in rest {
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

/// Describe a statement without verifying any part of it.
///
/// Everything printed here is read straight off the file. None of it has been
/// checked against a key, a trust anchor, or a policy — a forged statement will
/// inspect exactly as cleanly as a genuine one. The purpose is to let someone
/// see what a statement contains *before* they have the trust material to
/// judge it, which is where most people start.
pub fn inspect(statement: &Sign1, verbose: bool) -> scitt_receipt::Result<()> {
    println!("COSE_Sign1");
    println!("  {:<19} {}", "tagged", statement.was_tagged);
    println!(
        "  {:<19} {}",
        "claim digest",
        scitt_receipt::cbor::hex(&statement.claim_digest()?)
    );
    println!(
        "  {:<19} {}",
        "signed bytes",
        statement.signed_statement_bytes()?.len()
    );

    print_bucket("Protected headers", &statement.protected, verbose);
    print_bucket("Unprotected headers", &statement.unprotected, verbose);

    println!();
    println!("Payload");
    match &statement.payload {
        Some(bytes) => {
            println!("  {:<19} {}", "bytes", bytes.len());
            if let Some(cty) = statement.content_type() {
                println!("  {:<19} {}", "content type", cty);
            }
            println!("  {:<19} {}", "sha-256", scitt_receipt::sha256_hex(bytes));
        }
        None => println!("  detached — the payload is not carried in this file"),
    }

    println!();
    println!("Signature");
    println!("  {:<19} {}", "bytes", statement.signature.len());

    if verbose {
        inspect_chain(statement);
    } else if let Ok(Some((subject, issuer))) = statement.leaf_names() {
        println!();
        println!("Signing certificate");
        println!("  {:<19} {subject}", "subject");
        println!("  {:<19} {issuer}", "issuer");
    }

    inspect_receipts(statement, verbose);

    println!();
    println!("inspect does not verify anything. Use `verify` to make a decision.");
    Ok(())
}

/// Print one COSE header bucket.
///
/// Grouping by bucket is not cosmetic. Everything under `Unprotected headers`
/// sits *outside* the signature and can be changed by anyone who handled the
/// file. A reader who cannot tell the two apart cannot tell what the signer
/// actually committed to.
fn print_bucket(title: &str, bucket: &CborValue, verbose: bool) {
    println!();
    println!("{title}");
    let CborValue::Map(entries) = bucket else {
        println!("  (not a header map)");
        return;
    };
    if entries.is_empty() {
        println!("  (none)");
        return;
    }
    for (key, value) in entries {
        print_header(key, value, verbose);
    }
}

/// Print one header, naming the label when this build understands it.
///
/// Headers we do not interpret are still printed, and marked. A header nobody
/// renders is a header nobody audits.
fn print_header(key: &CborValue, value: &CborValue, verbose: bool) {
    let (name, known) = match key {
        CborValue::Int(i) => match scitt_receipt::labels::header_display_name(*i) {
            Some(name) => (name.to_string(), true),
            None => (i.to_string(), false),
        },
        CborValue::TextString(s) => (s.clone(), false),
        other => (scitt_receipt::cbor::type_name(other).to_string(), false),
    };

    if matches!(key, CborValue::Int(i) if *i == scitt_receipt::labels::CWT_CLAIMS) {
        println!("  {name}");
        print_cwt_claims(value, verbose);
        return;
    }

    let rendered = header_value_text(key, value, verbose, known);
    if known {
        println!("  {name:<19} {rendered}");
    } else {
        println!("  {name:<19} {rendered}  (not interpreted)");
    }
}

fn header_value_text(key: &CborValue, value: &CborValue, verbose: bool, known: bool) -> String {
    use scitt_receipt::cbor;
    use scitt_receipt::labels;

    let CborValue::Int(label) = key else {
        return scalar(value, verbose, known);
    };
    match *label {
        labels::ALG => cbor::as_int(value)
            .map(labels::alg::name)
            .unwrap_or_else(|_| scalar(value, verbose, known)),
        // A CCF `kid` is a byte string holding ASCII hex, not raw digest bytes.
        labels::KID => cbor::as_kid(value).unwrap_or_else(|_| scalar(value, verbose, known)),
        labels::X5T => x5t_text(value).unwrap_or_else(|| scalar(value, verbose, known)),
        labels::X5CHAIN => format!("{} certificate(s)", count_items(value)),
        labels::RECEIPTS => count_items(value).to_string(),
        labels::VERIFIABLE_DATA_STRUCTURE => match cbor::as_int(value) {
            Ok(labels::CCF_LEDGER_SHA256) => "2 (CCF_LEDGER_SHA256)".into(),
            Ok(other) => format!("{other} (not supported by this build)"),
            Err(_) => scalar(value, verbose, known),
        },
        labels::VDP => "present — see the inclusion proof below".into(),
        _ => scalar(value, verbose, known),
    }
}

fn print_cwt_claims(value: &CborValue, verbose: bool) {
    use scitt_receipt::cbor;
    use scitt_receipt::labels;

    let CborValue::Map(entries) = value else {
        println!("    {}", scalar(value, verbose, false));
        return;
    };
    for (key, claim) in entries {
        let (name, known) = match key {
            CborValue::Int(i) => match labels::cwt_claim_name(*i) {
                Some(name) => (name.to_string(), true),
                None => (i.to_string(), false),
            },
            CborValue::TextString(s) => (s.clone(), false),
            other => (cbor::type_name(other).to_string(), false),
        };
        let rendered = match key {
            CborValue::Int(i)
                if matches!(*i, labels::CWT_IAT | labels::CWT_NBF | labels::CWT_EXP) =>
            {
                timestamp(cbor::as_numeric_date(claim).ok())
            }
            _ => scalar(claim, verbose, known),
        };
        println!("    {name:<17} {rendered}");
    }
}

fn x5t_text(value: &CborValue) -> Option<String> {
    use scitt_receipt::cbor;
    let items = cbor::as_array(value).ok()?;
    if items.len() != 2 {
        return None;
    }
    Some(format!(
        "{} {}",
        scitt_receipt::labels::alg::name(cbor::as_int(&items[0]).ok()?),
        cbor::hex(cbor::as_bytes(&items[1]).ok()?)
    ))
}

/// A single certificate or receipt may be encoded bare rather than in an array.
fn count_items(value: &CborValue) -> usize {
    match value {
        CborValue::Array(items) => items.len(),
        CborValue::ByteString(_) => 1,
        _ => 0,
    }
}

/// A rendering that cannot flood a terminal.
///
/// Only values under labels this build does *not* interpret are summarised. A
/// field we chose to name is a field somebody came to read: truncating `iss`
/// would hide the exact string a policy has to match. Unknown fields are the
/// flood risk — one statement we tested against carries a 684-character
/// detached signature in a header nothing here interprets.
fn scalar(value: &CborValue, verbose: bool, known: bool) -> String {
    match value {
        CborValue::TextString(s) if !known && !verbose && s.chars().count() > TEXT_LIMIT => {
            let head: String = s.chars().take(32).collect();
            format!("{} chars: {head}…", s.chars().count())
        }
        other => scitt_receipt::render_scalar(other),
    }
}

fn inspect_chain(statement: &Sign1) {
    let chain = statement.describe_chain();
    if chain.is_empty() {
        println!();
        println!("Certificate chain");
        println!("  none — this statement carries no x5chain");
        return;
    }
    for cert in chain {
        println!();
        println!(
            "Certificate {} {}",
            cert.index + 1,
            if cert.index == 0 { "(leaf)" } else { "" }
        );
        if let Some(problem) = &cert.problem {
            println!("  problem             {problem}");
            println!("  sha-256             {}", cert.sha256);
            continue;
        }
        println!(
            "  subject             {}",
            cert.subject.as_deref().unwrap_or("(none)")
        );
        println!(
            "  issuer              {}",
            cert.issuer.as_deref().unwrap_or("(none)")
        );
        println!(
            "  version             {}",
            cert.version
                .map(|v| format!("v{}", v + 1))
                .unwrap_or_else(|| "(unknown)".into())
        );
        println!("  sha-256             {}", cert.sha256);
        println!(
            "  basic constraints   {}",
            match cert.basic_constraints {
                Some((critical, ca, path_len)) => format!(
                    "ca={ca}{}{}",
                    path_len
                        .map(|n| format!(", path len {n}"))
                        .unwrap_or_default(),
                    if critical { ", critical" } else { "" }
                ),
                None => "(not present)".into(),
            }
        );
        println!(
            "  key cert sign       {}",
            match cert.key_cert_sign {
                Some(true) => "yes",
                Some(false) => "no",
                None => "(no key usage extension)",
            }
        );
        if cert.extended_key_usage.is_empty() {
            println!("  extended key usage  (none present)");
        } else {
            for (i, oid) in cert.extended_key_usage.iter().enumerate() {
                let label = if i == 0 { "extended key usage" } else { "" };
                println!("  {label:<19} {oid}");
            }
            if cert.eku_critical == Some(true) {
                println!("  {:<19} marked critical", "");
            }
        }
        // Loud, because this predicts a verify-time rejection rather than
        // describing a property. Someone inspecting a chain that cannot pass
        // should learn it here, not from an opaque failure later.
        for oid in &cert.unhandled_critical_extensions {
            println!("  unhandled critical  {oid} — `verify` will reject this chain");
        }
    }
}

fn inspect_receipts(statement: &Sign1, verbose: bool) {
    let receipts = statement.receipts();
    if receipts.is_empty() {
        println!();
        println!("Receipts");
        println!("  none — this statement is signed, but not transparent");
        return;
    }
    for (index, bytes) in receipts.iter().enumerate() {
        println!();
        println!("Receipt {}", index + 1);
        let summary = match scitt_receipt::describe_receipt(bytes) {
            Ok(s) => s,
            Err(e) => {
                println!("  could not be read    {e}");
                continue;
            }
        };
        println!(
            "  algorithm           {}",
            summary
                .algorithm
                .map(scitt_receipt::labels::alg::name)
                .unwrap_or_else(|| "(none)".into())
        );
        println!(
            "  kid                 {}",
            summary.kid.as_deref().unwrap_or("(none)")
        );
        println!(
            "  iss                 {}",
            summary.issuer.as_deref().unwrap_or("(none)")
        );
        println!(
            "  sub                 {}",
            summary.subject.as_deref().unwrap_or("(none)")
        );
        println!("  registered at       {}", timestamp(summary.registered_at));
        println!(
            "  data structure      {}",
            match summary.vds {
                Some(scitt_receipt::labels::CCF_LEDGER_SHA256) => "2 (CCF_LEDGER_SHA256)".into(),
                Some(other) => format!("{other} (not supported by this build)"),
                None => "(none)".into(),
            }
        );
        println!(
            "  ccf txid            {}",
            summary.ccf_txid.as_deref().unwrap_or("(none)")
        );

        if verbose {
            print_inclusion_proof(&summary);
            print_labels("  protected headers  ", &summary.protected_labels);
            print_labels("  unprotected headers", &summary.unprotected_labels);
        }

        for problem in &summary.problems {
            println!("  problem             {problem}");
        }
    }
}

/// The receipt's inclusion proof, decoded but not evaluated.
///
/// These are the components the receipt stores. No hash is computed and no root
/// is reached: `verify` does that. A Merkle root printed beside an unchecked
/// proof is exactly the sort of thing a reader mistakes for evidence.
fn print_inclusion_proof(summary: &scitt_receipt::ReceiptSummary) {
    let Some(proof) = &summary.inclusion_proof else {
        return;
    };
    println!("  inclusion proof");
    println!("    {:<17} {}", "write set digest", proof.write_set_digest);
    println!("    {:<17} {}", "commit evidence", proof.commit_evidence);
    println!("    {:<17} {}", "claims digest", proof.claims_digest);
    println!("    {:<17} {} step(s)", "merkle path", proof.path.len());
    for (index, step) in proof.path.iter().enumerate() {
        println!(
            "      {index:<2} sibling {:<5} {}",
            if step.sibling_left { "left" } else { "right" },
            step.digest
        );
    }
}

fn print_labels(prefix: &str, labels: &[String]) {
    if labels.is_empty() {
        println!("{prefix} (none)");
        return;
    }
    println!("{prefix} {}", labels.join(", "));
}

/// Render a Unix timestamp as both the raw value and a UTC instant.
///
/// The raw seconds are kept because they are what a policy compares against;
/// the formatted form is there so a human notices a statement dated 1970.
fn timestamp(seconds: Option<i64>) -> String {
    let Some(s) = seconds else {
        return "(none)".into();
    };
    match utc_rfc3339(s) {
        Some(text) => format!("{s} ({text})"),
        None => format!("{s} (not a representable date)"),
    }
}

/// Format a Unix timestamp as RFC 3339 UTC, without pulling in a date crate.
///
/// Uses Howard Hinnant's civil-from-days algorithm, which is exact for the
/// proleptic Gregorian calendar. Returns `None` rather than a wrong date for
/// values that cannot be represented.
fn utc_rfc3339(seconds: i64) -> Option<String> {
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);

    let z = days.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    Some(format!(
        "{year:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60
    ))
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
