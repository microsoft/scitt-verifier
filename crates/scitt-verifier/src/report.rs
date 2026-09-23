//! Human-readable output.
//!
//! The completed verdict that follows the live verification transcript.
//!
//! The transcript says what ran as it happened; this renderer states the final
//! decision. The completed evidence report remains available with `--verbose`.

use scitt_policy::{Outcome, PolicyDecision};
use scitt_receipt::{CborValue, KeyLookup, Sign1, StatementFacts};
use std::io::{self, Write};

use crate::cli::{BindingMode, VerifyArgs};
use crate::outcome::{Assessment, CheckState, Verdict};
use crate::progress::safe_text;

/// How much of one untrusted value the verbose report will print.
///
/// Larger than the progress transcript's limit because the verbose report
/// exists to be read in full, but still a limit: a single unbounded value can
/// push the verdict off the top of a terminal just as effectively as a
/// forged one can imitate it.
const DETAIL_LIMIT: usize = 4096;

/// Escape a value that came from the statement, the ledger or the policy file.
///
/// Everything printed by this module that did not originate as a literal in
/// this repository passes through here. A node id, a policy id or a diagnostic
/// message quoting either can carry newlines and terminal control sequences,
/// and an unescaped newline in the verbose report is enough to print a line
/// that reads like a verdict, or to scroll a real one out of view. The
/// progress transcript already escapes for the same reason; the completed
/// report is the same text read by the same terminal.
fn safe(value: &str) -> String {
    safe_text(value, DETAIL_LIMIT)
}

/// Text longer than this is summarised unless `--verbose` is given.
const TEXT_LIMIT: usize = 64;

pub fn verify(out: &mut impl Write, a: &Assessment, verbose: bool, color: bool) -> io::Result<()> {
    writeln!(out)?;
    headline(out, a, color)?;
    if verbose {
        writeln!(out)?;
        detail(out, a)?;
    }
    Ok(())
}

/// The transcript already carries check results. Keep the final decision and
/// limitations, including diagnostics added while writing persistent records.
pub fn compact(
    out: &mut impl Write,
    a: &Assessment,
    args: &VerifyArgs,
    color: bool,
) -> io::Result<()> {
    writeln!(
        out,
        "\n{}",
        styled_verdict(a.verdict.banner(), a.verdict.as_str(), color)
    )?;
    let claim = match a.verdict {
        Verdict::StatementTransparent => "Statement signature and receipt inclusion verified; relying-party policy satisfied.",
        Verdict::ArtifactTransparent => "Supplied artifact matches the verified statement; relying-party policy satisfied.",
        Verdict::ResourceTransparent => "Verified statement and assessed node evidence satisfy the scoped resource requirements.",
        Verdict::CannotEvaluate => "This is not a pass. The tool could not answer the requested question.",
        _ => "The requested acceptance requirements were not met.",
    };
    writeln!(out, "{claim}")?;
    if a.trust.mode == "no-key-set" {
        writeln!(out, "Trust material: {}", a.trust.describe())?;
    }
    if args.adapter.is_some() {
        let scope = if a.adapter_findings.is_empty() {
            "No node evidence was appraised."
        } else if args.binding_mode == BindingMode::LiveEvidence {
            "Evidence from the authenticated target during this run; assessed snapshot only, not proof of full service membership or distinct authenticated nodes."
        } else {
            "Saved evidence only; bundle origin and service anchor are collector-asserted, not authenticated acquisition provenance. Assessed snapshot only, not proof of full service membership or distinct authenticated nodes."
        };
        writeln!(out, "Scope: {scope}")?;
    }

    for diagnostic in &a.diagnostics {
        if diagnostic.code == "ResourceAppraisalScoped"
            || a.not_checked.iter().any(|gap| {
                gap.code == diagnostic.code
                    && diagnostic.severity == crate::outcome::Severity::Warning
            })
        {
            continue;
        }
        let message = if diagnostic.code == "ResourceAppraisalNote"
            && diagnostic
                .message
                .starts_with("the statement's execution policy matches the pinned digest ")
        {
            "Statement-derived policy commitment matches the configured pin."
        } else {
            &diagnostic.message
        };
        let severity = match diagnostic.severity {
            crate::outcome::Severity::Error => "FAIL",
            crate::outcome::Severity::Warning => "NOTICE",
        };
        writeln!(
            out,
            "{severity} {} {}",
            diagnostic.code,
            safe_text(message, 384)
        )?;
        if diagnostic.severity == crate::outcome::Severity::Error {
            writeln!(out, "  Action: {}", safe_text(diagnostic.action, 384))?;
        }
    }
    if let Some(primary) = &a.primary {
        if !a
            .diagnostics
            .iter()
            .any(|d| d.code == primary.code && d.message == primary.message)
        {
            writeln!(
                out,
                "FAIL {} {}\n  Action: {}",
                primary.code,
                safe_text(&primary.message, 384),
                safe_text(primary.action, 384)
            )?;
        }
    }
    writeln!(out, "Limitations:")?;
    if let Some(adapter) = args.adapter {
        let mut shown = Vec::new();
        for check in &a.checks.adapter {
            if let Some(message) =
                crate::adapters::compact_limitation(adapter, check, &a.adapter_findings)
            {
                if !shown.contains(&message) {
                    writeln!(out, "  {message}")?;
                    shown.push(message);
                }
            }
        }
    }
    for gap in &a.not_checked {
        let message = match gap.code {
            "ArtifactBindingNotRequested" => "artifact binding was not requested; no artifact identity is established.",
            "CertificateChainNotAnchoredExternally" => "Signing chain is internally consistent with its embedded root, not independently trusted.",
            "RevocationNotChecked" => "Signing certificate revocation was not checked.",
            _ => &gap.message,
        };
        writeln!(out, "  [{}] {}", gap.code, safe_text(message, 384))?;
    }
    if args.binding_mode.is_evidence() {
        writeln!(
            out,
            "  Artifact binding was not requested; this is a resource appraisal."
        )?;
    }
    if !a.facts.as_ref().is_some_and(|facts| {
        matches!(&facts.chain_outcome,
        Some(scitt_receipt::chain::Outcome::Valid(details)) if details.anchored_externally)
    }) && !a.decision.as_ref().is_some_and(|decision| {
        decision.results.iter().any(|r| {
            r.name == "requireChainToRootSha256" && r.outcome == scitt_policy::Outcome::Pass
        })
    }) {
        writeln!(out, "  No independent publisher authorization is established by a receipt issuer assertion.")?;
    }
    for limitation in &a.trust.limitations {
        writeln!(out, "  {}", safe_text(limitation, 384))?;
    }
    if a.trust.mode == "acquired-key-set" {
        writeln!(
            out,
            "  Receipt-key freshness is not established by acquisition."
        )?;
    }
    Ok(())
}

/// Everything a reader needs in order to act, before any evidence.
fn headline(out: &mut impl Write, a: &Assessment, color: bool) -> io::Result<()> {
    writeln!(out, "Verdict")?;
    writeln!(out, "-------")?;
    writeln!(
        out,
        "{}",
        styled_verdict(a.verdict.banner(), a.verdict.as_str(), color)
    )?;
    writeln!(out)?;

    if let Some(d) = &a.primary {
        writeln!(
            out,
            "Primary diagnostic:  {} ({})",
            safe(d.code),
            d.category.as_str()
        )?;
        writeln!(out, "  {}", safe(&d.message))?;
        writeln!(out)?;
    }

    if let Some(decision) = &a.decision {
        writeln!(
            out,
            "Policy document:     {} v{}",
            safe(&decision.policy_id),
            safe(&decision.policy_version)
        )?;
    }
    writeln!(out, "Trust material:      {}", a.trust.describe())?;

    // Named "decision" rather than "policy" so it cannot be misread as a
    // second mention of the policy document above it.
    writeln!(
        out,
        "Statement signature: {}",
        a.checks.statement_signature.label()
    )?;
    writeln!(
        out,
        "Receipt inclusion:   {}",
        a.checks.receipt_inclusion.label()
    )?;
    writeln!(
        out,
        "Artifact binding:    {}",
        a.checks.artifact_binding.label()
    )?;
    writeln!(out, "Policy decision:     {}", a.checks.policy.label())?;

    // Adapter checks follow the fixed four, so the core result reads the same
    // whether or not an adapter ran. Labels are padded to the same column as
    // the lines above, and the detail sits underneath rather than inline,
    // because an adapter's reason is usually a sentence and not a word.
    for check in &a.checks.adapter {
        // Padded to the same column as the four above, but with the space
        // written explicitly rather than left to the padding. Adapter labels
        // are longer than the core ones and several overflow the column; with
        // padding alone the label and its state ran together into one word.
        let head = format!("{}:", safe(&check.label));
        writeln!(out, "{head:<20} {}", check.state.label())?;
        if !check.detail.is_empty() {
            writeln!(out, "  {}", safe(&check.detail))?;
        }
    }

    // The distinction the verdict exists to make. A pass that never looked at
    // an artifact is a pass about a file, not about a deployment.
    if a.verdict == Verdict::StatementTransparent {
        writeln!(out)?;
        writeln!(
            out,
            "NOTICE: artifact binding was not requested. This run says the statement is"
        )?;
        writeln!(
            out,
            "        transparent; it does not say which artifact it describes."
        )?;
    }

    // A resource pass is always bounded, and the bound is not a footnote: it
    // names the nodes the claim covers and says the evidence was recorded
    // rather than observed. Printed in the headline, beside the verdict,
    // because this is the sentence most likely to be dropped when the result
    // is quoted to someone else.
    if a.verdict == Verdict::ResourceTransparent {
        if let Some(scope) = a
            .diagnostics
            .iter()
            .find(|d| d.code == "ResourceAppraisalScoped")
        {
            writeln!(out)?;
            writeln!(out, "NOTICE: this pass is scoped.")?;
            writeln!(out, "        {}", safe(&scope.message))?;
        }
    }

    if let Some(d) = &a.primary {
        writeln!(out)?;
        writeln!(out, "Action: {}", safe(d.action))?;
    }

    // Spelled out because this is the case people misread. A non-zero exit that
    // does not mean "compromised" still means "do not proceed".
    if a.verdict == Verdict::CannotEvaluate {
        writeln!(out)?;
        writeln!(
            out,
            "This is not a pass. The tool could not answer the question;"
        )?;
        writeln!(
            out,
            "the usual causes are stale trust material or an unsupported feature."
        )?;
    }
    Ok(())
}

fn detail(out: &mut impl Write, a: &Assessment) -> io::Result<()> {
    writeln!(out, "Details")?;

    if let Some(facts) = &a.facts {
        statement_detail(out, facts)?;
        receipts_detail(out, facts)?;
    } else {
        writeln!(out)?;
        writeln!(
            out,
            "  The run stopped before any statement facts were established."
        )?;
    }

    writeln!(out)?;
    writeln!(out, "  Artifact binding")?;
    writeln!(out, "    {}", safe(&a.binding.detail))?;

    if let Some(decision) = &a.decision {
        policy_detail(out, decision)?;
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
        writeln!(out)?;
        writeln!(out, "  Diagnostics")?;
        for d in rest {
            writeln!(out, "    [{}] {}", safe(d.code), safe(&d.message))?;
        }
    }

    if !a.not_checked.is_empty() {
        writeln!(out)?;
        writeln!(out, "  Not checked")?;
        for g in &a.not_checked {
            writeln!(out, "    [{}] {}", safe(g.code), safe(&g.message))?;
            writeln!(out, "      impact: {}", safe(g.impact))?;
        }
    }

    if !a.trust.limitations.is_empty() {
        writeln!(out)?;
        writeln!(out, "  Trust limitations")?;
        for l in &a.trust.limitations {
            writeln!(out, "    - {}", safe(l))?;
        }
    }
    Ok(())
}

fn statement_detail(out: &mut impl Write, facts: &StatementFacts) -> io::Result<()> {
    writeln!(out)?;
    writeln!(out, "  Statement")?;
    writeln!(out, "    claim digest        {}", facts.claim_digest)?;
    writeln!(
        out,
        "    signed bytes        {}",
        facts.signed_statement_len
    )?;
    writeln!(
        out,
        "    algorithm           {}",
        facts
            .alg
            .map(scitt_receipt::labels::alg::name)
            .unwrap_or_else(|| "(none)".into())
    )?;
    writeln!(
        out,
        "    signature           {}",
        tri(facts.signature_valid)
    )?;
    if let Some(subject) = &facts.leaf_subject {
        writeln!(out, "    signing cert subject {}", safe(subject))?;
    }
    if let Some(iss) = &facts.cwt.iss {
        writeln!(out, "    statement issuer    {}", safe(iss))?;
    }
    if let Some(sub) = &facts.cwt.sub {
        writeln!(out, "    statement subject   {}", safe(sub))?;
    }

    for problem in &facts.problems {
        writeln!(out, "    ! {}", safe(problem))?;
    }
    Ok(())
}

fn receipts_detail(out: &mut impl Write, facts: &StatementFacts) -> io::Result<()> {
    if facts.receipts.is_empty() {
        writeln!(out)?;
        writeln!(out, "  Receipts")?;
        writeln!(
            out,
            "    none — this statement is signed, but not transparent"
        )?;
        return Ok(());
    }
    for (index, r) in facts.receipts.iter().enumerate() {
        writeln!(out)?;
        writeln!(out, "  Receipt {}", index + 1)?;
        writeln!(
            out,
            "    receipt issuer      {}",
            safe(r.issuer.as_deref().unwrap_or("(none)"))
        )?;
        writeln!(
            out,
            "    receipt key id      {}",
            safe(r.kid.as_deref().unwrap_or("(none)"))
        )?;
        writeln!(
            out,
            "    registered at UTC   {}",
            crate::display::optional_timestamp(r.registered_at)
        )?;
        writeln!(
            out,
            "    merkle root         {}",
            safe(r.root.as_deref().unwrap_or("(not computed)"))
        )?;
        writeln!(
            out,
            "    key lookup          {}",
            r.key_lookup
                .as_ref()
                .map(describe_lookup)
                .unwrap_or("(not attempted)")
        )?;
        writeln!(
            out,
            "    root signature      {}",
            tri(r.root_signature_valid)
        )?;
        writeln!(out, "    bound to statement  {}", tri(r.bound_to_statement))?;
        for problem in &r.problems {
            writeln!(out, "    ! {}", safe(problem))?;
        }
    }
    Ok(())
}

fn policy_detail(out: &mut impl Write, decision: &PolicyDecision) -> io::Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "  Policy {} v{}",
        safe(&decision.policy_id),
        safe(&decision.policy_version)
    )?;
    for r in &decision.results {
        // Spelled out rather than symbolic. "????" was memorable but told an
        // auditor nothing about whether the rule was skipped or unanswerable.
        let mark = match r.outcome {
            Outcome::Pass => CheckState::Pass,
            Outcome::Fail => CheckState::Fail,
            Outcome::CannotEvaluate => CheckState::CannotEvaluate,
        };
        writeln!(
            out,
            "    [{}] {} — {}",
            mark.label(),
            safe(&r.name),
            safe(&r.detail)
        )?;
    }
    Ok(())
}

/// Describe a statement without verifying any part of it.
///
/// Everything printed here is read straight off the file. None of it has been
/// checked against a key, a trust anchor, or a policy — a forged statement will
/// inspect exactly as cleanly as a genuine one. The purpose is to let someone
/// see what a statement contains *before* they have the trust material to
/// judge it, which is where most people start.
pub fn inspect(
    statement: &Sign1,
    verbose: bool,
    decoded: Option<&crate::decode::Decoded>,
) -> scitt_receipt::Result<()> {
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

    print_bucket("Protected headers", &statement.protected, verbose, true);
    print_bucket(
        "Unprotected headers",
        &statement.unprotected,
        verbose,
        false,
    );

    println!();
    println!("Payload");
    match &statement.payload {
        Some(bytes) => {
            println!("  {:<19} {}", "bytes", bytes.len());
            if let Some(cty) = statement.content_type() {
                println!("  {:<19} {}", "content type", cty);
            }
            // In a hash envelope the payload *is* a digest of something else
            // (RFC 9995). Printing sha-256 of it would be the hash of a hash —
            // a number that looks like the artifact digest a reader is hunting
            // for, and is not. Show the digest itself instead.
            if let Some(alg) = statement.payload_hash_alg() {
                println!(
                    "  {:<19} {} digest of the preimage, not the preimage itself",
                    "hash envelope",
                    scitt_receipt::labels::alg::name(alg)
                );
                println!("  {:<19} {}", "digest", scitt_receipt::cbor::hex(bytes));
                if let Some(cty) = statement.payload_preimage_content_type() {
                    println!("  {:<19} {}", "preimage cty", cty);
                }
                if let Some(loc) = statement.payload_location() {
                    println!("  {:<19} {}", "preimage at", loc);
                }
            } else {
                println!("  {:<19} {}", "sha-256", scitt_receipt::sha256_hex(bytes));
                print_payload_json(statement, bytes, verbose);
            }
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

    if let Some(decoded) = decoded {
        print_decoded(decoded);
    }

    println!();
    println!("inspect does not verify anything. Use `verify` to make a decision.");
    Ok(())
}

/// Print an explicitly requested decoded claim.
///
/// The digest leads, because it is the reason to run this: a producer that
/// embeds an encoded document usually publishes the digest of its decoded
/// bytes in a neighbouring field, and the point of the section is to put the
/// two side by side. The preview is last and bounded, so a 19 KB policy cannot
/// push the digest off the screen.
fn print_decoded(decoded: &crate::decode::Decoded) {
    println!();
    println!("Decoded claim");
    println!("  {:<19} {}", "path", decoded.path);
    println!("  {:<19} {}", "encoding", decoded.encoding);
    println!("  {:<19} {}", "decoded bytes", decoded.bytes.len());
    println!("  {:<19} {}", "sha-256", decoded.sha256);
    if !decoded.utf8 {
        println!(
            "  {:<19} the decoded bytes are not valid UTF-8, so they are shown as hex",
            "not text"
        );
    }
    // Restated here and not only at the foot of the report: this section is
    // the one a reader is most likely to screenshot or paste on its own.
    println!(
        "  {:<19} not verified — inspect authenticates nothing",
        "authentication"
    );

    println!();
    println!("  preview");
    for line in decoded.preview.lines() {
        println!("    {line}");
    }
    if decoded.preview_truncated {
        println!("    … truncated; --verbose prints it all, --decode-out writes the exact bytes");
    }
}

/// Print one COSE header bucket.
///
/// Grouping by bucket is not cosmetic. Everything under `Unprotected headers`
/// sits *outside* the signature and can be changed by anyone who handled the
/// file. A reader who cannot tell the two apart cannot tell what the signer
/// actually committed to.
/// Print a header bucket.
///
/// `addressable` says whether a `protectedHeaders` policy assertion can reach
/// these headers. Only the protected bucket qualifies, so only there is the
/// label printed in `path` form — advertising that syntax over the unprotected
/// bucket would offer an author a path that resolves to nothing.
fn print_bucket(title: &str, bucket: &CborValue, verbose: bool, addressable: bool) {
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
        print_header(key, value, verbose, addressable);
    }
}

/// The `path` segment a policy would use to address this header, or `None` for
/// a key no policy can name.
///
/// Integer labels print bare and text labels quoted, because that is precisely
/// the distinction a policy `path` draws: a JSON number and a JSON string
/// address different headers. Serialising through `serde_json` rather than
/// `Debug` keeps the quoting honest for labels outside ASCII.
fn path_segment(key: &CborValue) -> Option<String> {
    match key {
        CborValue::Int(i) => Some(i.to_string()),
        CborValue::TextString(s) => serde_json::to_string(s).ok(),
        _ => None,
    }
}

/// Print one header, naming the label when this build understands it.
///
/// Headers we do not interpret are still printed, and marked. A header nobody
/// renders is a header nobody audits.
///
/// The bracketed label is the other half of that: a name alone tells an author
/// what a header means but not how to write a rule about it, and the numbers
/// live in an IANA registry rather than in this output.
fn print_header(key: &CborValue, value: &CborValue, verbose: bool, addressable: bool) {
    let (name, known) = match key {
        CborValue::Int(i) => match scitt_receipt::labels::header_display_name(*i) {
            Some(name) => (name.to_string(), true),
            None => (i.to_string(), false),
        },
        CborValue::TextString(s) => (s.clone(), false),
        other => (scitt_receipt::cbor::type_name(other).to_string(), false),
    };

    let heading = match path_segment(key).filter(|_| addressable) {
        Some(segment) if known => format!("{name} [{segment}]"),
        Some(segment) => format!("[{segment}]"),
        None => name,
    };

    if matches!(key, CborValue::Int(i) if *i == scitt_receipt::labels::CWT_CLAIMS) {
        println!("  {heading}");
        let parent = addressable.then_some(scitt_receipt::labels::CWT_CLAIMS);
        print_cwt_claims(value, verbose, parent);
        return;
    }

    let rendered = header_value_text(key, value, verbose, known);
    if known {
        println!("  {heading:<24} {rendered}");
    } else {
        println!("  {heading:<24} {rendered}  (not interpreted)");
        // "array of 1" names the shape and stops. That is enough to prove a
        // header is there and nowhere near enough to write a rule about it,
        // so the author's next move is to decode the file by hand in another
        // tool. Descending here removes that step: every member is printed
        // with the `path` a policy would use to reach it.
        //
        // Only for headers this build does not interpret. A known label has a
        // renderer that already says something better than its raw structure.
        if let Some(root) = path_segment(key).filter(|_| addressable) {
            print_members(value, &root, verbose, 1);
        }
    }
}

/// Print the members of an uninterpreted container, each with its full policy
/// `path`.
///
/// `depth` counts segments already spent, so the walk stops where
/// `MAX_HEADER_PATH_DEPTH` stops: past it a policy cannot address the value,
/// and printing one would advertise a rule the engine refuses to parse.
fn print_members(value: &CborValue, path: &str, verbose: bool, depth: usize) {
    let members: Vec<(String, &CborValue)> = match value {
        // An integer indexes an array, which is what the policy engine does
        // with a numeric segment at this position.
        CborValue::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v))
            .collect(),
        CborValue::Map(entries) => entries
            .iter()
            .map(|(k, v)| {
                // A label that is neither an integer nor text has no `path`
                // spelling. Render it so it is still visible, but do not
                // print a path an author cannot type.
                let segment = path_segment(k).unwrap_or_else(|| scitt_receipt::render_scalar(k));
                (segment, v)
            })
            .collect(),
        _ => return,
    };

    let indent = "  ".repeat(depth + 1);
    if depth >= scitt_policy::MAX_HEADER_PATH_DEPTH {
        println!("{indent}… deeper than a policy path can address");
        return;
    }

    for (segment, member) in members {
        let child = format!("{path}, {segment}");
        let heading = format!("[{child}]");
        println!("{indent}{heading:<28} {}", scalar(member, verbose, false));
        print_members(member, &child, verbose, depth + 1);
    }
}

/// Print the payload's claims, each with the `path` a policy uses to reach it.
///
/// `bytes 72096` names the shape and stops, which is the same dead end
/// `print_members` was written to remove one level up: it proves a payload is
/// there, gives an author nothing to write a rule against, and sends them to
/// decode the file in a second tool. The fields a gate actually wants — a
/// build id, a source commit — live here and nowhere else.
///
/// Only a payload the statement *declares* to be JSON is decoded, matching
/// what `payloadJson` will read. Sniffing the bytes would print structure the
/// issuer never claimed was there, and invite a rule against it that the
/// policy engine would then refuse to evaluate.
fn print_payload_json(statement: &Sign1, bytes: &[u8], verbose: bool) {
    let Some(content_type) = statement.content_type() else {
        return;
    };
    if !scitt_policy::declares_json(&content_type) {
        return;
    }

    println!("  json");
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(document) => print_claims(&document, None, verbose, 0),
        // Loud rather than silent: a statement whose content type and payload
        // disagree is a defect, and `payloadJson` will fail against it.
        Err(why) => println!("    not valid JSON, despite the declared content type: {why}"),
    }
}

/// Print each claim in a JSON document beside its policy `path`.
///
/// `path` is `None` at the root, where there is no segment to print yet.
/// `depth` counts segments already spent, so the walk stops where
/// `MAX_HEADER_PATH_DEPTH` stops — printing a claim past it would advertise a
/// rule the policy engine refuses to parse.
fn print_claims(value: &serde_json::Value, path: Option<&str>, verbose: bool, depth: usize) {
    let members: Vec<(String, &serde_json::Value)> = match value {
        serde_json::Value::Object(fields) => fields
            .iter()
            // A key is quoted because that is how it is written in a path; a
            // bare `build` would suggest an identifier rather than a string.
            .map(|(k, v)| (format!("'{k}'"), v))
            .collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v))
            .collect(),
        _ => return,
    };

    let indent = "  ".repeat(depth + 2);
    if depth >= scitt_policy::MAX_HEADER_PATH_DEPTH {
        println!("{indent}… deeper than a policy path can address");
        return;
    }

    for (segment, member) in members {
        let child = match path {
            Some(parent) => format!("{parent}, {segment}"),
            None => segment,
        };
        let heading = format!("[{child}]");
        println!("{indent}{heading:<44} {}", json_scalar(member, verbose));
        print_claims(member, Some(&child), verbose, depth + 1);
    }
}

/// Render one JSON value for the payload listing.
///
/// A container names its shape, because its members are printed underneath it
/// on their own lines. A long string is summarised unless asked for, so a
/// 20 KB base64 blob does not bury the four fields worth reading.
fn json_scalar(value: &serde_json::Value, verbose: bool) -> String {
    match value {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) if !verbose && s.chars().count() > TEXT_LIMIT => {
            let head: String = s.chars().take(32).collect();
            format!("{} chars: {head}…", s.chars().count())
        }
        serde_json::Value::String(s) => format!("'{s}'"),
        serde_json::Value::Array(items) => format!("array of {}", items.len()),
        serde_json::Value::Object(fields) => format!("object of {}", fields.len()),
    }
}

/// An algorithm as `NAME (value)`.
///
/// The name is what a person reads; the number is what a policy has to write,
/// since `protectedHeaders` matches the integer on the wire and not this
/// rendering. Printing only the name left the author to find `ES256 = -7` in
/// an IANA registry — the same dead end the bracketed labels removed.
fn alg_display(alg: i64) -> String {
    format!("{} ({alg})", scitt_receipt::labels::alg::name(alg))
}

fn header_value_text(key: &CborValue, value: &CborValue, verbose: bool, known: bool) -> String {
    use scitt_receipt::cbor;
    use scitt_receipt::labels;

    let CborValue::Int(label) = key else {
        return scalar(value, verbose, known);
    };
    match *label {
        labels::ALG => cbor::as_int(value)
            .map(alg_display)
            .unwrap_or_else(|_| scalar(value, verbose, known)),
        // Same registry as `alg`, so the same naming applies. Left as a bare
        // integer this reads as an opaque constant, when it is the single fact
        // that decides how an artifact gets hashed.
        labels::PAYLOAD_HASH_ALG => cbor::as_int(value)
            .map(alg_display)
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

/// Print the CWT claims bucket.
///
/// `parent` carries the enclosing header's label so each claim can show its
/// **full** path. A claim is two segments deep, and that is exactly where an
/// author is most likely to guess wrong.
fn print_cwt_claims(value: &CborValue, verbose: bool, parent: Option<i64>) {
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
        let heading = match (parent, path_segment(key)) {
            (Some(outer), Some(segment)) if known => format!("{name} [{outer}, {segment}]"),
            (Some(outer), Some(segment)) => format!("[{outer}, {segment}]"),
            _ => name,
        };
        let rendered = match key {
            CborValue::Int(i)
                if matches!(*i, labels::CWT_IAT | labels::CWT_NBF | labels::CWT_EXP) =>
            {
                crate::display::optional_timestamp(cbor::as_numeric_date(claim).ok())
            }
            _ => scalar(claim, verbose, known),
        };
        println!("    {heading:<22} {rendered}");
    }
}

/// `x5t` is `[hashAlg, hashValue]`, and the algorithm is addressable on its own
/// at `[34, 0]`, so it carries its numeric form like any other.
fn x5t_text(value: &CborValue) -> Option<String> {
    use scitt_receipt::cbor;
    let items = cbor::as_array(value).ok()?;
    if items.len() != 2 {
        return None;
    }
    Some(format!(
        "{} {}",
        alg_display(cbor::as_int(&items[0]).ok()?),
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
            "  receipt key id      {}",
            summary.kid.as_deref().unwrap_or("(none)")
        );
        println!(
            "  receipt issuer      {}",
            summary.issuer.as_deref().unwrap_or("(none)")
        );
        println!(
            "  receipt subject     {}",
            summary.subject.as_deref().unwrap_or("(none)")
        );
        println!(
            "  registered at UTC   {}",
            crate::display::optional_timestamp(summary.registered_at)
        );
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

fn styled_verdict(banner: &str, verdict: &str, color: bool) -> String {
    let text = format!("{banner} {verdict}");
    if !color {
        return text;
    }
    let code = if banner == "PASS" { "1;32" } else { "1;31" };
    format!("\u{1b}[{code}m{text}\u{1b}[0m")
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
    }
}

#[cfg(test)]
mod tests {
    use super::{path_segment, styled_verdict};
    use scitt_receipt::CborValue;

    /// The completed report escapes what the transcript escapes.
    ///
    /// Node ids, policy ids and the adapter details quoting them come from the
    /// ledger and the policy file. An unescaped newline in the verbose report
    /// is enough to print a line that reads like a verdict; an unescaped
    /// control sequence can scroll the real one away. The compact path already
    /// escaped these, which made the verbose path — the one an auditor reads —
    /// the weaker of the two.
    #[test]
    fn untrusted_values_are_escaped_in_the_verbose_report_too() {
        use crate::outcome::{
            AdapterCheck, Assessment, Category, CheckState, Diagnostic, Trust, Verdict,
        };

        let hostile = "ok\nPASS statement-transparent\r\u{1b}[2J";
        let mut assessment = Assessment::incomplete(
            Verdict::ResourceFailed,
            Trust::acquired_key_set(),
            Diagnostic::error("Hostile", Category::Binding, hostile, hostile),
            Vec::new(),
        );
        assessment.checks.adapter.push(AdapterCheck {
            name: "node".into(),
            label: hostile.into(),
            state: CheckState::Fail,
            detail: hostile.into(),
        });
        assessment.binding.detail = hostile.into();

        let mut bytes = Vec::new();
        super::verify(&mut bytes, &assessment, true, false).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.contains("\\n"), "{text}");
        assert!(text.contains("\\r"), "{text}");
        assert!(text.contains("\\u{1b}"), "{text}");
        assert!(!text.contains('\r'), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
        // The forged verdict must not reach the start of a line, where a
        // reader — or a pipeline matching on the transcript — would take it
        // for this run's own.
        assert!(
            !text.contains("\nPASS statement-transparent"),
            "a hostile value produced a line that reads as a verdict:\n{text}"
        );
    }

    #[test]
    fn compact_resource_final_has_one_scope_no_duplicate_checks_and_keeps_distinct_warnings() {
        use crate::cli::{self, BindingMode, Command};
        use crate::outcome::{
            AdapterCheck, AdapterFinding, Assessment, Category, CheckState, Diagnostic, Trust,
            Verdict,
        };
        let args: Vec<_> = [
            "verify",
            "--statement",
            "statement.cose",
            "--policy",
            "policy.json",
            "--online",
            "--adapter",
            "mst-ledger",
            "--binding-mode",
            "live-evidence",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let Command::Verify(mut args) = cli::parse(&args).unwrap() else {
            panic!("verify")
        };
        let warning = Diagnostic::warning(
            "DistinctWarning",
            Category::Trust,
            "do not hide this\nwarning",
            "Read the evidence.",
        );
        let mut assessment = Assessment::incomplete(
            Verdict::ResourceTransparent,
            Trust::acquired_key_set(),
            warning,
            Vec::new(),
        );
        assessment.primary = None;
        assessment.checks.adapter.push(AdapterCheck {
            name: "ledger-identity-binding".into(),
            label: "Test binding".into(),
            state: CheckState::Pass,
            detail: "full-measurement-must-not-repeat".into(),
        });
        assessment.adapter_findings.push(AdapterFinding {
            check: "cce-policy-host-data".into(),
            subject: "long-node-id".into(),
            state: CheckState::Pass,
            detail: "full-measurement-must-not-repeat".into(),
            expected: None,
            observed: None,
        });
        for name in [
            "freshness",
            "connection-binding",
            "freshness",
            "future-excluded-check",
        ] {
            assessment.checks.adapter.push(AdapterCheck {
                name: name.into(),
                label: name.into(),
                state: CheckState::CannotEvaluate,
                detail: format!("full detail for {name}"),
            });
        }
        assessment.diagnostics.push(Diagnostic::warning(
            "ResourceAppraisalScoped",
            Category::Binding,
            "full scope with long-node-id",
            "Interpret within this scope.",
        ));
        for (mode, provenance) in [
            (
                BindingMode::LiveEvidence,
                "Evidence from the authenticated target during this run",
            ),
            (
                BindingMode::SavedEvidence,
                "bundle origin and service anchor are collector-asserted",
            ),
        ] {
            args.binding_mode = mode;
            let mut bytes = Vec::new();
            let mut progress = crate::progress::Text::compact(
                &mut bytes,
                false,
                vec![(
                    crate::progress::Stage::Adapter,
                    "Appraise node evidence".into(),
                )],
            );
            for check in &assessment.checks.adapter {
                crate::progress::Sink::emit(
                    &mut progress,
                    crate::adapters::check_event(
                        args.adapter.unwrap(),
                        check,
                        check.detail.clone(),
                        &assessment.adapter_findings,
                    ),
                );
            }
            progress.finish().unwrap();
            super::compact(&mut bytes, &assessment, &args, false).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains("\nPASS resource-transparent\n"));
            assert_eq!(text.matches("Scope:").count(), 1);
            assert!(text.contains(provenance), "{text}");
            assert!(
                text.contains("assessed snapshot only") || text.contains("Assessed snapshot only")
            );
            assert!(text.contains("NOTICE DistinctWarning do not hide this\\nwarning"));
            assert!(!text.contains("full-measurement") && !text.contains("long-node-id"));
            assert!(!text.contains("Test binding:"));
            assert_eq!(
                text.matches("Artifact binding was not requested").count(),
                1
            );
            assert!(text.contains("No independent publisher authorization"));
            let (_, limitations) = text.split_once("Limitations:\n").unwrap();
            for message in [
                "Report freshness was not established.",
                "Binding to the serving connection was not established.",
            ] {
                assert_eq!(text.matches(message).count(), 1, "{text}");
                assert!(limitations.contains(message), "{text}");
            }
            assert!(!text.contains("CANNOT EVALUATE freshness"), "{text}");
            assert!(
                !text.contains("CANNOT EVALUATE connection-binding"),
                "{text}"
            );
            assert!(
                text.contains(
                    "CANNOT EVALUATE future-excluded-check full detail for future-excluded-check"
                ),
                "{text}"
            );
        }
        let mut bytes = Vec::new();
        super::verify(&mut bytes, &assessment, false, false).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Test binding:"));
        assert!(
            text.contains("full-measurement-must-not-repeat"),
            "the standalone report remains complete without a transcript"
        );
        assert!(text.contains("full detail for freshness"));
        assert!(text.contains("full detail for connection-binding"));
    }

    /// The bracketed label is meant to be pasted into a policy `path`, so an
    /// integer label must print bare rather than quoted.
    #[test]
    fn an_integer_label_is_a_bare_number() {
        assert_eq!(path_segment(&CborValue::Int(258)).unwrap(), "258");
        assert_eq!(path_segment(&CborValue::Int(-1)).unwrap(), "-1");
    }

    /// A text label must print quoted, because a policy `path` distinguishes
    /// the two: `[15]` and `["15"]` address different headers.
    #[test]
    fn a_text_label_is_quoted() {
        let key = CborValue::TextString("external-signatures".into());
        assert_eq!(path_segment(&key).unwrap(), "\"external-signatures\"");
    }

    /// Quoting goes through a JSON serialiser, so a label needing an escape
    /// still yields something a policy author can paste. `Debug` would emit
    /// `\u{e9}` here, which is Rust syntax and not JSON.
    #[test]
    fn a_label_needing_an_escape_is_still_valid_json() {
        let key = CborValue::TextString("a\"b\\c".into());
        let rendered = path_segment(&key).unwrap();
        assert_eq!(rendered, r#""a\"b\\c""#);
        let parsed: String = serde_json::from_str(&rendered).expect("must parse as JSON");
        assert_eq!(parsed, "a\"b\\c");
    }

    /// CBOR permits any type as a map key, but a policy `path` can only name
    /// integers and text. Offering a path for anything else would be a lie.
    #[test]
    fn a_key_no_policy_can_name_has_no_path() {
        assert!(path_segment(&CborValue::ByteString(vec![1, 2, 3])).is_none());
        assert!(path_segment(&CborValue::Array(vec![])).is_none());
    }

    #[test]
    fn verdict_color_is_limited_to_the_verdict_line() {
        assert_eq!(
            styled_verdict("PASS", "statement-transparent", false),
            "PASS statement-transparent"
        );
        assert_eq!(
            styled_verdict("STOP", "untrusted", true),
            "\u{1b}[1;31mSTOP untrusted\u{1b}[0m"
        );
    }
}
