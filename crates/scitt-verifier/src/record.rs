//! The verification record.
//!
//! Two audiences, one document. A human wants to know whether to deploy; an
//! auditor six months later wants to know exactly what was checked and what was
//! not. The second audience is the harder one, which is why `notChecked` is a
//! first-class field rather than something you infer from silence.
//!
//! This record is produced on *every* path, including runs that failed before
//! a signature was checked. A pipeline that archives it on `always()` must get
//! a file when things go wrong — that is the only time anyone reads it closely.
//!
//! # Structure, and why it is shaped this way
//!
//! The document separates three things that earlier revisions ran together
//! under a single `details` bag:
//!
//! * **Observations** — `signedStatement`, `receipts`, `artifactBinding`.
//!   What the inputs say, and which signature (if any) covers each part.
//! * **The rules** — `relyingPartyPolicy`. What the relying party required.
//! * **The decision** — `appraisal`. The verdict and the reasoning.
//!
//! The observation blocks use the nouns from RFC 9943 §3 — Signed Statement,
//! Receipt, Verifiable Data Structure, Verifiable Data Proof — so that a reader
//! holding the spec needs no glossary for ours. `artifactBinding` deliberately
//! sits outside that vocabulary: SCITT has no concept of binding a statement to
//! a deployed file, so it is our invention, asserted by the operator and signed
//! by nobody. The structure should say so.
//!
//! `relyingPartyPolicy` is named in full rather than `policy` alone, because
//! RFC 9943 §3 already gives "Registration Policy" to the *transparency
//! service*. Ours is the Relying Party's — RFC 9943's own name for the role
//! this tool performs — applied long after registration, and conflating the two
//! would be a meaningful error. The ambiguity is about *whose* rules these are,
//! so the name answers that rather than describing what they do.
//!
//! # Provenance
//!
//! Every observation block carries a `provenance` object naming which key, if
//! any, covers it. This is not decoration. Within one COSE_Sign1 the fields
//! have genuinely different worth: the protected header and payload are covered
//! by the Issuer, a receipt's contents are covered by a *different* signer (the
//! transparency service), the receipt's presence in the unprotected header is
//! covered by nobody, and the artifact binding is an operator assertion. A flat
//! document invites a downstream policy engine to treat all four alike.

use scitt_receipt::{KeyLookup, ReceiptFacts};
use serde_json::{json, Map, Value};

use crate::cli::{BindingMode, VerifyArgs};
use crate::outcome::{Assessment, Checks, Diagnostic, Gap, Trust};

/// The full record: observations, rules, and decision.
///
/// `v0` is deliberate. The name changed from `evidence`, which frees the
/// numbering, and `v0` states the truth — this shape is still moving. It
/// freezes at `v1` when the repository goes public. `scitt-verifier/evidence/*`
/// is retired and will not be reused: `evidence/v1` means what v0.1.0 emitted,
/// permanently, and reusing the string for a different shape would leave a
/// consumer no way to tell them apart.
const RESULT_SCHEMA: &str = "scitt-verifier/result/v0";

/// The observations alone, for a system that makes its own decision.
///
/// A projection of the full record with `relyingPartyPolicy` and `appraisal`
/// removed. Deliberately not a separate code path: there is no way to obtain
/// this document without running a full verification, because facts about a
/// statement nobody authenticated are worth nothing, and a keyless extraction
/// door is how unauthenticated claims end up in an admission policy.
const FACTS_SCHEMA: &str = "scitt-verifier/facts/v0";

/// Which key covers a set of observations.
///
/// The two that matter most are the ones people conflate. `TransparencyService`
/// is *not* the Issuer: a receipt is signed by the log, not by whoever signed
/// the statement. `Unauthenticated` is not a soft warning — it means the bytes
/// are covered by no signature at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoveredBy {
    /// The Issuer's signature over the protected header and payload.
    StatementSigner,
    /// A transparency service's signature over the verifiable data structure.
    TransparencyService,
    /// Asserted by whoever invoked this tool. No signature.
    Operator,
    /// Present in a COSE unprotected header. Covered by no signature.
    Unauthenticated,
}

impl CoveredBy {
    fn as_str(self) -> &'static str {
        match self {
            CoveredBy::StatementSigner => "statement-signer",
            CoveredBy::TransparencyService => "transparency-service",
            CoveredBy::Operator => "operator",
            CoveredBy::Unauthenticated => "unauthenticated",
        }
    }
}

/// `signatureVerified` is `Some(false)` only when a signature was checked and
/// failed. Where no signature covers the block at all it is `null`, so that
/// "nobody signed this" can never be misread as "the signature was bad".
fn provenance(covered_by: CoveredBy, signature_verified: Option<bool>, note: &str) -> Value {
    json!({
        "coveredBy": covered_by.as_str(),
        "signatureVerified": signature_verified,
        "note": note,
    })
}

/// Whether this run got far enough to populate a block.
///
/// Distinct from a field being `null`. A `null` field means the input did not
/// carry that value; `status: not-evaluated` means we never looked. Collapsing
/// the two is how "the statement declares no SVN" becomes indistinguishable
/// from "we failed before parsing the statement" — and in Rego both would be
/// `undefined`, which reads as a failed check.
const EVALUATED: &str = "evaluated";
const NOT_EVALUATED: &str = "not-evaluated";
const NOT_REQUESTED: &str = "not-requested";

pub fn build(args: &VerifyArgs, assessment: &Assessment, now: i64) -> Value {
    let mut root = header(RESULT_SCHEMA, now);

    root.insert("inputs".into(), inputs_json(args));
    root.insert("trust".into(), trust_json(&assessment.trust));
    root.insert("signedStatement".into(), statement_json(assessment));
    root.insert("receipts".into(), receipts_json(assessment));
    root.insert("artifactBinding".into(), binding_json(args, assessment));
    root.insert("relyingPartyPolicy".into(), policy_json(assessment));
    root.insert("appraisal".into(), appraisal_json(assessment));

    Value::Object(root)
}

/// The observation blocks, without the verdict or the rules that produced it.
///
/// `appraisal` is omitted rather than emptied. A consumer that wants our
/// decision should read the full record; this document exists precisely for
/// consumers that intend to decide for themselves, and handing them a verdict
/// they did not ask for invites them to forward it as their own.
pub fn facts(args: &VerifyArgs, assessment: &Assessment, now: i64) -> Value {
    let mut root = header(FACTS_SCHEMA, now);

    root.insert("trust".into(), trust_json(&assessment.trust));
    root.insert("signedStatement".into(), statement_json(assessment));
    root.insert("receipts".into(), receipts_json(assessment));
    root.insert("artifactBinding".into(), binding_json(args, assessment));

    Value::Object(root)
}

fn header(schema: &str, now: i64) -> Map<String, Value> {
    let mut root = Map::new();
    root.insert("schemaVersion".into(), json!(schema));
    root.insert(
        "tool".into(),
        json!({
            "name": "scitt-verifier",
            "version": env!("CARGO_PKG_VERSION"),
        }),
    );
    root.insert("evaluatedAt".into(), json!(now));
    root
}

/// Local paths, kept apart from the observations.
///
/// `canonical: false` says out loud what a reader would otherwise discover the
/// hard way: these values vary by build agent and workspace, so two runs over
/// identical bytes produce records that differ here and nowhere else. A
/// consumer comparing records should skip this block.
fn inputs_json(args: &VerifyArgs) -> Value {
    json!({
        "canonical": false,
        "statement": args.statement.display().to_string(),
        "scittKeys": args.scitt_keys.display().to_string(),
        "policy": args.policy.display().to_string(),
        "artifact": args.artifact.as_ref().map(|p| p.display().to_string()),
        "issuerScope": args.issuer,
    })
}

/// How the trust material arrived, and therefore what it is worth.
///
/// "The receipt signature is valid" means nothing without "valid under whose
/// key, and who vouched for it". A consumer auditing a fleet needs to be able
/// to query for runs that trusted an unsigned key set.
fn trust_json(t: &Trust) -> Value {
    json!({
        "mode": t.mode,
        "issuerScope": t.issuer_scope,
        "limitations": t.limitations,
    })
}

fn statement_json(assessment: &Assessment) -> Value {
    let Some(facts) = &assessment.facts else {
        return json!({
            "status": NOT_EVALUATED,
            "provenance": provenance(
                CoveredBy::StatementSigner,
                None,
                "the run stopped before the statement was parsed",
            ),
        });
    };

    json!({
        "status": EVALUATED,
        "provenance": provenance(
            CoveredBy::StatementSigner,
            facts.signature_valid,
            "the protected header, CWT claims, and payload are covered by the Issuer's signature",
        ),
        "claimDigest": facts.claim_digest,
        "signedStatementBytes": facts.signed_statement_len,
        "payloadBytes": facts.payload_len,
        "algorithm": facts.alg.map(scitt_receipt::labels::alg::name),
        "signatureValid": facts.signature_valid,
        "certificateChainLength": facts.certificate_chain_len,
        "signerSubject": facts.leaf_subject,
        "signerIssuer": facts.leaf_issuer,
        "cwt": {
            "iss": facts.cwt.iss,
            "sub": facts.cwt.sub,
            "iat": facts.cwt.iat,
            "svn": facts.cwt.svn,
        },
        "problems": facts.problems,
    })
}

/// Receipts, with the provenance split that matters most in this document.
///
/// The *presence* of a receipt is unauthenticated: RFC 9943 §3 puts it in the
/// Signed Statement's unprotected header, outside the Issuer's signature, so
/// anyone can add or strip one without breaking that signature. The *contents*
/// of each receipt are covered by the transparency service's own key. Those are
/// two different trust statements and the block reports them separately.
fn receipts_json(assessment: &Assessment) -> Value {
    let Some(facts) = &assessment.facts else {
        return json!({
            "status": NOT_EVALUATED,
            "provenance": provenance(
                CoveredBy::Unauthenticated,
                None,
                "the run stopped before receipts were parsed",
            ),
            "entries": [],
        });
    };

    json!({
        "status": EVALUATED,
        "provenance": provenance(
            CoveredBy::Unauthenticated,
            None,
            "receipts are carried in the statement's unprotected header, so their presence \
             is not covered by the Issuer's signature; each entry's own fields are covered \
             by that receipt's transparency-service signature",
        ),
        "count": facts.receipts.len(),
        "entries": Value::Array(facts.receipts.iter().map(receipt_entry_json).collect()),
    })
}

fn receipt_entry_json(r: &ReceiptFacts) -> Value {
    json!({
        "provenance": provenance(
            CoveredBy::TransparencyService,
            r.root_signature_valid,
            "these fields are covered by the transparency service's signature over the \
             verifiable data structure root, not by the Issuer's signature",
        ),
        "issuer": r.issuer,
        "kid": r.kid,
        "registeredAt": r.registered_at,
        "algorithm": r.algorithm.map(scitt_receipt::labels::alg::name),
        "verifiableDataStructure": r.vds,
        "leafHash": r.leaf_hash,
        "verifiableDataStructureRoot": r.root,
        "verifiableDataProofLength": r.path_length,
        "rootSignatureValid": r.root_signature_valid,
        "boundToStatement": r.bound_to_statement,
        "claimsDigest": r.claims_digest,
        "keyLookup": r.key_lookup.as_ref().map(key_lookup_name),
        "kidBoundToKey": r.kid_bound_to_key,
        "problems": r.problems,
    })
}

/// The one block SCITT has no word for, because SCITT does not do this.
///
/// A transparent statement says an Issuer registered *something*. Which file on
/// disk that something is remains an assertion by whoever ran this tool. Always
/// recorded as declared, never inferred — a future reader must be able to see
/// that the operator asserted the relationship rather than the tool guessing it
/// from a file extension.
fn binding_json(args: &VerifyArgs, assessment: &Assessment) -> Value {
    let mode = match args.binding_mode {
        BindingMode::None => "none",
        BindingMode::PayloadBytes => "payload-bytes",
    };

    let status = if args.artifact.is_some() {
        EVALUATED
    } else {
        NOT_REQUESTED
    };

    json!({
        "status": status,
        "provenance": provenance(
            CoveredBy::Operator,
            None,
            "the binding mode and the artifact are asserted by the caller; SCITT does not \
             define a relationship between a statement and a deployed file",
        ),
        "mode": mode,
        "declared": args.artifact.is_some(),
        "bound": assessment.binding.bound,
        "detail": assessment.binding.detail,
    })
}

/// The rules, separated from the decision they produced.
///
/// Named `relyingPartyPolicy` rather than `policy`, because RFC 9943 §3
/// reserves "Registration Policy" for the transparency service's own admission
/// rules. Someone reading `policy` in a SCITT context will reasonably assume
/// the latter. Populated from the `--policy` document.
fn policy_json(assessment: &Assessment) -> Value {
    match &assessment.decision {
        Some(d) => json!({
            "status": EVALUATED,
            "policyId": d.policy_id,
            "policyVersion": d.policy_version,
            "satisfied": d.satisfied(),
            "assertions": d.results,
        }),
        None => json!({
            "status": NOT_EVALUATED,
            "policyId": null,
            "policyVersion": null,
            "satisfied": null,
            "assertions": [],
        }),
    }
}

/// The decision, and everything needed to act on it.
fn appraisal_json(assessment: &Assessment) -> Value {
    json!({
        "verdict": assessment.verdict.as_str(),
        "exitCode": assessment.verdict.exit_code(),
        "pass": assessment.verdict.is_pass(),
        "checks": checks_json(&assessment.checks),
        // The single field that answers "what stopped my deployment".
        // Everything else here is supporting detail for that one question.
        "primaryDiagnostic": match &assessment.primary {
            Some(d) => diagnostic_json(d),
            None => Value::Null,
        },
        "diagnostics": Value::Array(
            assessment.diagnostics.iter().map(diagnostic_json).collect()
        ),
        "notChecked": Value::Array(assessment.not_checked.iter().map(gap_json).collect()),
    })
}

fn checks_json(c: &Checks) -> Value {
    json!({
        "statementSignature": c.statement_signature.as_str(),
        "receiptInclusion": c.receipt_inclusion.as_str(),
        "artifactBinding": c.artifact_binding.as_str(),
        "policy": c.policy.as_str(),
    })
}

fn diagnostic_json(d: &Diagnostic) -> Value {
    json!({
        "code": d.code,
        "category": d.category.as_str(),
        "severity": d.severity.as_str(),
        "message": d.message,
        "action": d.action,
    })
}

fn gap_json(g: &Gap) -> Value {
    json!({
        "code": g.code,
        "category": g.category.as_str(),
        "message": g.message,
        "impact": g.impact,
    })
}

fn key_lookup_name(lookup: &KeyLookup) -> &'static str {
    match lookup {
        KeyLookup::Found => "found",
        KeyLookup::UnknownKid => "unknownKid",
        KeyLookup::Revoked => "revoked",
        KeyLookup::IssuerMismatch => "issuerMismatch",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Format;
    use crate::outcome::{Category, Verdict};
    use std::path::PathBuf;

    fn args() -> VerifyArgs {
        VerifyArgs {
            statement: PathBuf::from("s.cose"),
            scitt_keys: PathBuf::from("k.cbor"),
            policy: PathBuf::from("p.json"),
            issuer: None,
            artifact: None,
            binding_mode: BindingMode::None,
            format: Format::Text,
            result: None,
            facts: None,
            now: None,
        }
    }

    fn incomplete() -> Assessment {
        Assessment::incomplete(
            Verdict::CannotEvaluate,
            Trust::unsigned_key_set(None),
            Diagnostic::error("ReceiptKeyUnknown", Category::Trust, "m", "a"),
            vec![Gap::new(
                "RevocationNotChecked",
                Category::SignerIdentity,
                "Certificate revocation was not checked.",
                "a revoked signing certificate would still verify here",
            )],
        )
    }

    #[test]
    fn a_run_that_stopped_early_still_produces_every_section() {
        let record = build(&args(), &incomplete(), 0);
        for section in [
            "inputs",
            "trust",
            "signedStatement",
            "receipts",
            "artifactBinding",
            "relyingPartyPolicy",
            "appraisal",
        ] {
            assert!(
                record.get(section).is_some(),
                "missing section '{section}' on the early-failure path"
            );
        }
    }

    /// The distinction the `status` field exists to make. A consumer must be
    /// able to tell "we never looked" from "the input did not carry it".
    #[test]
    fn unreached_blocks_say_so_rather_than_being_null() {
        let record = build(&args(), &incomplete(), 0);
        assert_eq!(record["signedStatement"]["status"], NOT_EVALUATED);
        assert_eq!(record["receipts"]["status"], NOT_EVALUATED);
        assert_eq!(record["relyingPartyPolicy"]["status"], NOT_EVALUATED);
        assert!(!record["signedStatement"].is_null());
    }

    #[test]
    fn a_binding_nobody_asked_for_is_not_evaluated_and_not_failed() {
        let record = build(&args(), &incomplete(), 0);
        assert_eq!(record["artifactBinding"]["status"], NOT_REQUESTED);
        assert_eq!(record["artifactBinding"]["bound"], Value::Null);
    }

    /// Receipts arrive in the unprotected header. If this block ever claims the
    /// statement signer covers them, a consumer would be entitled to treat an
    /// attacker-supplied receipt as issuer-endorsed.
    #[test]
    fn receipt_presence_is_reported_as_unauthenticated() {
        let record = build(&args(), &incomplete(), 0);
        assert_eq!(
            record["receipts"]["provenance"]["coveredBy"],
            "unauthenticated"
        );
    }

    #[test]
    fn an_operator_assertion_never_looks_like_a_failed_signature() {
        let record = build(&args(), &incomplete(), 0);
        let p = &record["artifactBinding"]["provenance"];
        assert_eq!(p["coveredBy"], "operator");
        assert_eq!(p["signatureVerified"], Value::Null);
    }

    /// The facts document exists so another engine can decide. Shipping our
    /// verdict inside it invites that engine to forward ours as its own.
    #[test]
    fn the_facts_projection_carries_no_verdict_and_no_policy() {
        let record = facts(&args(), &incomplete(), 0);
        assert!(record.get("appraisal").is_none());
        assert!(record.get("relyingPartyPolicy").is_none());
        assert!(record.get("signedStatement").is_some());
        assert_eq!(record["schemaVersion"], FACTS_SCHEMA);
    }

    #[test]
    fn local_paths_are_marked_non_canonical() {
        let record = build(&args(), &incomplete(), 0);
        assert_eq!(record["inputs"]["canonical"], false);
    }

    /// `evidence/v1` is what v0.1.0 emitted. Reusing the string for a different
    /// shape would leave a consumer no way to distinguish them.
    #[test]
    fn the_retired_evidence_schema_name_is_never_reused() {
        let record = build(&args(), &incomplete(), 0);
        let schema = record["schemaVersion"].as_str().unwrap();
        assert!(!schema.contains("evidence"), "{schema}");
    }
}
