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

use crate::cli::{BindingMode, TrustSource, VerifyArgs};
use crate::outcome::{
    required_checks_pass, Acquisition, AdapterCheck, AdapterFinding, Assessment, Binding, Checks,
    Diagnostic, Gap, Trust,
};

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
    // Additive, and present only when a fetch was part of the run. A record
    // from an offline run has no acquisition block at all, rather than an
    // empty one: "did not fetch" and "fetched nothing" are different runs, and
    // a consumer keying on the field's presence should get the right answer
    // without having to read its contents.
    if let Some(a) = &assessment.acquisition {
        root.insert("acquisition".into(), acquisition_json(a));
        root.insert("serviceConfiguration".into(), configuration_json(a));
    }
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
    // Provenance is an observation — which endpoint was asked, what it served,
    // when — not a conclusion, so it belongs here by the same rule that keeps
    // the policy verdict out. Without it a reader asking "whose key was this
    // checked against" gets `trust` saying the key set was acquired and
    // nothing at all saying from where.
    if let Some(a) = &assessment.acquisition {
        root.insert("acquisition".into(), acquisition_json(a));
        // An observation too — what the service said, when, over which
        // connection — so it belongs here by the same rule.
        root.insert("serviceConfiguration".into(), configuration_json(a));
    }
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
        // Null in online mode: there was no key file. A path here would name a
        // file the run never read, and a reader reproducing the run from this
        // record would go looking for it.
        "scittKeys": match &args.trust {
            TrustSource::Local(p) => Value::from(p.display().to_string()),
            TrustSource::Online { .. } => Value::Null,
        },
        "policy": args.policy.display().to_string(),
        "artifact": args.artifact.as_ref().map(|p| p.display().to_string()),
        // Named separately from the ledger key material above because the two
        // are different trust decisions: these roots say who may have signed
        // the statement, the key set says which ledger may have registered it.
        // A record that mentioned only one would leave half the operator's
        // configuration invisible to an auditor.
        "trustedRoots": args.trusted_roots.as_ref().map(|p| p.display().to_string()),
    })
}

/// What chain validation established, projected verbatim.
///
/// Success used to be legible only as the *absence* of a warning, which asks a
/// downstream consumer to infer a positive from a negative — and leaves
/// `--facts`, which carries no policy messages or gaps at all, with nothing
/// about the chain whatsoever. The anchor digest and whether it came from
/// outside are the two values a later audit actually needs: together they say
/// which CA this statement leads to and whether anyone but its author vouched
/// for it.
fn chain_json(facts: &scitt_receipt::StatementFacts) -> Value {
    use scitt_receipt::chain::Outcome;

    let Some(outcome) = &facts.chain_outcome else {
        return json!({ "status": NOT_EVALUATED });
    };

    match outcome {
        Outcome::Valid(details) => json!({
            "status": EVALUATED,
            "outcome": "valid",
            "rootSha256": hex(&details.root_sha256),
            "anchoredExternally": details.anchored_externally,
            "validatedAt": details.validated_at,
            "pathLength": details.path_len,
            "pathNotBefore": details.path_not_before,
            "pathNotAfter": details.path_not_after,
        }),
        Outcome::Invalid(reason) => json!({
            "status": EVALUATED,
            "outcome": "invalid",
            "reason": reason,
        }),
        Outcome::Insufficient(reason) => json!({
            "status": EVALUATED,
            "outcome": "insufficient",
            "reason": reason,
        }),
        Outcome::Unsupported(reason) => json!({
            "status": EVALUATED,
            "outcome": "unsupported",
            "reason": reason,
        }),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What online mode asked for, what it got, and what it could not get.
///
/// Every selected issuer appears exactly once, whether it answered or not. A
/// block listing only successes would let a partial outage read as a complete
/// picture, which is the failure this whole feature has to avoid: the point of
/// fetching keys is to know whose keys they are, and a record that quietly
/// omits the ledger nobody could reach does not support that.
///
/// The digests are the auditable part. `serviceCertSha256` says which
/// certificate the connection was authenticated to, and `keysetSha256` says
/// exactly which bytes were used, so a later run can be compared against this
/// one without trusting either run's conclusion.
fn acquisition_json(a: &Acquisition) -> Value {
    let mut ledgers: Vec<Value> = a
        .acquired
        .iter()
        .map(|x| provenance_json(&x.provenance, true))
        .chain(
            a.failed
                .iter()
                .map(|x| provenance_json(&x.provenance, false)),
        )
        .collect();
    // Stable order regardless of which finished first, so two records over the
    // same inputs differ only where the inputs differ.
    ledgers.sort_by(|l, r| l["issuer"].as_str().cmp(&r["issuer"].as_str()));

    json!({
        "selected": a.selected,
        "ledgers": ledgers,
        // Present when selection stopped before any request. Explains an empty
        // `selected` rather than leaving the reader to guess between "nothing
        // was allowlisted" and "nothing was asked".
        "notAttempted": a.not_attempted,
    })
}

/// What a service's current configuration can and cannot be used for.
///
/// Fixed strings, carried in every record that has the block, because the
/// record outlives the run and a reader six months later has only the record.
pub const CONFIGURATION_LIMITATIONS: [&str; 4] = [
    "This is the service's configuration when this run asked, not the policy any \
     statement was registered under, and not a prediction of whether this statement \
     would be accepted today.",
    "It is not signed and not bound to any receipt. It was authenticated only by the \
     TLS connection it arrived on; a saved copy keeps the bytes and loses that.",
    "A registration policy is the transparency service's, not the relying party's. It \
     was not executed, and it did not relax, satisfy, or replace any assertion in the \
     relying-party policy.",
    "It says nothing about the code the service runs; it is not runtime attestation.",
];

/// The current configuration of each selected service, for audit.
///
/// Its own top-level block rather than part of `acquisition`, because
/// everything in `acquisition` fed the verdict and nothing here did.
/// `affectsVerdict: false` says so to a consumer that reads fields rather than
/// documentation.
fn configuration_json(a: &Acquisition) -> Value {
    use scitt_network::configuration::Outcome;

    let ledgers: Vec<Value> = a
        .configurations
        .iter()
        .map(|o| {
            let (status, configuration, bytes, sha256, failure, reason) = match &o.outcome {
                Outcome::Retrieved(c) => (
                    "retrieved",
                    Value::Object(c.document.clone()),
                    json!(c.bytes.len()),
                    json!(c.sha256),
                    Value::Null,
                    Value::Null,
                ),
                Outcome::Failed(e) => (
                    "failed",
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    json!({ "code": e.diagnostic.code(), "detail": e.detail }),
                    Value::Null,
                ),
                Outcome::NotAttempted(why) => (
                    "not-attempted",
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    json!(why),
                ),
            };
            json!({
                "issuer": o.issuer,
                "endpoint": o.url,
                "status": status,
                "observedAt": o.observed_at,
                "tlsServiceCertSha256": o.service_cert_sha256,
                "responseSha256": sha256,
                "responseBytes": bytes,
                "configuration": configuration,
                "failure": failure,
                "reason": reason,
            })
        })
        .collect();

    json!({
        "kind": "current-observation",
        "affectsVerdict": false,
        "limitations": CONFIGURATION_LIMITATIONS,
        "ledgers": ledgers,
    })
}

fn provenance_json(p: &scitt_network::Provenance, acquired: bool) -> Value {
    json!({
        "issuer": p.issuer,
        "acquired": acquired,
        "provider": p.provider,
        "identityUrl": p.identity_url,
        "keysetUrl": p.keyset_url,
        "serviceCertSha256": p.service_cert_sha256,
        "keysetSha256": p.keyset_sha256,
        "serviceKeyKid": p.service_key_kid,
        "acquiredAt": p.acquired_at,
        "ambiguousKids": p.ambiguous_kids,
        "failure": p.failure.as_ref().map(|e| json!({
            "code": e.diagnostic.code(),
            "detail": e.detail,
            "configuration": e.diagnostic.is_configuration(),
        })),
    })
}

/// How the trust material arrived, and therefore what it is worth.///
/// "The receipt signature is valid" means nothing without "valid under whose
/// key, and who vouched for it". A consumer auditing a fleet needs to be able
/// to query for runs that trusted an unsigned key set.
fn trust_json(t: &Trust) -> Value {
    json!({
        "mode": t.mode,
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
        "certificateChain": chain_json(facts),
        // Named for registration rather than signing: the time is the ledger's
        // countersigned `iat`, which witnesses when the statement was
        // registered and is the closest independently attested instant there
        // is. Null when the chain did not validate or no verified receipt
        // carried a time.
        "certificatesValidAtRegistration": facts.certificates_valid_at_signing_time,
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
        BindingMode::PayloadDigest => "payload-digest",
        // Recorded in the artifact-binding block as `none`, because that is
        // exactly what it is here: this mode binds the statement to a service,
        // not to a file, and the artifact block must not imply an artifact
        // comparison happened. The resource appraisal is recorded separately,
        // under the adapter checks.
        BindingMode::SavedEvidence | BindingMode::LiveEvidence => "none",
    };

    // Derived from the outcome, not from whether `--artifact` was passed.
    // Keying it off the flag reported `evaluated` for a run that was asked to
    // compare and could not — an unreadable artifact, or a detached payload —
    // so the block claimed an evaluation it did not have.
    let status = match assessment.binding.outcome {
        Binding::NotRequested => NOT_REQUESTED,
        Binding::Bound | Binding::Mismatch => EVALUATED,
        Binding::CannotCompare => NOT_EVALUATED,
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
        // Which adapter, if any, was asked to appraise a resource. Recorded
        // beside the binding mode because that is what selected it, and
        // because the adapter's identity is part of what a future reader needs
        // in order to know what the adapter checks below actually mean.
        "adapter": match args.adapter {
            Some(a) => Value::String(a.as_str().to_string()),
            None => Value::Null,
        },
        "declared": args.artifact.is_some(),
        "bound": assessment.binding.as_json_bool(),
        "detail": assessment.binding.detail,
    })
}

/// The rules, separated from the decision they produced.
///
/// Named `relyingPartyPolicy` rather than `policy`, because RFC 9943 §3
/// reserves "Registration Policy" for the transparency service's own admission
/// rules. Someone reading `policy` in a SCITT context will reasonably assume
/// the latter. Populated from the `--policy` document.
///
/// `satisfied` answers "was the relying party's policy met", and the policy
/// document configures adapter requirements as well as statement assertions.
/// It therefore cannot be the assertion outcome alone: a required adapter check
/// that failed, or that could not run, means the document was not satisfied
/// however well the statement itself read. The narrower fact is not lost —
/// `assertionsSatisfied` keeps it, and `assertions` still lists each result —
/// but the field a gate is most likely to read is the one that accounts for
/// everything the policy asked for.
fn policy_json(assessment: &Assessment) -> Value {
    // Every check the adapter declared *required* must have passed. Its other
    // checks are excluded deliberately: an adapter reports findings that bound
    // a claim as well as ones that decide it, and `freshness` against CCF can
    // never pass, so reading "every reported check passed" here would make
    // every genuine `resource-transparent` run report an unsatisfied policy.
    //
    // The rule is `required_checks_pass`, the same one the verdict is derived
    // from, so this field cannot come to disagree with the exit code beside it.
    // A run that selected no adapter has no contract and no results, and keeps
    // the old meaning.
    let adapters_satisfied = assessment.checks.adapter.is_empty()
        && assessment.checks.adapter_required.is_empty()
        || required_checks_pass(
            &assessment.checks.adapter,
            &assessment.checks.adapter_required,
        );
    match &assessment.decision {
        Some(d) => json!({
            "status": EVALUATED,
            "policyId": d.policy_id,
            "policyVersion": d.policy_version,
            "satisfied": d.satisfied() && adapters_satisfied,
            "assertionsSatisfied": d.satisfied(),
            "assertions": d.results,
        }),
        None => json!({
            "status": NOT_EVALUATED,
            "policyId": null,
            "policyVersion": null,
            "satisfied": null,
            "assertionsSatisfied": null,
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
        "adapterFindings": Value::Array(
            assessment.adapter_findings.iter().map(adapter_finding_json).collect()
        ),
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
        // Always present, empty when no adapter ran. A consumer must not have
        // to tell an absent key from an empty list to know whether an adapter
        // contributed anything.
        "adapter": Value::Array(c.adapter.iter().map(adapter_check_json).collect()),
    })
}

fn adapter_check_json(c: &AdapterCheck) -> Value {
    json!({
        "name": c.name,
        "label": c.label,
        "state": c.state.as_str(),
        "detail": c.detail,
    })
}

fn adapter_finding_json(f: &AdapterFinding) -> Value {
    json!({
        "check": f.check,
        "subject": f.subject,
        "state": f.state.as_str(),
        "detail": f.detail,
        "expected": f.expected,
        "observed": f.observed,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Format;
    use crate::outcome::{AdapterFinding, CheckState};
    use crate::outcome::{Category, Verdict};
    use std::path::PathBuf;

    fn args() -> VerifyArgs {
        VerifyArgs {
            statement: PathBuf::from("s.cose"),
            trust: TrustSource::Local(PathBuf::from("k.cbor")),
            policy: PathBuf::from("p.json"),
            artifact: None,
            binding_mode: BindingMode::None,
            adapter: None,
            evidence: None,
            save_evidence: None,
            format: Format::Text,
            verbose: false,
            result: None,
            facts: None,
            save_trust: None,
            trusted_roots: None,
            now: None,
        }
    }

    fn incomplete() -> Assessment {
        Assessment::incomplete(
            Verdict::CannotEvaluate,
            Trust::unsigned_key_set(),
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

    /// A consumer must not have to tell a missing key from an empty list to
    /// know whether an adapter contributed anything. If this key ever becomes
    /// conditional, "no adapter ran" and "an older verifier wrote this record"
    /// stop being distinguishable, and the second one is not a claim about the
    /// deployment at all.
    #[test]
    fn adapter_checks_are_always_an_array_even_when_none_ran() {
        let record = build(&args(), &incomplete(), 0);
        let adapter = &record["appraisal"]["checks"]["adapter"];
        assert!(
            adapter.is_array(),
            "adapter checks must always be an array, got {adapter:?}"
        );
        assert_eq!(adapter.as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn adapter_findings_keep_structured_expected_and_observed_values() {
        let mut assessment = incomplete();
        assessment.adapter_findings.push(AdapterFinding {
            check: "cce-policy-host-data".into(),
            subject: "node-a".into(),
            state: CheckState::Fail,
            detail: "different commitments".into(),
            expected: Some("expected".into()),
            observed: Some("observed".into()),
        });

        let record = build(&args(), &assessment, 0);
        let finding = &record["appraisal"]["adapterFindings"][0];
        assert_eq!(finding["check"], "cce-policy-host-data");
        assert_eq!(finding["subject"], "node-a");
        assert_eq!(finding["state"], "fail");
        assert_eq!(finding["expected"], "expected");
        assert_eq!(finding["observed"], "observed");
    }

    /// A policy document configures adapter requirements as well as statement
    /// assertions, so its `satisfied` may not report only the latter.
    ///
    /// A gate reading the record is the primary consumer, and a field that
    /// says the relying party's policy was met while a required appraisal
    /// failed is a trap — the more so because the verdict and exit code are
    /// correct, so the record disagrees with the process that wrote it.
    #[test]
    fn a_failed_adapter_check_leaves_the_policy_unsatisfied() {
        use scitt_policy::{AssertionResult, Outcome, PolicyDecision};

        let satisfied_assertions = || PolicyDecision {
            policy_id: "p".into(),
            policy_version: "1".into(),
            results: vec![AssertionResult {
                name: "issuer".into(),
                outcome: Outcome::Pass,
                detail: "d".into(),
            }],
        };

        let with_adapter = |state: Option<CheckState>| {
            let mut assessment = incomplete();
            assessment.decision = Some(satisfied_assertions());
            if let Some(state) = state {
                assessment.checks.adapter.push(AdapterCheck {
                    name: "cce-policy-host-data".into(),
                    label: "CCE policy / HOST_DATA".into(),
                    state,
                    detail: "d".into(),
                });
                assessment.checks.adapter_required = vec!["cce-policy-host-data".into()];
            }
            build(&args(), &assessment, 0)
        };

        // With no adapter selected the meaning is unchanged.
        let record = with_adapter(None);
        assert_eq!(record["relyingPartyPolicy"]["satisfied"], true);
        assert_eq!(record["relyingPartyPolicy"]["assertionsSatisfied"], true);

        for state in [
            CheckState::Fail,
            CheckState::CannotEvaluate,
            CheckState::NotChecked,
        ] {
            let record = with_adapter(Some(state));
            assert_eq!(
                record["relyingPartyPolicy"]["satisfied"], false,
                "an adapter check in state {state:?} must not read as a satisfied policy"
            );
            // The narrower fact survives rather than being overwritten.
            assert_eq!(record["relyingPartyPolicy"]["assertionsSatisfied"], true);
        }

        let record = with_adapter(Some(CheckState::Pass));
        assert_eq!(record["relyingPartyPolicy"]["satisfied"], true);
    }

    /// The regression this field invited: the adapter reports checks that can
    /// never pass, and counting those would make every real success look like
    /// an unsatisfied policy.
    #[test]
    fn a_check_outside_the_contract_does_not_unsatisfy_the_policy() {
        use scitt_policy::{AssertionResult, Outcome, PolicyDecision};

        let mut assessment = incomplete();
        assessment.decision = Some(PolicyDecision {
            policy_id: "p".into(),
            policy_version: "1".into(),
            results: vec![AssertionResult {
                name: "issuer".into(),
                outcome: Outcome::Pass,
                detail: "d".into(),
            }],
        });
        let check = |name: &str, state: CheckState| AdapterCheck {
            name: name.into(),
            label: name.into(),
            state,
            detail: "d".into(),
        };
        assessment.checks.adapter = vec![
            check("cce-policy-host-data", CheckState::Pass),
            // Permanently unevaluable against CCF, and deliberately not in the
            // contract below.
            check("freshness", CheckState::CannotEvaluate),
        ];
        assessment.checks.adapter_required = vec!["cce-policy-host-data".into()];

        let record = build(&args(), &assessment, 0);
        assert_eq!(
            record["relyingPartyPolicy"]["satisfied"], true,
            "a check the adapter never required must not decide the policy"
        );

        // A contract naming a check the adapter did not report is unmet: the
        // appraisal is incomplete, not satisfied by omission.
        assessment
            .checks
            .adapter_required
            .push("node-coverage".into());
        let record = build(&args(), &assessment, 0);
        assert_eq!(record["relyingPartyPolicy"]["satisfied"], false);
    }

    /// The four core checks are the compatibility surface. Adding adapter
    /// checks must not move or rename them.
    #[test]
    fn adding_adapter_checks_leaves_the_core_four_in_place() {
        let record = build(&args(), &incomplete(), 0);
        let checks = &record["appraisal"]["checks"];
        for key in [
            "statementSignature",
            "receiptInclusion",
            "artifactBinding",
            "policy",
        ] {
            assert_eq!(
                checks[key], "not-checked",
                "core check {key} missing or changed"
            );
        }
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

#[cfg(test)]
mod service_configuration_tests {
    use super::*;
    use crate::cli::Format;
    use crate::outcome::{Category, Verdict};
    use scitt_network::configuration::{Configuration, Observation, Outcome};
    use std::path::PathBuf;

    fn args() -> VerifyArgs {
        VerifyArgs {
            statement: PathBuf::from("s.cose"),
            trust: TrustSource::Local(PathBuf::from("k.cbor")),
            policy: PathBuf::from("p.json"),
            artifact: None,
            binding_mode: BindingMode::None,
            adapter: None,
            evidence: None,
            save_evidence: None,
            format: Format::Json,
            verbose: false,
            result: None,
            facts: None,
            save_trust: None,
            trusted_roots: None,
            now: None,
        }
    }

    fn assessment(acquisition: Option<Acquisition>) -> Assessment {
        let mut a = Assessment::incomplete(
            Verdict::CannotEvaluate,
            Trust::acquired_key_set(),
            Diagnostic::error("ReceiptKeyUnknown", Category::Trust, "m", "a"),
            Vec::new(),
        );
        a.acquisition = acquisition;
        a
    }

    fn online() -> Acquisition {
        let body = br#"{"policy":{"policyScript":"x"},"extra":[1]}"#;
        Acquisition {
            selected: vec!["b.example".into(), "a.example".into()],
            acquired: Vec::new(),
            failed: Vec::new(),
            not_attempted: None,
            configurations: vec![
                Observation::not_attempted("a.example", "key set not acquired", 5),
                Observation {
                    issuer: "b.example".into(),
                    url: Some("https://b.example/configuration".into()),
                    service_cert_sha256: Some("cc".into()),
                    observed_at: 7,
                    outcome: Outcome::Retrieved(Configuration {
                        bytes: body.to_vec(),
                        sha256: scitt_receipt::sha256_hex(body),
                        document: serde_json::from_slice(body).unwrap(),
                    }),
                },
            ],
        }
    }

    /// Present in both documents, marked as not part of the decision, with
    /// every selected service accounted for.
    #[test]
    fn online_records_carry_the_configuration_as_an_informational_block() {
        let a = assessment(Some(online()));
        for record in [build(&args(), &a, 0), facts(&args(), &a, 0)] {
            let block = &record["serviceConfiguration"];
            assert_eq!(block["kind"], "current-observation");
            assert_eq!(block["affectsVerdict"], false);
            assert_eq!(block["limitations"].as_array().unwrap().len(), 4);

            let ledgers = block["ledgers"].as_array().unwrap();
            assert_eq!(ledgers.len(), 2);
            assert_eq!(ledgers[0]["issuer"], "a.example");
            assert_eq!(ledgers[0]["status"], "not-attempted");
            assert_eq!(ledgers[0]["reason"], "key set not acquired");
            assert!(ledgers[0]["configuration"].is_null());

            let b = &ledgers[1];
            assert_eq!(b["status"], "retrieved");
            assert_eq!(b["observedAt"], 7);
            assert_eq!(b["tlsServiceCertSha256"], "cc");
            assert_eq!(
                b["responseBytes"],
                br#"{"policy":{"policyScript":"x"},"extra":[1]}"#.len()
            );
            assert_eq!(b["configuration"]["policy"]["policyScript"], "x");
            assert_eq!(b["configuration"]["extra"][0], 1);
            assert!(b["failure"].is_null());
        }
    }

    #[test]
    fn a_failed_read_records_its_code_and_detail() {
        let mut acquisition = online();
        acquisition.configurations[1].outcome = Outcome::Failed(scitt_network::AcquireError::new(
            scitt_network::Diagnostic::AccessDenied,
            "HTTP 401",
        ));
        let record = build(&args(), &assessment(Some(acquisition)), 0);
        let b = &record["serviceConfiguration"]["ledgers"][1];
        assert_eq!(b["status"], "failed");
        assert_eq!(b["failure"]["code"], "accessDenied");
        assert_eq!(b["failure"]["detail"], "HTTP 401");
        assert!(b["responseSha256"].is_null());
    }

    /// No fetch, no block: "did not ask" must not look like "asked, got nothing".
    #[test]
    fn offline_records_have_no_configuration_block() {
        let a = assessment(None);
        assert!(build(&args(), &a, 0).get("serviceConfiguration").is_none());
        assert!(facts(&args(), &a, 0).get("serviceConfiguration").is_none());
    }
}
