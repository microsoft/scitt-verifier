//! # scitt-policy
//!
//! Relying-party policy: the part that turns *facts* into a *decision*.
//!
//! `scitt-receipt` can tell you that a statement was registered on a ledger by
//! an issuer calling itself `https://example.transparency`. It cannot tell you
//! whether that is an issuer you accept. That question has no universal answer,
//! so it is asked here, against a policy document the relying party owns.
//!
//! Three properties are load-bearing:
//!
//! * **A policy is always required.** There is no default policy, because a
//!   default would be a trust decision made by this tool on someone else's
//!   behalf.
//! * **An assertion that cannot be evaluated is not a pass.** If a policy asks
//!   for a minimum SVN and the statement carries no SVN, the answer is
//!   `CannotEvaluate` — never `Pass`.
//! * **Unknown assertions are refused.** A policy naming an assertion this
//!   build does not implement is rejected outright, so a policy written for a
//!   newer version cannot appear to pass on an older binary.
//!
//! The crate takes no clock. `now` is passed in, so evaluation is reproducible
//! and testable.

use scitt_receipt::external::{self, DetachedSigner};
use scitt_receipt::labels;
use scitt_receipt::CborValue;
use scitt_receipt::StatementFacts;
use serde::{Deserialize, Serialize};

/// A relying-party policy document.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Policy {
    /// Stable identifier, echoed into the evidence so a decision can be traced
    /// back to the rules that produced it.
    pub policy_id: String,
    pub policy_version: String,
    #[serde(default)]
    pub description: Option<String>,
    pub assertions: Assertions,
}

/// The assertions this build understands.
///
/// `deny_unknown_fields` is the mechanism that refuses forward-dated policies.
/// Silently ignoring an unrecognised assertion would report a pass for a rule
/// that was never checked.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Assertions {
    /// Accepted transparency service issuers.
    #[serde(default)]
    pub issuer: Option<Vec<String>>,
    /// Substring that must appear in the signing certificate's subject.
    #[serde(default)]
    pub signer_subject_contains: Option<String>,
    /// Substring that must appear in the signing certificate's issuer.
    #[serde(default)]
    pub signer_issuer_contains: Option<String>,
    /// Exactly how many receipts the statement must carry. Must be 1.
    ///
    /// Counts receipts *present*, not receipts that verified, because the
    /// thing it detects is insertion. Receipts ride in the unprotected header
    /// bucket that no signature covers, so anyone who handled the file can add
    /// one; a service this tool verifies against issues exactly one per
    /// registration. A second receipt therefore means the file is not the file
    /// the service returned, whether or not the extra one verifies.
    ///
    /// A value above 1 is refused rather than supported. Receipts are not
    /// signed as a set, so `2` would be satisfied by attaching a copy of the
    /// one that exists — counting twice while proving once. Verifying genuinely
    /// independent registrations needs explicit support, not a larger number.
    ///
    /// Deliberately an exact count rather than a lower bound. A minimum of 1
    /// could only restate what the verdict already guarantees — no run passes
    /// without a verified receipt — so it would never reject anything.
    #[serde(default)]
    pub receipt_count: Option<usize>,
    /// Registration must be no earlier than this Unix timestamp.
    #[serde(default)]
    pub registered_after: Option<i64>,
    /// Registration must be no later than this Unix timestamp.
    #[serde(default)]
    pub registered_before: Option<i64>,
    /// Registration must be within this many days of `now`.
    #[serde(default)]
    pub max_age_days: Option<i64>,
    /// Minimum security version number, for anti-rollback.
    #[serde(default)]
    pub min_svn: Option<i64>,
    /// Require that each receipt's kid was derived from its key material.
    #[serde(default)]
    pub require_kid_bound_to_key: Option<bool>,
    /// The subject the statement must claim, from the protected CWT claims.
    ///
    /// Unlike `signerSubjectContains`, which reads a certificate the statement
    /// carries, this reads a claim inside the signed payload — so it is covered
    /// by the issuer's signature and, through the claim digest, by the receipt
    /// the ledger issued. Pinning it answers "is this statement about the thing
    /// I am holding?" for artifacts that cannot be hashed, such as a physical
    /// part identified by serial number.
    #[serde(default)]
    pub statement_subject: Option<StringMatch>,
    /// The issuer the statement must claim, from the protected CWT claims.
    ///
    /// This is the complement to `statementSubject`: `sub` names what the
    /// statement is about, `iss` names who said it. Both live in the protected
    /// header, so the issuer's signature covers them and, through the claim
    /// digest, so does the receipt.
    ///
    /// That coverage is what separates this from `signerSubjectContains` and
    /// `signerIssuerContains`. Those read the leaf certificate the statement
    /// carries, which this build does not validate to a trusted root, so an
    /// attacker who self-signs chooses the strings they match. `iss` is inside
    /// the signed payload the ledger registered, so forging it means obtaining
    /// a receipt for the forgery.
    ///
    /// What it is worth therefore depends on the registration policy of the
    /// service that issued the receipt. Where the service authenticates the
    /// issuer identity at registration — as Microsoft Signing Transparency does
    /// for the `did:x509` form — pinning it says the ledger checked this signer
    /// and it is the one expected. Against a service that registers whatever it
    /// is handed, it pins a self-asserted string.
    #[serde(default)]
    pub statement_issuer: Option<StringMatch>,
    /// Assertions on individual protected header entries, by label path.
    ///
    /// The named assertions above cover the headers this build understands.
    /// This one covers the rest: a vendor label, or a profile that did not
    /// exist when this binary was compiled. `inspect` prints those headers
    /// marked `(not interpreted)`; this is how a relying party interprets one.
    ///
    /// Everything reachable here is inside the protected bucket, so the
    /// issuer's signature covers it and the claim digest carries it into the
    /// receipt. That places these assertions in the same strength class as
    /// `statementSubject` and `statementIssuer`, and strictly above the
    /// certificate assertions, which read material no receipt covers.
    ///
    /// The tool holds no opinion about what any of these headers mean. It
    /// reports what the issuer signed; deciding whether that is acceptable is
    /// the relying party's job, which is the whole point of a policy.
    #[serde(default)]
    pub protected_headers: Option<Vec<HeaderAssertion>>,
    /// Detached signatures carried inside the protected header, checked
    /// cryptographically rather than merely described.
    ///
    /// `protectedHeaders` can say a signature descriptor *looks* right — that
    /// it declares RS256, that its certificate names the expected supplier.
    /// None of that is evidence: every byte it reads was chosen by whoever
    /// assembled the statement, and a descriptor containing 512 random bytes
    /// matches exactly as well as a real one. This assertion computes the
    /// signature, so a forged descriptor fails.
    ///
    /// What it establishes is narrower than it looks, and the narrowness is
    /// the point. A passing check says: the bytes at label `-1` are a valid
    /// signature over this statement's payload by the key in the certificate
    /// at label `33`. It does *not* say that certificate belongs to anyone in
    /// particular — this build does not validate the chain to a trusted root,
    /// so a signer who mints their own certificate passes. `signerSubject
    /// Contains` narrows that to a named subject, which raises the bar from
    /// "someone" to "someone who wrote this string into a certificate", and a
    /// run that uses this assertion says so in `notChecked`.
    ///
    /// It is still worth having. It converts a claim that could be fabricated
    /// with a random-number generator into one that requires a private key,
    /// and — because the descriptor is in the protected bucket — the ledger
    /// witnessed the whole thing at registration.
    #[serde(default)]
    pub external_signatures: Option<Vec<ExternalSignature>>,
}

/// One detached signature to verify.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalSignature {
    /// Where the descriptor map lives, from the protected header downwards.
    ///
    /// Addresses the map, not any field inside it. The labels within — `1`,
    /// `33`, `-1` — are read by the verifier, so an author names the vendor
    /// header once instead of writing three coordinated paths that could drift
    /// apart and check a signature against a different signature's algorithm.
    pub path: Vec<PathSegment>,
    /// Which bytes the signature is supposed to cover.
    ///
    /// Required, and no default. A detached signature carries no statement of
    /// what it signed, so a verifier that guessed would report a forgery
    /// whenever it guessed wrong — the worst possible error for a gate,
    /// because it trains operators to disregard the result. Naming it makes
    /// the convention the policy author's declaration.
    ///
    /// An unrecognised value is refused when the policy is read, not treated
    /// as a failure to verify.
    pub signed_over: SignedOver,
    /// Substring that must appear in the external signer's certificate subject.
    #[serde(default)]
    pub signer_subject_contains: Option<String>,
    /// Substring that must appear in the external signer's certificate issuer.
    ///
    /// Worth more than `signerSubjectContains` against a self-signed
    /// certificate, where subject and issuer are the same attacker-chosen
    /// string. Pinning an issuer at least requires the forger to name a real
    /// CA — which this build cannot yet hold them to, so the two are of the
    /// same strength class until chain validation lands.
    #[serde(default)]
    pub signer_issuer_contains: Option<String>,
}

/// What a detached signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SignedOver {
    /// The statement's payload, byte for byte as it appears in the statement.
    ///
    /// A bare signature over bytes, with the algorithm and certificate given
    /// alongside it in a map of COSE labels. Nothing in the descriptor records
    /// what was signed, which is why this value has to be written down.
    Payload,
    /// A nested COSE_Sign1 whose `Sig_structure` covers the statement's payload.
    ///
    /// The standard shape for the same job, and a better one: the signature
    /// covers a structure that names the protected header and the payload
    /// together, so what was signed is determined by the encoding rather than
    /// by convention, and any COSE library can check it.
    ///
    /// The nested payload is expected to be detached (`nil`) — the outer
    /// statement already carries those bytes, and duplicating them costs the
    /// size of the payload for nothing. An embedded payload is accepted only
    /// when it matches the statement's exactly; a mismatch **fails**, because
    /// two disagreeing copies inside one signed statement would let a producer
    /// have a supplier endorse one thing and register another, with both
    /// signatures verifying.
    CoseSign1,
}

/// One assertion about one protected header entry.
///
/// The value is matched by declared CBOR type rather than by a rendered
/// string. That is a security property, not ergonomics: the reporting
/// renderer summarises a byte string as `"20 bytes: <first 16 in hex>"` and an
/// array as `"array of 3"`. Matching those renderings would mean a *text*
/// header whose content is literally `array of 3` satisfies a rule expecting
/// an array, and two different byte strings sharing a 16-byte prefix compare
/// equal. Naming the type makes both impossible.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HeaderAssertion {
    /// Where the value lives, from the protected header map downwards.
    ///
    /// A JSON number addresses an integer CBOR label; a JSON string addresses
    /// a text label. COSE permits both, and JSON's own type distinction keeps
    /// them apart without an escaping convention — which an object keyed by
    /// label could not do, since JSON object keys are always strings and
    /// `"15"` would be ambiguous.
    ///
    /// Later segments descend into nested maps, and into arrays by position.
    /// Which one an integer segment means is decided by the node it is applied
    /// to, so no extra syntax is needed.
    pub path: Vec<PathSegment>,
    /// The value must be a CBOR text string matching this.
    #[serde(default)]
    pub text: Option<StringMatch>,
    /// The value must be a CBOR integer matching this.
    #[serde(default)]
    pub int: Option<IntMatch>,
    /// The value must be a CBOR integer naming one of these COSE algorithms.
    ///
    /// The same values `int` would match, written the way the registry spells
    /// them. Kept separate rather than folded into `int` as sugar because the
    /// interpretation is the author's to declare, not the tool's to infer: a
    /// path may address an algorithm, but it may equally address `nbf`, and at
    /// a private-use label inside a vendor structure this build has no basis
    /// to know which. Writing `alg` says "read this as an algorithm", and that
    /// claim is the author's.
    #[serde(default)]
    pub alg: Option<AlgMatch>,
}

/// One step in a header path: an integer label or index, or a text label.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PathSegment {
    Int(i64),
    Text(String),
}

impl std::fmt::Display for PathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(i) => write!(f, "{i}"),
            Self::Text(s) => write!(f, "'{s}'"),
        }
    }
}

/// How a policy matches an algorithm-valued header.
///
/// `{"alg": {"oneOf": ["ES256", "ES384"]}}` accepts what
/// `{"int": {"oneOf": [-7, -35]}}` accepts. The difference is what happens to a
/// mistake. COSE algorithm identifiers are adjacent negative integers — `-35`,
/// `-36`, `-37` are ES384, ES512 and PS256 — so a typed digit produces a
/// different, still-valid policy that passes for the rest of its life. A typed
/// letter produces a name that resolves to nothing, and this refuses it when
/// the policy is read.
///
/// There is no `min`/`max`. The identifiers are registry codes, not a scale;
/// a range over them would accept algorithms by accident of numbering.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlgMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<String>>,
}

impl AlgMatch {
    fn names(&self) -> &[String] {
        match (&self.equals, &self.one_of) {
            (Some(one), _) => std::slice::from_ref(one),
            (None, Some(many)) => many,
            (None, None) => &[],
        }
    }

    fn validate(&self, field: &str) -> Result<(), String> {
        let declared = self.equals.is_some() as u8 + self.one_of.is_some() as u8;
        if declared == 0 {
            return Err(format!(
                "{field} declares no match criteria; it would accept any algorithm"
            ));
        }
        if declared > 1 {
            return Err(format!(
                "{field} declares both equals and oneOf; use exactly one"
            ));
        }
        if self.one_of.as_deref().is_some_and(<[String]>::is_empty) {
            return Err(format!(
                "{field}.oneOf is empty; no value could ever satisfy it"
            ));
        }
        for name in self.names() {
            if labels::alg::from_name(name).is_none() {
                let known: Vec<&str> = labels::alg::NAMED.iter().map(|(n, _)| *n).collect();
                return Err(format!(
                    "{field} names '{name}', which this build does not know. Accepting it would \
                     mean a rule that can never match reported as a rule that ran. Known names: \
                     {}. For an algorithm outside this list, address it by identifier with int.",
                    known.join(", ")
                ));
            }
        }
        Ok(())
    }

    fn accepted(&self) -> Vec<i64> {
        // Unresolvable names are refused by `validate`, so filtering here
        // cannot silently narrow a policy that was accepted.
        self.names()
            .iter()
            .filter_map(|n| labels::alg::from_name(n))
            .collect()
    }

    fn matches(&self, value: i64) -> bool {
        self.accepted().contains(&value)
    }

    fn describe(&self) -> String {
        if let Some(expected) = &self.equals {
            return format!("must be {expected}");
        }
        format!("must be one of [{}]", self.names().join(", "))
    }
}

/// How a policy matches an integer-valued header.
///
/// Either an exact set (`equals`, `oneOf`) or a range (`min`, `max`, which may
/// be combined). As with [`StringMatch`], a criterion nothing could fail is
/// refused when the policy is parsed rather than reported as a rule that ran.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IntMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<i64>>,
}

impl IntMatch {
    fn validate(&self, field: &str) -> Result<(), String> {
        let exact = self.equals.is_some() as u8 + self.one_of.is_some() as u8;
        let ranged = self.min.is_some() || self.max.is_some();

        if exact == 0 && !ranged {
            return Err(format!(
                "{field} declares no match criteria; it would accept any integer"
            ));
        }
        if exact > 1 {
            return Err(format!(
                "{field} declares both equals and oneOf; use exactly one"
            ));
        }
        if exact == 1 && ranged {
            return Err(format!(
                "{field} mixes an exact match with min/max; use one or the other"
            ));
        }
        if self.one_of.as_deref().is_some_and(<[i64]>::is_empty) {
            return Err(format!(
                "{field}.oneOf is empty; no value could ever satisfy it"
            ));
        }
        // An inverted range can never be satisfied. Refusing it here is the
        // same bargain as `oneOf: []`: a policy nobody could pass is a
        // mistake, and finding it now beats finding it per-artifact later.
        if let (Some(min), Some(max)) = (self.min, self.max) {
            if min > max {
                return Err(format!(
                    "{field} has min {min} above max {max}; no value could ever satisfy it"
                ));
            }
        }
        Ok(())
    }

    fn matches(&self, value: i64) -> bool {
        if let Some(expected) = self.equals {
            return value == expected;
        }
        if let Some(accepted) = &self.one_of {
            return accepted.contains(&value);
        }
        !matches!(self.min, Some(min) if value < min)
            && !matches!(self.max, Some(max) if value > max)
    }

    fn describe(&self) -> String {
        if let Some(expected) = self.equals {
            return format!("must equal {expected}");
        }
        if let Some(accepted) = &self.one_of {
            return format!("must be one of {accepted:?}");
        }
        match (self.min, self.max) {
            (Some(min), Some(max)) => format!("must be between {min} and {max}"),
            (Some(min), None) => format!("must be at least {min}"),
            (None, Some(max)) => format!("must be at most {max}"),
            (None, None) => "has no criteria".into(),
        }
    }
}

/// How a policy matches a string-valued claim.
///
/// Exactly one mode must be set, and it must be capable of rejecting something.
/// Both an empty object and a criterion every value satisfies are refused when
/// the policy is parsed, because either would appear in the report as a rule
/// that ran and passed while having examined nothing.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StringMatch {
    /// The claim must be exactly this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    /// The claim must begin with this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_with: Option<String>,
    /// The claim must be exactly one of these values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<String>>,
}

impl StringMatch {
    fn validate(&self, field: &str) -> Result<(), String> {
        let declared = [
            self.equals.is_some(),
            self.starts_with.is_some(),
            self.one_of.is_some(),
        ]
        .iter()
        .filter(|set| **set)
        .count();

        if declared == 0 {
            return Err(format!(
                "{field} declares no match criteria; it would accept any value"
            ));
        }
        if declared > 1 {
            return Err(format!(
                "{field} declares more than one of equals, startsWith, oneOf; use exactly one"
            ));
        }
        // A criterion that cannot reject anything is worse than no criterion at
        // all, because the report shows it passing.
        if self.starts_with.as_deref() == Some("") {
            return Err(format!(
                "{field}.startsWith is empty; every value starts with the empty string"
            ));
        }
        if self.one_of.as_deref().is_some_and(<[String]>::is_empty) {
            return Err(format!(
                "{field}.oneOf is empty; no value could ever satisfy it"
            ));
        }
        Ok(())
    }

    fn matches(&self, value: &str) -> bool {
        if let Some(expected) = &self.equals {
            return value == expected;
        }
        if let Some(prefix) = &self.starts_with {
            return value.starts_with(prefix);
        }
        if let Some(accepted) = &self.one_of {
            return accepted.iter().any(|c| c == value);
        }
        false
    }

    fn describe(&self) -> String {
        if let Some(expected) = &self.equals {
            return format!("must equal '{expected}'");
        }
        if let Some(prefix) = &self.starts_with {
            return format!("must start with '{prefix}'");
        }
        if let Some(accepted) = &self.one_of {
            return format!("must be one of {accepted:?}");
        }
        "has no criteria".into()
    }
}

/// The outcome of one assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Pass,
    Fail,
    /// The input needed to answer this assertion was absent.
    ///
    /// Distinct from `Fail` on purpose: "the statement does not claim an SVN"
    /// and "the statement claims an SVN that is too low" call for different
    /// responses from the person reading the report.
    CannotEvaluate,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResult {
    pub name: String,
    pub outcome: Outcome,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub policy_id: String,
    pub policy_version: String,
    pub results: Vec<AssertionResult>,
}

impl PolicyDecision {
    pub fn failed(&self) -> bool {
        self.results.iter().any(|r| r.outcome == Outcome::Fail)
    }

    pub fn unevaluable(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.outcome == Outcome::CannotEvaluate)
    }

    /// True only if every assertion actually ran and passed.
    pub fn satisfied(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.outcome == Outcome::Pass)
    }
}

/// How deep a header path may descend.
///
/// The map being walked is attacker-supplied, and each level is another
/// allocation-free hop, but a bound keeps a pathological document from turning
/// a policy into a stack walk. Nothing legitimate approaches this.
/// Public so `inspect` can stop describing a header exactly where a policy
/// stops being able to address one. Two literals would drift, and the failure
/// would be silent: output inviting an author down a path the engine refuses.
pub const MAX_HEADER_PATH_DEPTH: usize = 8;

/// Reserved for iterating an array once quantifiers exist.
///
/// Refused now rather than treated as a literal label. A policy written for a
/// later build must not quietly become "look for a text label named `*`",
/// find nothing, and report `cannotEvaluate` — that is the same failure as
/// ignoring an unknown assertion, one level down.
const PATH_WILDCARD: &str = "*";

/// Check a header path before anything tries to walk it.
///
/// Shared by every assertion that addresses the protected header, so a limit
/// tightened in one place cannot leave another accepting what the engine will
/// refuse.
fn validate_path(path: &[PathSegment], field: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{field}.path is empty; it addresses no header"));
    }
    if path.len() > MAX_HEADER_PATH_DEPTH {
        return Err(format!(
            "{field}.path is {} segments deep; the limit is {MAX_HEADER_PATH_DEPTH}",
            path.len()
        ));
    }
    for segment in path {
        if matches!(segment, PathSegment::Text(s) if s == PATH_WILDCARD) {
            return Err(format!(
                "{field}.path uses '*', which is reserved for matching across every element of \
                 an array. This build has no quantifier, so it cannot say whether you meant \
                 every element or any element, and guessing either would report a decision you \
                 did not ask for. Address one element by position instead."
            ));
        }
    }
    Ok(())
}

impl ExternalSignature {
    fn validate(&self, index: usize) -> Result<(), String> {
        validate_path(&self.path, &format!("externalSignatures[{index}]"))
    }

    /// Render the path the way a reader would write it back into the policy.
    fn describe_path(&self) -> String {
        let parts: Vec<String> = self.path.iter().map(ToString::to_string).collect();
        format!("[{}]", parts.join(", "))
    }

    /// Whether the signer's certificate satisfies the pins, and why not.
    fn check_signer(&self, signer: &DetachedSigner) -> Result<(), String> {
        if let Some(needle) = &self.signer_subject_contains {
            match &signer.subject {
                Some(subject) if subject.contains(needle) => {}
                Some(subject) => {
                    return Err(format!(
                        "signer subject '{subject}' does not contain '{needle}'"
                    ))
                }
                None => return Err("the signer's certificate declares no subject".into()),
            }
        }
        if let Some(needle) = &self.signer_issuer_contains {
            match &signer.issuer {
                Some(issuer) if issuer.contains(needle) => {}
                Some(issuer) => {
                    return Err(format!(
                        "signer issuer '{issuer}' does not contain '{needle}'"
                    ))
                }
                None => return Err("the signer's certificate declares no issuer".into()),
            }
        }
        Ok(())
    }
}

impl HeaderAssertion {
    fn validate(&self, index: usize) -> Result<(), String> {
        let field = format!("protectedHeaders[{index}]");

        validate_path(&self.path, &field)?;

        match (&self.text, &self.int, &self.alg) {
            (None, None, None) => Err(format!(
                "{field} declares no matcher; give it text, int or alg so the value's CBOR type \
                 is stated. A header is matched by declared type because the value could be any \
                 CBOR type, and a rule that accepts whichever type arrived is not a rule."
            )),
            (Some(text), None, None) => text.validate(&format!("{field}.text")),
            (None, Some(int), None) => int.validate(&format!("{field}.int")),
            (None, None, Some(alg)) => alg.validate(&format!("{field}.alg")),
            // `int` and `alg` both read an integer, so a value satisfying one
            // and not the other would make the outcome depend on which the
            // engine happened to consult first.
            _ => Err(format!(
                "{field} declares more than one matcher; a value has one CBOR type, so use one"
            )),
        }
    }

    /// Render the path the way a reader would write it back into the policy.
    fn describe_path(&self) -> String {
        let parts: Vec<String> = self.path.iter().map(ToString::to_string).collect();
        format!("[{}]", parts.join(", "))
    }
}

/// Follow a header path, or say why it could not be followed.
///
/// `Ok(None)` means the path led nowhere: the header is absent, which is a
/// different answer from "present and wrong" and must not read as either.
fn resolve_path<'a>(
    root: &'a CborValue,
    path: &[PathSegment],
) -> Result<Option<&'a CborValue>, String> {
    let mut node = root;

    for (depth, segment) in path.iter().enumerate() {
        let next = match node {
            CborValue::Map(entries) => {
                let mut found = None;
                for (key, value) in entries {
                    let hit = match (key, segment) {
                        (CborValue::Int(k), PathSegment::Int(want)) => k == want,
                        (CborValue::TextString(k), PathSegment::Text(want)) => k == want,
                        _ => false,
                    };
                    if !hit {
                        continue;
                    }
                    // A CBOR map may carry the same key twice, and nothing
                    // upstream rejects it. Taking the first would let a
                    // producer show this tool one value and another parser a
                    // different one, with both reading the same signed bytes.
                    // There is no safe choice between them, so refuse.
                    if found.is_some() {
                        return Err(format!(
                            "header {segment} appears more than once at depth {depth}; the \
                             statement is ambiguous and no value can be trusted"
                        ));
                    }
                    found = Some(value);
                }
                found
            }
            // An integer indexes an array; the node's type decides what the
            // segment meant, so no extra syntax is needed to tell a label from
            // an index. Reserved `*` is refused when the policy is parsed.
            CborValue::Array(items) => match segment {
                PathSegment::Int(i) => usize::try_from(*i).ok().and_then(|i| items.get(i)),
                PathSegment::Text(_) => {
                    return Err(format!(
                        "path segment {segment} names a label, but the value at depth {depth} is \
                         an array; index it by position"
                    ))
                }
            },
            other => {
                return Err(format!(
                    "path segment {segment} cannot be applied at depth {depth}: the value there \
                     is {}, which has no members",
                    scitt_receipt::render_scalar(other)
                ))
            }
        };

        match next {
            Some(value) => node = value,
            None => return Ok(None),
        }
    }

    Ok(Some(node))
}

impl Policy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let policy: Policy = serde_json::from_slice(bytes)
            .map_err(|e| format!("policy document is not valid: {e}"))?;
        if policy.is_empty() {
            return Err(
                "policy declares no assertions; an empty policy would accept anything".into(),
            );
        }
        if let Some(subject) = &policy.assertions.statement_subject {
            subject.validate("statementSubject")?;
        }
        if let Some(issuer) = &policy.assertions.statement_issuer {
            issuer.validate("statementIssuer")?;
        }
        if let Some(headers) = &policy.assertions.protected_headers {
            if headers.is_empty() {
                return Err("protectedHeaders is empty; it would assert nothing".into());
            }
            for (index, header) in headers.iter().enumerate() {
                header.validate(index)?;
            }
        }
        if let Some(externals) = &policy.assertions.external_signatures {
            if externals.is_empty() {
                return Err("externalSignatures is empty; it would assert nothing".into());
            }
            for (index, external) in externals.iter().enumerate() {
                external.validate(index)?;
            }
        }
        if let Some(expected) = policy.assertions.receipt_count {
            // Refused at parse time rather than evaluated to a failure, so the
            // operator learns the policy asks for something unobtainable
            // instead of watching every artifact fail and hunting for why.
            if expected != 1 {
                return Err(format!(
                    "receiptCount is {expected}, but the only supported value is 1. Receipts are \
                     not signed as a set, so a count above 1 can be met by attaching a copy of a \
                     single receipt — counting twice while proving once — and no transparency \
                     service this build verifies against issues more than one per registration. \
                     A count of 0 would accept a statement with no proof at all."
                ));
            }
        }
        Ok(policy)
    }

    /// Whether the policy declares no assertion at all.
    ///
    /// Derived from the serialised form rather than a hand-written chain of
    /// `is_none` checks. The chain had to be extended every time an assertion
    /// was added, and forgetting to do so would reject a policy that used only
    /// the new assertion as though it were empty.
    fn is_empty(&self) -> bool {
        match serde_json::to_value(&self.assertions) {
            Ok(serde_json::Value::Object(fields)) => {
                fields.values().all(serde_json::Value::is_null)
            }
            _ => false,
        }
    }

    /// Evaluate the policy against verified facts.
    ///
    /// `now` is a Unix timestamp supplied by the caller. Passing it in rather
    /// than reading the clock keeps the same inputs producing the same decision
    /// on every machine, which matters when a build agent and a human are
    /// arguing about why a gate failed.
    pub fn evaluate(&self, facts: &StatementFacts, now: i64) -> PolicyDecision {
        let mut results = Vec::new();
        let a = &self.assertions;

        // Registration time is taken from the receipt, not the statement's own
        // `iat`. The issuer controls the latter; the ledger controls the former.
        let registered_at = facts
            .verified_receipts()
            .filter_map(|r| r.registered_at)
            .min();

        if let Some(accepted) = &a.issuer {
            // Only fully verified receipts, for the same reason `registered_at`
            // filters above: receipts travel in the statement's *unprotected*
            // bucket, so anyone handling the file can append one. An appended
            // receipt's self-declared `iss` is an attacker-chosen string, and
            // accepting it here would let a statement registered on a ledger
            // this policy rejects satisfy the issuer rule anyway.
            let issuers: Vec<String> = facts
                .verified_receipts()
                .filter_map(|r| r.issuer.clone())
                .collect();
            results.push(if issuers.is_empty() {
                result(
                    "issuer",
                    Outcome::CannotEvaluate,
                    "no fully verified receipt declares an issuer",
                )
            } else if issuers.iter().any(|i| accepted.contains(i)) {
                result(
                    "issuer",
                    Outcome::Pass,
                    format!("receipt issuer {issuers:?} is accepted"),
                )
            } else {
                result(
                    "issuer",
                    Outcome::Fail,
                    format!("receipt issuer {issuers:?} is not in the accepted list {accepted:?}"),
                )
            });
        }

        if let Some(expected) = &a.statement_subject {
            // The claim is absent rather than wrong, which is a different
            // message to the reader and must never read as a pass.
            results.push(match &facts.cwt.sub {
                None => result(
                    "statementSubject",
                    Outcome::CannotEvaluate,
                    "statement declares no CWT subject claim",
                ),
                Some(subject) if expected.matches(subject) => result(
                    "statementSubject",
                    Outcome::Pass,
                    format!("subject '{subject}' {}", expected.describe()),
                ),
                Some(subject) => result(
                    "statementSubject",
                    Outcome::Fail,
                    format!(
                        "subject '{subject}' does not match: it {}",
                        expected.describe()
                    ),
                ),
            });
        }

        if let Some(expected) = &a.statement_issuer {
            // Absent is `cannotEvaluate` for the same reason as the subject: a
            // statement that names no issuer has not made a claim this rule
            // could have rejected.
            results.push(match &facts.cwt.iss {
                None => result(
                    "statementIssuer",
                    Outcome::CannotEvaluate,
                    "statement declares no CWT issuer claim",
                ),
                Some(issuer) if expected.matches(issuer) => result(
                    "statementIssuer",
                    Outcome::Pass,
                    format!("issuer '{issuer}' {}", expected.describe()),
                ),
                Some(issuer) => result(
                    "statementIssuer",
                    Outcome::Fail,
                    format!(
                        "issuer '{issuer}' does not match: it {}",
                        expected.describe()
                    ),
                ),
            });
        }

        if let Some(headers) = &a.protected_headers {
            for header in headers {
                let name = "protectedHeaders";
                let at = header.describe_path();

                let Some(protected) = &facts.protected else {
                    results.push(result(
                        name,
                        Outcome::CannotEvaluate,
                        format!("{at}: no statement was parsed"),
                    ));
                    continue;
                };

                let found = match resolve_path(protected, &header.path) {
                    Ok(found) => found,
                    // A malformed or ambiguous path is the policy author being
                    // told something specific about this statement, not a
                    // missing input, so it fails rather than abstaining.
                    Err(why) => {
                        results.push(result(name, Outcome::Fail, format!("{at}: {why}")));
                        continue;
                    }
                };

                let Some(value) = found else {
                    results.push(result(
                        name,
                        Outcome::CannotEvaluate,
                        format!("{at}: no such protected header"),
                    ));
                    continue;
                };

                results.push(evaluate_header(header, &at, value));
            }
        }

        if let Some(externals) = &a.external_signatures {
            for external in externals {
                let name = "externalSignatures";
                let at = external.describe_path();

                let Some(protected) = &facts.protected else {
                    results.push(result(
                        name,
                        Outcome::CannotEvaluate,
                        format!("{at}: no statement was parsed"),
                    ));
                    continue;
                };

                let found = match resolve_path(protected, &external.path) {
                    Ok(found) => found,
                    Err(why) => {
                        results.push(result(name, Outcome::Fail, format!("{at}: {why}")));
                        continue;
                    }
                };

                let Some(descriptor) = found else {
                    results.push(result(
                        name,
                        Outcome::CannotEvaluate,
                        format!("{at}: no such protected header, so there is no signature here"),
                    ));
                    continue;
                };

                // Every convention is named by the policy, never inferred from
                // the value's shape. An exhaustive match makes adding one a
                // compile error rather than a silent fallthrough.
                let payload = facts.payload.as_deref();
                let checked = match external.signed_over {
                    SignedOver::Payload => external::verify_detached(descriptor, payload),
                    SignedOver::CoseSign1 => external::verify_cose_sign1(descriptor, payload),
                };

                results.push(match checked {
                    // The tool could not put the question. Never a pass, and
                    // not a failure either: nobody has been shown to have done
                    // anything wrong, and a report that conflated the two
                    // would send an operator hunting for a forgery that is
                    // actually a missing field.
                    external::Detached::Unusable(why) => {
                        result(name, Outcome::CannotEvaluate, format!("{at}: {why}"))
                    }
                    external::Detached::Invalid { signer, why } => result(
                        name,
                        Outcome::Fail,
                        format!("{at}: {why} — signed by {}", describe_signer(&signer)),
                    ),
                    external::Detached::Valid(signer) => match external.check_signer(&signer) {
                        // A valid signature by the wrong signer is a failure,
                        // not a pass with a caveat. It is exactly the shape a
                        // substitution attack takes: real cryptography, wrong
                        // party.
                        Err(why) => result(name, Outcome::Fail, format!("{at}: {why}")),
                        Ok(()) => result(
                            name,
                            Outcome::Pass,
                            format!(
                                "{at}: valid signature over the payload by {}",
                                describe_signer(&signer)
                            ),
                        ),
                    },
                });
            }
        }

        if let Some(needle) = &a.signer_subject_contains {
            results.push(match &facts.leaf_subject {
                None => result(
                    "signerSubjectContains",
                    Outcome::CannotEvaluate,
                    "statement carries no signing certificate",
                ),
                Some(subject) if subject.contains(needle) => result(
                    "signerSubjectContains",
                    Outcome::Pass,
                    format!("subject '{subject}' contains '{needle}'"),
                ),
                Some(subject) => result(
                    "signerSubjectContains",
                    Outcome::Fail,
                    format!("subject '{subject}' does not contain '{needle}'"),
                ),
            });
        }

        if let Some(needle) = &a.signer_issuer_contains {
            results.push(match &facts.leaf_issuer {
                None => result(
                    "signerIssuerContains",
                    Outcome::CannotEvaluate,
                    "statement carries no signing certificate",
                ),
                Some(issuer) if issuer.contains(needle) => result(
                    "signerIssuerContains",
                    Outcome::Pass,
                    format!("certificate issuer '{issuer}' contains '{needle}'"),
                ),
                Some(issuer) => result(
                    "signerIssuerContains",
                    Outcome::Fail,
                    format!("certificate issuer '{issuer}' does not contain '{needle}'"),
                ),
            });
        }

        if let Some(expected) = a.receipt_count {
            // `receipts_present`, not `verified_receipts()`: this assertion
            // exists to notice that the file grew a receipt after the service
            // returned it, and an inserted receipt is unlikely to verify. That
            // an inserted receipt is disregarded by the verdict is exactly why
            // counting only the verified ones would never see it.
            let present = facts.receipts_present;
            results.push(if present == expected {
                result(
                    "receiptCount",
                    Outcome::Pass,
                    format!("statement carries {present} receipt(s), {expected} required"),
                )
            } else {
                result(
                    "receiptCount",
                    Outcome::Fail,
                    format!(
                        "statement carries {present} receipt(s), {expected} required; \
                         receipts are attached to a header no signature covers, so an \
                         unexpected count means the file is not the one the service returned"
                    ),
                )
            });
        }

        if let Some(bound) = a.registered_after {
            results.push(compare_time(
                "registeredAfter",
                registered_at,
                |t| t >= bound,
                format!("registration must be at or after {bound}"),
            ));
        }

        if let Some(bound) = a.registered_before {
            results.push(compare_time(
                "registeredBefore",
                registered_at,
                |t| t <= bound,
                format!("registration must be at or before {bound}"),
            ));
        }

        if let Some(days) = a.max_age_days {
            let cutoff = now - days * 86_400;
            results.push(compare_time(
                "maxAgeDays",
                registered_at,
                |t| t >= cutoff,
                format!("registration must be within {days} day(s) of {now}"),
            ));
        }

        if let Some(minimum) = a.min_svn {
            results.push(match facts.cwt.svn {
                None => result(
                    "minSvn",
                    Outcome::CannotEvaluate,
                    "statement declares no security version number",
                ),
                Some(svn) if svn >= minimum => result(
                    "minSvn",
                    Outcome::Pass,
                    format!("svn {svn} meets the minimum of {minimum}"),
                ),
                Some(svn) => result(
                    "minSvn",
                    Outcome::Fail,
                    format!("svn {svn} is below the minimum of {minimum}"),
                ),
            });
        }

        if a.require_kid_bound_to_key == Some(true) {
            // Only fully verified receipts. Reading every receipt here made
            // this assertion an attacker-triggerable denial of gate: appending
            // one junk receipt, whose key never resolves, left a `None` in the
            // list and forced `cannotEvaluate` on a statement that was
            // otherwise fine. Nobody needs a signing key to append a receipt.
            //
            // Filtering does not weaken the assertion. `fully_verified()`
            // requires the key to have been *found*, not that its kid was
            // derived from it, so the case this rule exists to catch — a
            // genuine, verifying receipt whose kid is not its key's digest —
            // still reaches the check below.
            let flags: Vec<Option<bool>> = facts
                .verified_receipts()
                .map(|r| r.kid_bound_to_key)
                .collect();
            results.push(if flags.is_empty() {
                result(
                    "requireKidBoundToKey",
                    Outcome::CannotEvaluate,
                    "no receipt fully verified, so no signing key was resolved to compare",
                )
            } else if flags.iter().any(Option::is_none) {
                result(
                    "requireKidBoundToKey",
                    Outcome::CannotEvaluate,
                    "a verified receipt's kid could not be compared to its signing key",
                )
            } else if flags.iter().all(|f| *f == Some(true)) {
                result(
                    "requireKidBoundToKey",
                    Outcome::Pass,
                    "every receipt's kid is the digest of its signing key",
                )
            } else {
                result(
                    "requireKidBoundToKey",
                    Outcome::Fail,
                    "a receipt's kid is not the digest of its signing key",
                )
            });
        }

        PolicyDecision {
            policy_id: self.policy_id.clone(),
            policy_version: self.policy_version.clone(),
            results,
        }
    }
}

fn result(name: &str, outcome: Outcome, detail: impl Into<String>) -> AssertionResult {
    AssertionResult {
        name: name.to_string(),
        outcome,
        detail: detail.into(),
    }
}

/// Name an external signer for a report.
///
/// Says "certificate naming X" rather than "X", because that is all that was
/// established: no chain was validated, so the subject is a string the
/// certificate's own author chose.
fn describe_signer(signer: &DetachedSigner) -> String {
    match &signer.subject {
        Some(subject) => format!("a certificate naming '{subject}'"),
        None => "a certificate with no subject".into(),
    }
}

/// Match one resolved header value against its declared type and criteria.
///
/// A present value of the wrong CBOR type is a `fail`, not a `cannotEvaluate`.
/// The tool did reach an answer — the statement says something, and it is not
/// what the policy described — and the detail names both types so an author
/// who addressed the wrong label can see it immediately.
fn evaluate_header(header: &HeaderAssertion, at: &str, value: &CborValue) -> AssertionResult {
    let name = "protectedHeaders";

    if let Some(expected) = &header.text {
        return match value {
            CborValue::TextString(s) if expected.matches(s) => result(
                name,
                Outcome::Pass,
                format!("{at}: '{s}' {}", expected.describe()),
            ),
            CborValue::TextString(s) => result(
                name,
                Outcome::Fail,
                format!("{at}: '{s}' does not match: it {}", expected.describe()),
            ),
            other => result(
                name,
                Outcome::Fail,
                format!(
                    "{at}: expected a text string, found {}",
                    scitt_receipt::render_scalar(other)
                ),
            ),
        };
    }

    if let Some(expected) = &header.int {
        return match value {
            CborValue::Int(i) if expected.matches(*i) => result(
                name,
                Outcome::Pass,
                format!("{at}: {i} {}", expected.describe()),
            ),
            CborValue::Int(i) => result(
                name,
                Outcome::Fail,
                format!("{at}: {i} does not match: it {}", expected.describe()),
            ),
            // A tagged integer is deliberately not unwrapped. Tag 1 is a date
            // and tag 2 a bignum; silently reading through the tag would let a
            // policy match a value whose meaning it never established.
            other => result(
                name,
                Outcome::Fail,
                format!(
                    "{at}: expected an integer, found {}",
                    scitt_receipt::render_scalar(other)
                ),
            ),
        };
    }

    if let Some(expected) = &header.alg {
        return match value {
            CborValue::Int(i) if expected.matches(*i) => result(
                name,
                Outcome::Pass,
                format!(
                    "{at}: {} ({i}) {}",
                    labels::alg::name(*i),
                    expected.describe()
                ),
            ),
            // Both sides are named. An author who wrote ES384 and met ES512
            // learns that from the report rather than from a registry.
            CborValue::Int(i) => result(
                name,
                Outcome::Fail,
                format!(
                    "{at}: {} ({i}) does not match: it {}",
                    labels::alg::name(*i),
                    expected.describe()
                ),
            ),
            other => result(
                name,
                Outcome::Fail,
                format!(
                    "{at}: expected an algorithm identifier, found {}",
                    scitt_receipt::render_scalar(other)
                ),
            ),
        };
    }

    // Unreachable via `from_json`, which refuses a matcher-less assertion.
    result(
        name,
        Outcome::CannotEvaluate,
        format!("{at}: no matcher declared"),
    )
}

fn compare_time(
    name: &str,
    registered_at: Option<i64>,
    predicate: impl Fn(i64) -> bool,
    requirement: String,
) -> AssertionResult {
    match registered_at {
        // No verified receipt means no trustworthy registration time. Falling
        // back to the statement's own `iat` here would let the issuer choose
        // the answer to a time-based policy question.
        None => result(
            name,
            Outcome::CannotEvaluate,
            format!("{requirement}, but no verified receipt supplied a registration time"),
        ),
        Some(t) if predicate(t) => result(
            name,
            Outcome::Pass,
            format!("registered at {t}; {requirement}"),
        ),
        Some(t) => result(
            name,
            Outcome::Fail,
            format!("registered at {t}; {requirement}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scitt_receipt::keys::KeyLookup;
    use scitt_receipt::receipt::ReceiptFacts;

    #[test]
    fn unknown_assertions_are_refused() {
        let json = br#"{"policyId":"p","policyVersion":"1","assertions":{"quantumProof":true}}"#;
        let err = Policy::from_json(json).unwrap_err();
        assert!(err.contains("not valid"), "{err}");
    }

    #[test]
    fn an_empty_policy_is_refused() {
        let json = br#"{"policyId":"p","policyVersion":"1","assertions":{}}"#;
        assert!(Policy::from_json(json).is_err());
    }

    fn subject_policy(criteria: &str) -> Result<Policy, String> {
        let json = format!(
            r#"{{"policyId":"p","policyVersion":"1","assertions":{{"statementSubject":{criteria}}}}}"#
        );
        Policy::from_json(json.as_bytes())
    }

    fn receipt_count_policy(value: &str) -> Result<Policy, String> {
        let json = format!(
            r#"{{"policyId":"p","policyVersion":"1","assertions":{{"receiptCount":{value}}}}}"#
        );
        Policy::from_json(json.as_bytes())
    }

    #[test]
    fn one_receipt_is_the_only_accepted_count() {
        assert!(receipt_count_policy("1").is_ok());
    }

    #[test]
    fn asking_for_two_receipts_is_refused_at_parse_time() {
        // The count is unobtainable rather than merely strict: no service this
        // tool verifies against issues two receipts, and the only way to reach
        // two is to attach a copy of the one that exists. Refusing the policy
        // tells the operator that; failing every artifact would not.
        let err = receipt_count_policy("2").unwrap_err();
        assert!(err.contains("only supported value is 1"), "{err}");
    }

    #[test]
    fn a_large_receipt_count_is_refused_too() {
        assert!(receipt_count_policy("99").is_err());
    }

    #[test]
    fn a_zero_receipt_count_is_refused() {
        // Zero would accept a statement carrying no proof of registration at
        // all, which is the one thing this tool exists to require.
        assert!(receipt_count_policy("0").is_err());
    }

    #[test]
    fn an_extra_receipt_fails_the_count_even_though_it_is_disregarded() {
        // The whole point of the assertion. An inserted receipt does not
        // verify, so `verified_receipts()` cannot see it and the verdict
        // rightly ignores it — but the file still is not the one the service
        // returned, and an operator who asked for exactly one is told so.
        let policy = receipt_count_policy("1").unwrap();
        let facts = StatementFacts {
            receipts_present: 2,
            ..Default::default()
        };
        assert!(policy.evaluate(&facts, 0).failed());
    }

    #[test]
    fn a_single_receipt_satisfies_the_count() {
        let policy = receipt_count_policy("1").unwrap();
        let facts = StatementFacts {
            receipts_present: 1,
            ..Default::default()
        };
        assert!(!policy.evaluate(&facts, 0).failed());
    }

    #[test]
    fn a_policy_of_only_a_new_assertion_is_not_empty() {
        // Guards the reflective `is_empty`. The hand-written chain it replaced
        // had to be extended for every assertion, and forgetting to do so
        // rejected a valid policy as though it declared nothing.
        subject_policy(r#"{"startsWith":"release-manifest-"}"#).unwrap();
    }

    #[test]
    fn a_subject_match_with_no_criteria_is_refused() {
        let err = subject_policy("{}").unwrap_err();
        assert!(err.contains("no match criteria"), "{err}");
    }

    #[test]
    fn a_subject_match_that_cannot_reject_anything_is_refused() {
        // `startsWith: ""` is satisfied by every string. Accepting it would put
        // a rule in the report that passed without examining anything — the
        // same class of failure as an assertion nobody ran.
        let err = subject_policy(r#"{"startsWith":""}"#).unwrap_err();
        assert!(err.contains("empty string"), "{err}");
    }

    #[test]
    fn a_subject_match_nothing_can_satisfy_is_refused() {
        let err = subject_policy(r#"{"oneOf":[]}"#).unwrap_err();
        assert!(err.contains("oneOf is empty"), "{err}");
    }

    #[test]
    fn a_subject_match_with_two_modes_is_refused() {
        let err = subject_policy(r#"{"equals":"a","startsWith":"b"}"#).unwrap_err();
        assert!(err.contains("exactly one"), "{err}");
    }

    #[test]
    fn an_unknown_subject_match_mode_is_refused() {
        // `contains` is deliberately absent: `signerSubjectContains` reads a
        // certificate, and a substring match on an identity claim invites a
        // policy for 'release-manifest-1' to accept 'not-release-manifest-12'.
        assert!(subject_policy(r#"{"contains":"release"}"#).is_err());
    }

    #[test]
    fn an_absent_subject_claim_cannot_evaluate_rather_than_fail() {
        // "the statement claims no subject" and "the statement claims the wrong
        // subject" call for different responses from whoever reads the report.
        let policy = subject_policy(r#"{"equals":"release-manifest-1"}"#).unwrap();
        let facts = StatementFacts::default();
        assert_eq!(facts.cwt.sub, None);
        let decision = policy.evaluate(&facts, 0);
        assert!(decision.unevaluable(), "{decision:?}");
        assert!(!decision.failed(), "{decision:?}");
        assert!(!decision.satisfied(), "{decision:?}");
    }

    #[test]
    fn a_subject_prefix_does_not_match_in_the_middle() {
        let policy = subject_policy(r#"{"startsWith":"release-manifest-"}"#).unwrap();
        let facts = StatementFacts {
            cwt: scitt_receipt::statement::CwtClaims {
                sub: Some("evil-release-manifest-1".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(policy.evaluate(&facts, 0).failed());
    }

    fn statement_issuer_policy(criteria: &str) -> Result<Policy, String> {
        let json = format!(
            r#"{{"policyId":"p","policyVersion":"1","assertions":{{"statementIssuer":{criteria}}}}}"#
        );
        Policy::from_json(json.as_bytes())
    }

    fn facts_with_issuer(iss: &str) -> StatementFacts {
        StatementFacts {
            cwt: scitt_receipt::statement::CwtClaims {
                iss: Some(iss.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn a_statement_issuer_alone_is_a_complete_policy() {
        // `is_empty` decides this by serialising the assertions, so a new field
        // is covered automatically — but only while it serialises. This pins
        // that, because the failure would be a policy refused as empty while
        // plainly asserting something.
        assert!(statement_issuer_policy(r#"{"equals":"did:x509:0:sha256:abc"}"#).is_ok());
    }

    #[test]
    fn a_statement_issuer_match_with_no_criteria_is_refused() {
        // The validation is shared with `statementSubject`, so what this pins
        // is that it was wired up at all: an unvalidated criteria object would
        // report a rule that ran and passed while examining nothing.
        let err = statement_issuer_policy("{}").unwrap_err();
        assert!(err.contains("statementIssuer"), "{err}");
    }

    #[test]
    fn a_statement_issuer_match_that_cannot_reject_anything_is_refused() {
        assert!(statement_issuer_policy(r#"{"startsWith":""}"#).is_err());
        assert!(statement_issuer_policy(r#"{"oneOf":[]}"#).is_err());
    }

    #[test]
    fn a_statement_issuer_match_with_two_modes_is_refused() {
        assert!(statement_issuer_policy(r#"{"equals":"a","startsWith":"b"}"#).is_err());
    }

    #[test]
    fn an_absent_issuer_claim_cannot_evaluate_rather_than_fail() {
        let policy = statement_issuer_policy(r#"{"equals":"did:x509:0:sha256:abc"}"#).unwrap();
        let facts = StatementFacts::default();
        assert_eq!(facts.cwt.iss, None);
        let decision = policy.evaluate(&facts, 0);
        assert!(decision.unevaluable(), "{decision:?}");
        assert!(!decision.failed(), "{decision:?}");
        assert!(!decision.satisfied(), "{decision:?}");
    }

    #[test]
    fn a_matching_statement_issuer_passes() {
        let policy = statement_issuer_policy(r#"{"equals":"did:x509:0:sha256:abc"}"#).unwrap();
        assert!(policy
            .evaluate(&facts_with_issuer("did:x509:0:sha256:abc"), 0)
            .satisfied());
    }

    #[test]
    fn a_different_statement_issuer_fails() {
        let policy = statement_issuer_policy(r#"{"equals":"did:x509:0:sha256:abc"}"#).unwrap();
        assert!(policy
            .evaluate(&facts_with_issuer("did:x509:0:sha256:zzz"), 0)
            .failed());
    }

    #[test]
    fn an_issuer_prefix_does_not_match_in_the_middle() {
        // The reason there is no `contains` mode. A did:x509 an attacker
        // controls can embed the string a relying party is pinning, so a
        // substring rule would accept the impostor it was written to exclude.
        let policy = statement_issuer_policy(r#"{"startsWith":"did:x509:0:sha256:abc"}"#).unwrap();
        assert!(policy
            .evaluate(&facts_with_issuer("did:x509:0:sha256:evil"), 0)
            .failed());
        assert!(policy
            .evaluate(&facts_with_issuer("not-did:x509:0:sha256:abc"), 0)
            .failed());
    }

    #[test]
    fn the_subject_and_issuer_rules_read_different_claims() {
        // Both are StringMatch over a CWT claim, so a copy-paste that pointed
        // one at the other's field would satisfy every test above.
        let policy = statement_issuer_policy(r#"{"equals":"who"}"#).unwrap();
        let facts = StatementFacts {
            cwt: scitt_receipt::statement::CwtClaims {
                iss: Some("who".into()),
                sub: Some("what".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(policy.evaluate(&facts, 0).satisfied());

        let subject = subject_policy(r#"{"equals":"who"}"#).unwrap();
        assert!(subject.evaluate(&facts, 0).failed());
    }

    #[test]
    fn a_decision_with_no_results_is_not_satisfied() {
        let decision = PolicyDecision {
            policy_id: "p".into(),
            policy_version: "1".into(),
            results: vec![],
        };
        assert!(!decision.satisfied());
    }

    #[test]
    fn cannot_evaluate_is_not_a_pass() {
        let decision = PolicyDecision {
            policy_id: "p".into(),
            policy_version: "1".into(),
            results: vec![result("minSvn", Outcome::CannotEvaluate, "no svn")],
        };
        assert!(!decision.satisfied());
        assert!(!decision.failed());
        assert!(decision.unevaluable());
    }

    fn policy_accepting(issuer: &str) -> Policy {
        let json = format!(
            r#"{{"policyId":"p","policyVersion":"1","assertions":{{"issuer":["{issuer}"]}}}}"#
        );
        Policy::from_json(json.as_bytes()).unwrap()
    }

    fn verified_receipt(issuer: &str) -> ReceiptFacts {
        ReceiptFacts {
            issuer: Some(issuer.into()),
            root_signature_valid: Some(true),
            bound_to_statement: Some(true),
            key_lookup: Some(KeyLookup::Found),
            ..Default::default()
        }
    }

    fn unverified_receipt(issuer: &str) -> ReceiptFacts {
        ReceiptFacts {
            issuer: Some(issuer.into()),
            ..Default::default()
        }
    }

    fn facts_with(receipts: Vec<ReceiptFacts>) -> StatementFacts {
        StatementFacts {
            receipts,
            ..Default::default()
        }
    }

    #[test]
    fn an_unverified_receipt_cannot_satisfy_the_issuer_assertion() {
        // Receipts ride in the statement's unprotected bucket, so anyone can
        // append one that declares whatever issuer the policy wants to see.
        let facts = facts_with(vec![unverified_receipt("trusted.example")]);
        let decision = policy_accepting("trusted.example").evaluate(&facts, 0);
        assert!(!decision.satisfied(), "{decision:?}");
        assert!(decision.unevaluable(), "{decision:?}");
    }

    #[test]
    fn a_forged_receipt_cannot_launder_a_genuine_one_from_another_ledger() {
        // A genuine receipt from a ledger the policy rejects, plus a forged
        // receipt naming the ledger it accepts, must not add up to a pass.
        let facts = facts_with(vec![
            verified_receipt("other.example"),
            unverified_receipt("trusted.example"),
        ]);
        let decision = policy_accepting("trusted.example").evaluate(&facts, 0);
        assert!(decision.failed(), "{decision:?}");
    }

    #[test]
    fn a_verified_receipt_satisfies_the_issuer_assertion() {
        let facts = facts_with(vec![verified_receipt("trusted.example")]);
        assert!(policy_accepting("trusted.example")
            .evaluate(&facts, 0)
            .satisfied());
    }

    fn kid_policy() -> Policy {
        let json =
            br#"{"policyId":"p","policyVersion":"1","assertions":{"requireKidBoundToKey":true}}"#;
        Policy::from_json(json).unwrap()
    }

    #[test]
    fn an_appended_junk_receipt_cannot_deny_the_gate() {
        // Anyone handling the file can append a receipt whose key never
        // resolves. If that alone forced cannotEvaluate, appending junk would
        // be enough to stop a good build from shipping.
        let mut good = verified_receipt("trusted.example");
        good.kid_bound_to_key = Some(true);
        let facts = facts_with(vec![good, unverified_receipt("whatever")]);
        assert!(kid_policy().evaluate(&facts, 0).satisfied());
    }

    #[test]
    fn a_verified_receipt_with_an_unbound_kid_still_fails() {
        // The filter above must not swallow the case this assertion exists for.
        let mut bad = verified_receipt("trusted.example");
        bad.kid_bound_to_key = Some(false);
        assert!(kid_policy().evaluate(&facts_with(vec![bad]), 0).failed());
    }

    #[test]
    fn nothing_verified_means_the_kid_rule_cannot_be_evaluated() {
        let facts = facts_with(vec![unverified_receipt("trusted.example")]);
        assert!(kid_policy().evaluate(&facts, 0).unevaluable());
    }

    // --- protectedHeaders -------------------------------------------------

    fn header_policy(assertion: &str) -> Policy {
        let json = format!(
            r#"{{"policyId":"t","policyVersion":"1","assertions":{{"protectedHeaders":[{assertion}]}}}}"#
        );
        Policy::from_json(json.as_bytes()).expect("policy should parse")
    }

    fn facts_with_protected(protected: CborValue) -> StatementFacts {
        StatementFacts {
            protected: Some(protected),
            ..Default::default()
        }
    }

    fn map(entries: Vec<(CborValue, CborValue)>) -> CborValue {
        CborValue::Map(entries)
    }

    fn text(s: &str) -> CborValue {
        CborValue::TextString(s.into())
    }

    fn outcome_of(policy: &Policy, facts: &StatementFacts) -> Outcome {
        let decision = policy.evaluate(facts, 0);
        assert_eq!(decision.results.len(), 1, "expected exactly one result");
        decision.results[0].outcome
    }

    #[test]
    fn an_algorithm_matches_by_name() {
        let facts = facts_with_protected(map(vec![(CborValue::Int(1), CborValue::Int(-7))]));
        let by_name = header_policy(r#"{"path":[1],"alg":{"oneOf":["ES256","ES384","PS256"]}}"#);
        let by_number = header_policy(r#"{"path":[1],"int":{"oneOf":[-7,-35,-37]}}"#);

        // The point of the matcher is that these are the same rule. If they
        // ever diverge, one of the two spellings is lying to its author.
        assert_eq!(outcome_of(&by_name, &facts), Outcome::Pass);
        assert_eq!(outcome_of(&by_number, &facts), Outcome::Pass);
    }

    #[test]
    fn an_algorithm_report_names_both_sides() {
        // The reason to prefer `alg` is legibility under failure. A report
        // reading "-36 is not one of [-7, -35]" sends the reader to a registry
        // at the moment they are trying to understand a refusal.
        let facts = facts_with_protected(map(vec![(CborValue::Int(1), CborValue::Int(-36))]));
        let policy = header_policy(r#"{"path":[1],"alg":{"oneOf":["ES256","ES384"]}}"#);
        let decision = policy.evaluate(&facts, 0);

        assert_eq!(decision.results[0].outcome, Outcome::Fail);
        let detail = &decision.results[0].detail;
        assert!(detail.contains("ES512 (-36)"), "{detail}");
        assert!(detail.contains("[ES256, ES384]"), "{detail}");
    }

    #[test]
    fn an_unknown_algorithm_name_is_refused_when_the_policy_is_read() {
        // This is the whole argument for the matcher. `-38` for `-37` is a
        // policy that runs forever against an algorithm nobody chose; "PS257"
        // cannot survive first contact with the parser.
        let json = r#"{"policyId":"t","policyVersion":"1","assertions":{
            "protectedHeaders":[{"path":[1],"alg":{"equals":"PS257"}}]}}"#;
        let err = Policy::from_json(json.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("PS257"), "{err}");
        assert!(
            err.contains("ES256"),
            "the error must list what is known: {err}"
        );
    }

    #[test]
    fn an_algorithm_name_is_not_repaired() {
        // Case folding here would make 'es256' work and leave the author
        // believing the spelling is free. The registry has one spelling.
        for spelling in ["es256", "ES-256", " ES256"] {
            let json = format!(
                r#"{{"policyId":"t","policyVersion":"1","assertions":{{
                   "protectedHeaders":[{{"path":[1],"alg":{{"equals":"{spelling}"}}}}]}}}}"#
            );
            assert!(
                Policy::from_json(json.as_bytes()).is_err(),
                "'{spelling}' must not be accepted"
            );
        }
    }

    #[test]
    fn an_algorithm_matcher_and_an_integer_matcher_cannot_be_combined() {
        // Both read an integer, so a value satisfying one and not the other
        // would make the verdict depend on evaluation order.
        let json = r#"{"policyId":"t","policyVersion":"1","assertions":{
            "protectedHeaders":[{"path":[1],"alg":{"equals":"ES256"},"int":{"equals":-7}}]}}"#;
        let err = Policy::from_json(json.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("more than one matcher"), "{err}");
    }

    #[test]
    fn an_algorithm_matcher_with_no_criteria_is_refused() {
        let json = r#"{"policyId":"t","policyVersion":"1","assertions":{
            "protectedHeaders":[{"path":[1],"alg":{}}]}}"#;
        let err = Policy::from_json(json.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("no match criteria"), "{err}");
    }

    #[test]
    fn an_algorithm_matcher_reaches_a_private_use_label() {
        // The nested case is why this is a matcher and not an interpretation
        // the tool applies to label 1. Inside a vendor structure the tool has
        // no basis to know key 1 is an algorithm; the author asserts it.
        let facts = facts_with_protected(map(vec![(
            text("external-signature"),
            CborValue::Array(vec![map(vec![(CborValue::Int(1), CborValue::Int(-257))])]),
        )]));
        let policy =
            header_policy(r#"{"path":["external-signature",0,1],"alg":{"equals":"RS256"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Pass);
    }

    #[test]
    fn an_algorithm_matcher_on_a_non_integer_fails_rather_than_cannot_evaluate() {
        let facts = facts_with_protected(map(vec![(CborValue::Int(1), text("ES256"))]));
        let policy = header_policy(r#"{"path":[1],"alg":{"equals":"ES256"}}"#);
        // The statement said something and it was not an algorithm identifier.
        // Reading the name out of a text string would accept a header whose
        // type was never what the policy described.
        assert_eq!(outcome_of(&policy, &facts), Outcome::Fail);
    }

    #[test]
    fn a_text_header_matches_by_label() {
        let facts = facts_with_protected(map(vec![(CborValue::Int(3), text("application/cose"))]));
        let policy = header_policy(r#"{"path":[3],"text":{"equals":"application/cose"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Pass);
    }

    #[test]
    fn a_text_label_and_an_integer_label_are_different_headers() {
        // JSON's own number/string distinction is what keeps these apart. An
        // object keyed by label could not, since JSON object keys are strings.
        let facts = facts_with_protected(map(vec![(text("15"), text("decoy"))]));
        let by_int = header_policy(r#"{"path":[15],"text":{"equals":"decoy"}}"#);
        let by_text = header_policy(r#"{"path":["15"],"text":{"equals":"decoy"}}"#);

        assert_eq!(outcome_of(&by_int, &facts), Outcome::CannotEvaluate);
        assert_eq!(outcome_of(&by_text, &facts), Outcome::Pass);
    }

    #[test]
    fn a_path_descends_into_a_nested_map() {
        let facts = facts_with_protected(map(vec![(
            CborValue::Int(15),
            map(vec![(CborValue::Int(2), text("unknown.intent"))]),
        )]));
        let policy = header_policy(r#"{"path":[15,2],"text":{"equals":"unknown.intent"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Pass);
    }

    #[test]
    fn an_integer_segment_indexes_an_array() {
        let facts = facts_with_protected(map(vec![(
            CborValue::Int(34),
            CborValue::Array(vec![CborValue::Int(-16), text("thumbprint")]),
        )]));
        let policy = header_policy(r#"{"path":[34,0],"int":{"equals":-16}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Pass);
    }

    #[test]
    fn an_absent_header_cannot_be_evaluated_rather_than_failing() {
        // "says nothing" and "says the wrong thing" call for different
        // responses, exactly as for statementSubject.
        let facts = facts_with_protected(map(vec![(CborValue::Int(3), text("application/cose"))]));
        let policy = header_policy(r#"{"path":[-65537],"text":{"equals":"x"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::CannotEvaluate);
    }

    /// The reason values are matched by declared CBOR type.
    ///
    /// `render_scalar` summarises a three-element array as the string
    /// `"array of 3"`. If matching ran against that rendering, a text header
    /// whose content is literally `array of 3` would be indistinguishable from
    /// a real array. Naming the type makes the two cases disjoint.
    #[test]
    fn a_text_header_cannot_impersonate_a_container() {
        let decoy = facts_with_protected(map(vec![(CborValue::Int(9), text("array of 3"))]));
        let real = facts_with_protected(map(vec![(
            CborValue::Int(9),
            CborValue::Array(vec![
                CborValue::Int(1),
                CborValue::Int(2),
                CborValue::Int(3),
            ]),
        )]));

        let policy = header_policy(r#"{"path":[9],"text":{"equals":"array of 3"}}"#);
        assert_eq!(outcome_of(&policy, &decoy), Outcome::Pass);
        assert_eq!(outcome_of(&policy, &real), Outcome::Fail);
    }

    /// Two byte strings sharing a 16-byte prefix render identically, because
    /// `render_scalar` truncates. Neither can satisfy a typed matcher at all,
    /// so the collision is unreachable from a policy.
    #[test]
    fn byte_strings_are_not_matchable_by_their_truncated_rendering() {
        let mut a = vec![0xABu8; 16];
        let mut b = a.clone();
        a.push(0x01);
        b.push(0x02);
        assert_eq!(
            scitt_receipt::render_scalar(&CborValue::ByteString(a.clone())),
            scitt_receipt::render_scalar(&CborValue::ByteString(b)),
            "precondition: the renderings collide"
        );

        let facts = facts_with_protected(map(vec![(CborValue::Int(4), CborValue::ByteString(a))]));
        let rendered = "17 bytes: abababababababababababababababab…";
        let policy = header_policy(&format!(
            r#"{{"path":[4],"text":{{"equals":"{rendered}"}}}}"#
        ));
        assert_eq!(outcome_of(&policy, &facts), Outcome::Fail);
    }

    #[test]
    fn a_present_header_of_the_wrong_type_fails_rather_than_abstaining() {
        // The tool reached an answer: the statement says something, and it is
        // not the shape the policy described.
        let facts = facts_with_protected(map(vec![(CborValue::Int(1), CborValue::Int(-37))]));
        let policy = header_policy(r#"{"path":[1],"text":{"equals":"-37"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Fail);
    }

    #[test]
    fn a_tagged_integer_is_not_read_through_its_tag() {
        // Tag 1 is a date and tag 2 a bignum. Unwrapping silently would let a
        // policy match a value whose meaning it never established.
        let facts = facts_with_protected(map(vec![(
            CborValue::Int(6),
            CborValue::Tagged {
                tag: 1,
                payload: Box::new(CborValue::Int(1_785_197_767)),
            },
        )]));
        let policy = header_policy(r#"{"path":[6],"int":{"equals":1785197767}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Fail);
    }

    /// A CBOR map may carry the same key twice and nothing upstream rejects
    /// it. Taking the first would let a producer show this tool one value and
    /// another parser a different one, from the same signed bytes.
    #[test]
    fn a_duplicated_label_is_refused_rather_than_resolved_to_the_first() {
        let facts = facts_with_protected(map(vec![
            (CborValue::Int(7), text("production")),
            (CborValue::Int(7), text("debug")),
        ]));
        let policy = header_policy(r#"{"path":[7],"text":{"equals":"production"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Fail);

        let detail = &policy.evaluate(&facts, 0).results[0].detail;
        assert!(
            detail.contains("more than once"),
            "the detail should name the ambiguity, got: {detail}"
        );
    }

    #[test]
    fn a_segment_applied_to_a_scalar_fails_with_a_reason() {
        let facts = facts_with_protected(map(vec![(CborValue::Int(3), text("application/cose"))]));
        let policy = header_policy(r#"{"path":[3,1],"text":{"equals":"x"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Fail);
    }

    #[test]
    fn a_text_segment_cannot_index_an_array() {
        let facts = facts_with_protected(map(vec![(
            CborValue::Int(33),
            CborValue::Array(vec![CborValue::Int(1)]),
        )]));
        let policy = header_policy(r#"{"path":[33,"first"],"text":{"equals":"x"}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Fail);
    }

    /// The forward-compatibility guard. A policy written for a build that has
    /// quantifiers must not quietly become "look for a label named `*`" here.
    #[test]
    fn the_array_wildcard_is_refused_rather_than_read_as_a_label() {
        let json = br#"{"policyId":"t","policyVersion":"1","assertions":
            {"protectedHeaders":[{"path":["external-signatures","*",1],"int":{"equals":-257}}]}}"#;
        let err = Policy::from_json(json).expect_err("'*' should be refused");
        assert!(err.contains('*'), "the error should name the wildcard");
    }

    #[test]
    fn a_header_assertion_must_declare_exactly_one_matcher() {
        let none = br#"{"policyId":"t","policyVersion":"1","assertions":
            {"protectedHeaders":[{"path":[3]}]}}"#;
        let both = br#"{"policyId":"t","policyVersion":"1","assertions":
            {"protectedHeaders":[{"path":[3],"text":{"equals":"x"},"int":{"equals":1}}]}}"#;
        assert!(Policy::from_json(none).is_err());
        assert!(Policy::from_json(both).is_err());
    }

    #[test]
    fn an_unsatisfiable_integer_range_is_refused_when_the_policy_is_parsed() {
        // Same bargain as `oneOf: []`: a policy nobody could pass is a
        // mistake, and finding it now beats finding it per-artifact later.
        let json = br#"{"policyId":"t","policyVersion":"1","assertions":
            {"protectedHeaders":[{"path":[1],"int":{"min":5,"max":2}}]}}"#;
        assert!(Policy::from_json(json).is_err());
    }

    #[test]
    fn an_integer_range_accepts_its_boundaries() {
        let facts = facts_with_protected(map(vec![(CborValue::Int(1), CborValue::Int(5))]));
        let policy = header_policy(r#"{"path":[1],"int":{"min":5,"max":5}}"#);
        assert_eq!(outcome_of(&policy, &facts), Outcome::Pass);
    }

    #[test]
    fn a_policy_of_only_protected_headers_is_not_treated_as_empty() {
        // `is_empty` serialises the assertions and checks for all-null, so a
        // new field is picked up without being listed anywhere.
        let json = br#"{"policyId":"t","policyVersion":"1","assertions":
            {"protectedHeaders":[{"path":[3],"text":{"equals":"application/cose"}}]}}"#;
        assert!(Policy::from_json(json).is_ok());
    }

    #[test]
    fn every_header_assertion_produces_its_own_result() {
        let facts = facts_with_protected(map(vec![
            (CborValue::Int(1), CborValue::Int(-37)),
            (CborValue::Int(3), text("application/cose")),
        ]));
        let json = br#"{"policyId":"t","policyVersion":"1","assertions":{"protectedHeaders":[
            {"path":[1],"int":{"equals":-37}},
            {"path":[3],"text":{"equals":"application/cose"}}]}}"#;
        let policy = Policy::from_json(json).unwrap();
        let decision = policy.evaluate(&facts, 0);
        assert_eq!(decision.results.len(), 2);
        assert!(decision.satisfied());
    }
}
