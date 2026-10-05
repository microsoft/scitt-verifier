//! Appraisal of a supplied image rebuild against the reproduction record an
//! accepted statement commits to.
//!
//! The question answered here is narrow: *does a rebuild someone supplied
//! match the reproduction record this statement authenticates — the same
//! recorded inputs, and the same ordered filesystem layers?*
//!
//! What it deliberately does not answer, because nothing here establishes it:
//!
//! * **Whether the rebuild was independent.** The rebuilt record is whatever
//!   the operator hands in. A copy of the published record passes. The claim
//!   is "the supplied rebuild matches", never "an independent rebuild was
//!   established"; the second needs an approved runner or authenticated
//!   builder evidence, and this crate has neither.
//! * **Whether a published image has these layers**, or whether any
//!   deployment runs them. No registry is contacted and no dm-verity root is
//!   derived.
//! * **Whether the source is safe.** Reproducibility says the bytes follow
//!   from the source; it says nothing about the source.
//!
//! Like the ledger adapter, this crate reports checks and cannot express a
//! verdict. It runs no build, reads no file and makes no request.

use serde_json::{Map, Value};

/// The only profile this build understands: the transparent-signing payload
/// the MST release pipeline registers for each CTS image.
///
/// A profile is code, not configuration: it decides which statement fields
/// and which record fields mean what. A policy naming any other profile is
/// refused as unsupported rather than read under this one's rules.
pub const PROFILE_MST_TBS: &str = "mst-tbs";

/// The payload `schema-version` this profile reads. Version 1 payloads carry
/// no provenance at all.
pub const PAYLOAD_SCHEMA_VERSION: u64 = 2;

/// `schema_version` of the `reproduce.json` records this profile reads.
const RECORD_SCHEMA_VERSION: u64 = 1;

/// Recorded inputs that must be identical between the published record and
/// the rebuild. A difference in any of them means the rebuild did not use the
/// recorded inputs, so its layers — matching or not — are not evidence about
/// the recorded build.
pub const INPUT_FIELDS: [&str; 9] = [
    "source_commit",
    "scitt_version",
    "context_sha256",
    "source_date_epoch",
    "base_image",
    "ccf_version",
    "ccf_rpm_sha256",
    "ccf_reproduce_sha256",
    "tdnf_snapshottime",
];

/// Builder and image-store details that may legitimately differ between two
/// builds that produce identical layers. Reported, never compared.
const INFORMATIONAL_FIELDS: [&str; 3] = ["docker_version", "buildx_version", "image_id"];

/// Stable machine names and labels, in report order.
pub const CHECK_NAMES: [(&str, &str); 5] = [
    ("reproduction-claim", "Statement reproduction claim"),
    ("source-repository", "Source repository"),
    ("record-binding", "Reproduction record binding"),
    ("rebuild-inputs", "Rebuild inputs"),
    ("rebuild-layers", "Rebuilt filesystem layers"),
];

/// Three states, not four: every check here is always attempted when this
/// adapter is selected, so "nobody asked" never arises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Pass,
    Fail,
    CannotEvaluate,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub state: CheckState,
    pub detail: String,
}

impl Check {
    fn pass(detail: impl Into<String>) -> Self {
        Self {
            state: CheckState::Pass,
            detail: detail.into(),
        }
    }
    fn fail(detail: impl Into<String>) -> Self {
        Self {
            state: CheckState::Fail,
            detail: detail.into(),
        }
    }
    fn cannot(detail: impl Into<String>) -> Self {
        Self {
            state: CheckState::CannotEvaluate,
            detail: detail.into(),
        }
    }
}

/// One compared value, kept structured so a reader sees both sides.
#[derive(Debug, Clone)]
pub struct Finding {
    pub check: &'static str,
    pub subject: String,
    pub state: CheckState,
    pub detail: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
}

/// Fields, not a list, so a check cannot be forgotten at a construction site.
#[derive(Debug, Clone)]
pub struct Appraisal {
    /// The accepted statement carries a well-formed claim under this profile.
    pub reproduction_claim: Check,
    /// The claimed source repository is the one the relying party allows.
    pub source_repository: Check,
    /// The supplied record's exact bytes are the ones the statement commits
    /// to, and the fields both carry agree.
    pub record_binding: Check,
    /// The rebuild used the recorded inputs.
    pub rebuild_inputs: Check,
    /// The rebuild produced the recorded filesystem layers, in order.
    pub rebuild_layers: Check,
    pub findings: Vec<Finding>,
    /// Differences that do not bear on the claim, reported so they are not
    /// mistaken for having been checked.
    pub informational: Vec<String>,
}

impl Appraisal {
    /// Every check unable to run, for one reason.
    pub fn unevaluated(reason: &str) -> Self {
        Self {
            reproduction_claim: Check::cannot(reason),
            source_repository: Check::cannot(reason),
            record_binding: Check::cannot(reason),
            rebuild_inputs: Check::cannot(reason),
            rebuild_layers: Check::cannot(reason),
            findings: Vec::new(),
            informational: Vec::new(),
        }
    }

    /// Checks in [`CHECK_NAMES`] order.
    pub fn checks(&self) -> [(&'static str, &'static str, &Check); 5] {
        [
            (CHECK_NAMES[0].0, CHECK_NAMES[0].1, &self.reproduction_claim),
            (CHECK_NAMES[1].0, CHECK_NAMES[1].1, &self.source_repository),
            (CHECK_NAMES[2].0, CHECK_NAMES[2].1, &self.record_binding),
            (CHECK_NAMES[3].0, CHECK_NAMES[3].1, &self.rebuild_inputs),
            (CHECK_NAMES[4].0, CHECK_NAMES[4].1, &self.rebuild_layers),
        ]
    }
}

/// What the relying party requires, translated from its policy by the caller.
pub struct Requirements<'a> {
    pub profile: &'a str,
    /// `component.app` the statement must name. A signing pipeline issues
    /// statements for several components, all under one identity.
    pub app: &'a str,
    /// `component.variant` the statement must name, so a debug image's
    /// statement cannot satisfy a policy written for the production one.
    pub variant: &'a str,
    /// Compared exactly. Normalising URLs would make two spellings of a
    /// repository one, and deciding when that is safe is not this crate's call.
    pub source_repository: &'a str,
}

/// The accepted statement's payload, as the caller could obtain it.
pub enum Payload<'a> {
    /// Embedded and declared JSON.
    Json(&'a [u8]),
    /// Embedded but declared as something else, or with no content type.
    /// Such a statement makes no reproduction claim this profile can read.
    NotJson(String),
    /// Not available to appraise at all, for example a detached payload.
    Unavailable(String),
}

/// Operator-supplied evidence. Either may be absent.
pub struct Evidence<'a> {
    /// The publisher's reproduction record, authenticated only by its digest.
    pub published_record: Option<&'a [u8]>,
    /// The rebuild's record. Operator-asserted.
    pub rebuilt_record: Option<&'a [u8]>,
}

struct Claim {
    app: String,
    variant: String,
    source_repository: String,
    source_commit: String,
    source_date_epoch: u64,
    version: String,
    context_sha256: String,
    ccf_version: String,
    record_sha256: String,
    record_uri: String,
}

pub fn appraise(payload: Payload<'_>, evidence: Evidence<'_>, req: &Requirements<'_>) -> Appraisal {
    if req.profile != PROFILE_MST_TBS {
        return Appraisal::unevaluated(&format!(
            "profile {:?} is not supported by this build; supported: {PROFILE_MST_TBS}",
            req.profile
        ));
    }

    let mut findings = Vec::new();
    let mut informational = Vec::new();

    let claim = match read_claim(payload).and_then(|claim| check_component(claim, req)) {
        Ok(claim) => claim,
        Err(error) => {
            let (check, finding) = *error;
            let why = "the statement's reproduction claim was not established";
            let mut out = Appraisal::unevaluated(why);
            out.reproduction_claim = check;
            out.findings.extend(finding);
            return out;
        }
    };
    let reproduction_claim = Check::pass(format!(
        "{} {}/{} commit {} version {}; record {}",
        req.profile, claim.app, claim.variant, claim.source_commit, claim.version, claim.record_uri
    ));

    let source_repository = if claim.source_repository == req.source_repository {
        Check::pass(format!("{} is allowed", claim.source_repository))
    } else {
        findings.push(Finding {
            check: "source-repository",
            subject: "component.provenance.source-repository".into(),
            state: CheckState::Fail,
            detail: "the statement names a source repository the policy does not allow".into(),
            expected: Some(req.source_repository.to_string()),
            observed: Some(claim.source_repository.clone()),
        });
        Check::fail(format!(
            "the statement names {}, but the policy allows only {}",
            claim.source_repository, req.source_repository
        ))
    };

    let (record_binding, published) = bind_record(&claim, evidence.published_record, &mut findings);

    let rebuilt = match (&published, evidence.rebuilt_record) {
        (None, _) => Err(Check::cannot(
            "the published reproduction record was not authenticated, so there is nothing \
             trustworthy to compare the rebuild with",
        )),
        (Some(_), None) => Err(Check::cannot("no rebuilt record was supplied")),
        (Some(_), Some(bytes)) => read_rebuilt(bytes),
    };

    let (rebuild_inputs, rebuild_layers) = match (&published, rebuilt) {
        (Some(published), Ok(rebuilt)) => {
            let inputs = compare_inputs(published, &rebuilt, &mut findings);
            let layers = compare_layers(&published.layers, &rebuilt.layers, &mut findings);
            for field in INFORMATIONAL_FIELDS {
                let (a, b) = (published.fields.get(field), rebuilt.fields.get(field));
                if a != b {
                    informational.push(format!(
                        "{field} differs between the published record ({}) and the rebuild ({}); \
                         builder details are reported, not compared",
                        render(a),
                        render(b)
                    ));
                }
            }
            (inputs, layers)
        }
        (_, Err(check)) => (check.clone(), check),
        (None, Ok(_)) => unreachable!("a rebuild is only read once the record is authenticated"),
    };

    Appraisal {
        reproduction_claim,
        source_repository,
        record_binding,
        rebuild_inputs,
        rebuild_layers,
        findings,
        informational,
    }
}

type ClaimError = Box<(Check, Option<Finding>)>;

fn read_claim(payload: Payload<'_>) -> Result<Claim, ClaimError> {
    let fail = |detail: String| -> ClaimError { Box::new((Check::fail(detail), None)) };
    let bytes = match payload {
        Payload::Json(bytes) => bytes,
        Payload::NotJson(declared) => {
            return Err(fail(format!(
                "the statement's payload is declared as {declared}, not JSON, so it makes no \
                 reproduction claim"
            )))
        }
        Payload::Unavailable(why) => return Err(Box::new((Check::cannot(why), None))),
    };
    let document = scitt_policy::parse_payload_json(bytes)
        .map_err(|e| fail(format!("the statement's payload is not valid JSON: {e}")))?;
    let Value::Object(top) = document else {
        return Err(fail("the statement's payload is not a JSON object".into()));
    };

    match top.get("schema-version") {
        None => return Err(fail("the statement's payload has no schema-version".into())),
        Some(Value::Number(n)) if n.as_u64() == Some(PAYLOAD_SCHEMA_VERSION) => {}
        Some(Value::Number(n)) if n.as_u64().is_some() => {
            return Err(Box::new((
                Check::cannot(format!(
                    "payload schema-version {n} is not supported by this build; \
                     supported: {PAYLOAD_SCHEMA_VERSION}"
                )),
                None,
            )))
        }
        Some(other) => {
            return Err(fail(format!(
                "schema-version must be an integer, got {}",
                render(Some(other))
            )))
        }
    }

    let object = |map: &Map<String, Value>,
                  path: &str,
                  key: &str|
     -> Result<Map<String, Value>, ClaimError> {
        match map.get(key) {
            Some(Value::Object(inner)) => Ok(inner.clone()),
            None => Err(fail(format!("the statement's payload has no {path}"))),
            Some(other) => Err(fail(format!(
                "{path} must be an object, got {}",
                render(Some(other))
            ))),
        }
    };
    let component = object(&top, "component", "component")?;
    let provenance =
        object(&component, "component.provenance", "provenance").map_err(|mut e| {
            e.0.detail
                .push_str("; the statement makes no reproduction claim");
            e
        })?;

    let text = |map: &Map<String, Value>, path: &str, key: &str| -> Result<String, ClaimError> {
        match map.get(key) {
            Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
            other => Err(fail(format!(
                "{path}.{key} must be a non-empty string, got {}",
                render(other)
            ))),
        }
    };
    let hex = |key: &str, len: usize| -> Result<String, ClaimError> {
        let value = text(&provenance, "component.provenance", key)?;
        if is_lower_hex(&value, len) {
            Ok(value)
        } else {
            Err(fail(format!(
                "component.provenance.{key} must be {len} lowercase hex digits, got {value:?}"
            )))
        }
    };
    let source_date_epoch = match provenance.get("source-date-epoch") {
        Some(Value::Number(n)) if n.as_u64().is_some() => n.as_u64().unwrap_or_default(),
        other => {
            return Err(fail(format!(
                "component.provenance.source-date-epoch must be a non-negative integer, got {}",
                render(other)
            )))
        }
    };

    Ok(Claim {
        app: text(&component, "component", "app")?,
        variant: text(&component, "component", "variant")?,
        source_repository: text(&provenance, "component.provenance", "source-repository")?,
        source_commit: hex("source-commit", 40)?,
        source_date_epoch,
        version: text(&provenance, "component.provenance", "version")?,
        context_sha256: hex("context-sha256", 64)?,
        ccf_version: text(&provenance, "component.provenance", "ccf-version")?,
        record_sha256: hex("reproduction-record-sha256", 64)?,
        record_uri: text(
            &provenance,
            "component.provenance",
            "reproduction-record-uri",
        )?,
    })
}

/// The statement must be about the component the policy names. One signing
/// identity issues statements for every component and variant, so the
/// signature alone does not say which this is.
fn check_component(claim: Claim, req: &Requirements<'_>) -> Result<Claim, ClaimError> {
    for (key, claimed, required) in [
        ("app", &claim.app, req.app),
        ("variant", &claim.variant, req.variant),
    ] {
        if claimed != required {
            return Err(Box::new((
                Check::fail(format!(
                    "the statement is for component {key} {claimed:?}, but the policy requires {required:?}"
                )),
                Some(Finding {
                    check: "reproduction-claim",
                    subject: format!("component.{key}"),
                    state: CheckState::Fail,
                    detail: format!("the statement names a different component {key}"),
                    expected: Some(required.to_string()),
                    observed: Some(claimed.clone()),
                }),
            )));
        }
    }
    Ok(claim)
}

struct Record {
    fields: Map<String, Value>,
    layers: Vec<String>,
}

fn bind_record(
    claim: &Claim,
    bytes: Option<&[u8]>,
    findings: &mut Vec<Finding>,
) -> (Check, Option<Record>) {
    let Some(bytes) = bytes else {
        return (
            Check::cannot("no published reproduction record was supplied"),
            None,
        );
    };

    // The digest comes first and over the exact bytes. Nothing in the record
    // is read until it is known to be the record the statement commits to.
    let actual = scitt_receipt::sha256_hex(bytes);
    if actual != claim.record_sha256 {
        findings.push(Finding {
            check: "record-binding",
            subject: "component.provenance.reproduction-record-sha256".into(),
            state: CheckState::Fail,
            detail: "the supplied record is not the one the statement commits to".into(),
            expected: Some(claim.record_sha256.clone()),
            observed: Some(actual.clone()),
        });
        return (
            Check::fail(format!(
                "the supplied record's SHA-256 is {actual}, but the statement commits to {}",
                claim.record_sha256
            )),
            None,
        );
    }

    let record = match parse_record(bytes, "published record", true) {
        Ok(record) => record,
        // Authenticated but unreadable under this profile. Either the
        // publisher committed to a malformed record, which is a finding about
        // it, or it uses a schema this build does not know, which is not.
        Err(RecordError::Malformed(why)) => return (Check::fail(why), None),
        Err(RecordError::Unsupported(why)) => return (Check::cannot(why), None),
    };
    for field in INPUT_FIELDS {
        if !record.fields.contains_key(field) {
            return (
                Check::fail(format!(
                    "the published record has no {field}, which this profile requires"
                )),
                None,
            );
        }
    }

    let mut mismatched = Vec::new();
    for (claim_name, record_name, claimed) in [
        (
            "source-commit",
            "source_commit",
            Value::String(claim.source_commit.clone()),
        ),
        (
            "version",
            "scitt_version",
            Value::String(claim.version.clone()),
        ),
        (
            "context-sha256",
            "context_sha256",
            Value::String(claim.context_sha256.clone()),
        ),
        (
            "ccf-version",
            "ccf_version",
            Value::String(claim.ccf_version.clone()),
        ),
        (
            "source-date-epoch",
            "source_date_epoch",
            Value::from(claim.source_date_epoch),
        ),
    ] {
        let recorded = record.fields.get(record_name);
        if recorded != Some(&claimed) {
            mismatched.push(format!("{claim_name}/{record_name}"));
            findings.push(Finding {
                check: "record-binding",
                subject: record_name.into(),
                state: CheckState::Fail,
                detail: format!(
                    "the statement's {claim_name} and the record's {record_name} disagree"
                ),
                expected: Some(render(Some(&claimed))),
                observed: Some(render(recorded)),
            });
        }
    }
    if !mismatched.is_empty() {
        return (
            Check::fail(format!(
                "the record matches the committed digest but disagrees with the statement on {}",
                mismatched.join(", ")
            )),
            None,
        );
    }

    (
        Check::pass(format!(
            "record SHA-256 {actual} matches the statement; source commit, version, context, \
             CCF version and source date epoch agree"
        )),
        Some(record),
    )
}

fn read_rebuilt(bytes: &[u8]) -> Result<Record, Check> {
    // Every failure here is an inability, not a finding: the rebuild is the
    // operator's input, and one that cannot be read says nothing about the
    // publisher's build.
    let record = parse_record(bytes, "rebuilt record", false).map_err(|e| match e {
        RecordError::Malformed(why) | RecordError::Unsupported(why) => Check::cannot(why),
    })?;
    for field in INPUT_FIELDS {
        if !record.fields.contains_key(field) {
            return Err(Check::cannot(format!(
                "the rebuilt record has no {field}, so its inputs cannot be compared"
            )));
        }
    }
    Ok(record)
}

enum RecordError {
    Malformed(String),
    Unsupported(String),
}

/// `expectation` marks the published record, whose layer list is what a
/// rebuild is compared with; a rebuild listing no layers is merely a mismatch.
fn parse_record(bytes: &[u8], what: &str, expectation: bool) -> Result<Record, RecordError> {
    let document = scitt_policy::parse_payload_json(bytes)
        .map_err(|e| RecordError::Malformed(format!("the {what} is not valid JSON: {e}")))?;
    let Value::Object(fields) = document else {
        return Err(RecordError::Malformed(format!(
            "the {what} is not a JSON object"
        )));
    };
    match fields.get("schema_version") {
        Some(Value::Number(n)) if n.as_u64() == Some(RECORD_SCHEMA_VERSION) => {}
        other => {
            let found = render(other);
            return Err(RecordError::Unsupported(format!(
                "the {what}'s schema_version is {found}; \
                 this profile reads version {RECORD_SCHEMA_VERSION}"
            )));
        }
    }
    let layers = match fields.get("layers") {
        Some(Value::Array(items)) => {
            let mut layers = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s)
                        if s.strip_prefix("sha256:")
                            .is_some_and(|h| is_lower_hex(h, 64)) =>
                    {
                        layers.push(s.clone())
                    }
                    other => {
                        return Err(RecordError::Malformed(format!(
                            "the {what} lists a layer that is not a sha256 digest: {}",
                            render(Some(other))
                        )))
                    }
                }
            }
            layers
        }
        other => {
            return Err(RecordError::Malformed(format!(
                "the {what}'s layers must be an array, got {}",
                render(other)
            )))
        }
    };
    // An empty expectation matches an empty rebuild, which is a comparison
    // that cannot fail. Refused rather than allowed to pass vacuously.
    if layers.is_empty() && expectation {
        return Err(RecordError::Malformed(format!(
            "the {what} lists no layers, so there is nothing a rebuild could be shown to match"
        )));
    }
    Ok(Record { fields, layers })
}

fn compare_inputs(published: &Record, rebuilt: &Record, findings: &mut Vec<Finding>) -> Check {
    let mut drift = Vec::new();
    for field in INPUT_FIELDS {
        let (expected, observed) = (published.fields.get(field), rebuilt.fields.get(field));
        if expected != observed {
            drift.push(field);
            findings.push(Finding {
                check: "rebuild-inputs",
                subject: field.into(),
                state: CheckState::Fail,
                detail: format!("the rebuild used a different {field} than the published record"),
                expected: Some(render(expected)),
                observed: Some(render(observed)),
            });
        }
    }
    if drift.is_empty() {
        Check::pass(format!(
            "all {} recorded inputs are identical",
            INPUT_FIELDS.len()
        ))
    } else {
        Check::fail(format!(
            "input drift: the rebuild differs from the published record in {}",
            drift.join(", ")
        ))
    }
}

fn compare_layers(expected: &[String], observed: &[String], findings: &mut Vec<Finding>) -> Check {
    if expected == observed {
        return Check::pass(format!(
            "{} layers identical and in the same order",
            expected.len()
        ));
    }

    let mut sorted_expected = expected.to_vec();
    let mut sorted_observed = observed.to_vec();
    sorted_expected.sort();
    sorted_observed.sort();
    let summary = if sorted_expected == sorted_observed {
        "the same layers in a different order".to_string()
    } else if expected.len() != observed.len() {
        format!(
            "{} layers, but the published record lists {}",
            observed.len(),
            expected.len()
        )
    } else {
        "different layers".to_string()
    };

    for index in 0..expected.len().max(observed.len()) {
        let (e, o) = (expected.get(index), observed.get(index));
        if e != o {
            findings.push(Finding {
                check: "rebuild-layers",
                subject: format!("layer {index}"),
                state: CheckState::Fail,
                detail: "the rebuilt layer at this position differs from the published record"
                    .into(),
                expected: Some(e.cloned().unwrap_or_else(|| "(none)".into())),
                observed: Some(o.cloned().unwrap_or_else(|| "(none)".into())),
            });
        }
    }
    Check::fail(format!("the rebuild produced {summary}"))
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn render(value: Option<&Value>) -> String {
    match value {
        None => "(absent)".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

#[cfg(test)]
mod tests;
