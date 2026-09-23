# The output contract

Everything in this document is a contract. A pipeline branches on these values,
so removing a field, renaming one, or changing what an existing one means is a
breaking change and moves the record's `schemaVersion`. Adding a field is not:
a consumer that does not read it is unaffected, and requiring a version bump
for every addition would make the version say nothing about compatibility.

## The verdict

`verify` produces exactly one verdict.

Text output defaults to a compact, append-only explanatory transcript followed
by the verdict, its claim, scope, and limitations. `--verbose` (or `-v`) retains
detailed progress and the completed evidence report, including successful
measurements, certificate subjects, full node identities, and matching digests.
No new flag is needed:

```console
scitt-verifier verify --statement statement.cose --scitt-keys keys.cbor --policy policy.json
scitt-verifier verify --statement statement.cose --scitt-keys keys.cbor --policy policy.json --verbose
scitt-verifier verify --statement statement.cose --scitt-keys keys.cbor --policy policy.json --format json
```

The compact transcript numbers the stages actually requested: inputs, statement
verification (including receipt-key acquisition when online), optional artifact
binding, relying-party policy, and optional resource evidence collection and
appraisal. Resource mode does not add an artifact stage; the omitted binding is
disclosed once in the limitations. Saved evidence is labelled as loading a
bundle, never as an authenticated live connection. Missing prerequisites leave
later stages visibly `NOT RUN`.

Progress is emitted at the execution boundary of each stage; it is not
reconstructed from the final result. Stage order and display numbering are
presentation details, not an acceptance contract. The verdict, checks, and
exit code continue to come only from the completed assessment.
Transcript values are bounded and terminal control characters are escaped so
an issuer, path, or remote diagnostic cannot forge another displayed line.
The completed `--verbose` report applies the same escaping and bounding to
every value it did not originate itself, at a larger limit because that report
exists to be read in full.
Individual receipt outcomes and policy assertion results are emitted during
their respective stages; the later report remains a completed evidence view,
not the source from which the transcript is reconstructed.
The compact final block does not repeat the completed check list. It retains
diagnostics (including output-write errors), trust limitations, and omitted
checks. Verbose progress also has an assessment-summary stage. Neither view
participates in deriving the verdict. Diagnostics retain their severity; a
failure must not read like a notice. Where one cause blocks several adapter
checks, its reason is given once and the remaining checks refer to that check.

Compact rendering explains work once, summarizes each subject, and expands
exceptions. The MST checklist is printed **before** node appraisal. Each row is
emitted only when that node completes, with separate service binding, SNP/UVM,
and policy-match states. This is not a sequence of fleet-wide crypto passes.
Node labels use a visibly shortened unique prefix plus a row number; the row
number disambiguates identical IDs or prefixes too long to display safely.
Row numbers are display references, not evidence of distinct authenticated nodes.
Successes omit measurements and matching expected/observed values. Failures,
cannot-evaluate findings, and other nonpassing states retain their details and
available expected/observed values. Unknown adapter checks remain visible.
After MST node appraisal, its two known excluded `cannot-evaluate` checks
(report freshness and serving-connection binding) appear once as concise human
sentences under the final `Limitations`, rather than again beneath the node
table. Failures, prerequisite errors, and unknown checks are not filtered this
way. Verbose output and JSON retain the full original findings.

An authenticated-target success is emitted only after a pinned HTTPS request
succeeds, not after constructing a TLS client. Collection/save completion is
shown only after the corresponding operation succeeds. A resource pass covers
the assessed snapshot, not full service membership. Existing TCB, coverage,
report-freshness, and serving-connection-binding limitations are unchanged.
Signature text distinguishes internal consistency with an embedded root from
anchoring to supplied trust roots. Receipt-issuer acceptance does not establish
independent publisher authorization.

Human timestamps are labelled UTC and include both Unix seconds and an RFC 3339
instant. JSON keeps the original numeric values. Identity labels distinguish
the statement issuer and subject, signing-certificate subject, receipt issuer
and key ID, acquisition ledger, and appraised ledger node.

Detailed receipt, acquisition-ledger, and adapter-node findings are grouped under
their subject. Compact output uses short receipt results and node rows instead.
The final verdict is separated by a blank line; verbose output additionally
labels its completed assessment `Verdict`.

When stdout is an interactive terminal, state and verdict tokens use restrained
ANSI color. Redirected output, `TERM=dumb`, `NO_COLOR`, and JSON output remain
plain text/data with no escape sequences.

`--format json` emits no transcript on stdout. Stdout remains the final JSON
record only, preserving its equivalence with `--result`.

| Verdict | Exit | What it claims |
|---|---|---|
| `artifact-transparent` | 0 | The artifact you supplied is the one that was registered, the receipt proves inclusion, and your policy is satisfied. |
| `statement-transparent` | 0 | The statement is transparent and your policy is satisfied — but **no artifact was checked**. |
| `resource-transparent` | 0 | The statement is transparent, and the appraised ledger nodes enforce the execution policy it embeds. Always scoped to the nodes assessed. |
| `untrusted` | 1 | The statement's own signature or the artifact binding did not hold. Do not deploy. |
| `policy-failed` | 2 | Everything is cryptographically sound; your own rules rejected it. |
| `resource-failed` | 2 | The statement is sound, but an adapter's requirement about the ledger was not met. |
| `cannot-evaluate` | 3 | The tool could not answer the question. **This is not a pass.** |
| `usage-error` | 4 | The invocation or its inputs were wrong. Nothing was established. |

### Why exit 0 has distinct verdicts

These are different claims; select the one your task requires:

- `statement-transparent` — *some* statement was registered on a transparency
  service and satisfies your policy.
- `artifact-transparent` — *the bytes you are about to deploy* were registered.
- `resource-transparent` — the selected adapter's resource requirements held
  within the reported evidence scope.

A tool that prints one word for both lets a run that never opened the artifact
look identical to one that compared it byte for byte. If you are gating a
file deployment, **gate on `artifact-transparent`**, not on exit 0. A resource
appraisal instead requires `resource-transparent` and its scope; neither is
a substitute for the other.

Exit 0 is shared deliberately: a team adopting the gate incrementally should not
have their build break the day they add `--artifact`. The distinction lives in
the verdict, where it can be checked explicitly.

## Check states

Every check reports one of four states. They are not
interchangeable, and the human output spells them out rather than using symbols.

| State | Meaning |
|---|---|
| `pass` | Asked, and the answer was yes. |
| `fail` | Asked, and the answer was no. |
| `not-checked` | Nobody asked. Usually because a flag was not supplied. |
| `cannot-evaluate` | Asked, and could not find out. |

`receiptInclusion` never reports `fail`. A receipt that did not verify is not
an answer of "no" — receipts are unauthenticated in transit, so a broken one
may never have come from a transparency service at all. Transparency is either
established by a verified receipt (`pass`) or left open (`cannot-evaluate`).

`not-checked` and `cannot-evaluate` are the pair most worth keeping apart.
The first may be intentional (for example, no artifact in a statement-only
run); the second says a requested check could not be completed.

### Adapter checks

Alongside the four core checks, `appraisal.checks.adapter` carries an ordered
list of checks contributed by a selected adapter. The four core checks are
fixed fields because every run has an answer for each of them; the adapter list
is open, because only the selected adapter knows what it establishes.

```json
"checks": {
  "statementSignature": "pass",
  "receiptInclusion": "pass",
  "artifactBinding": "not-checked",
  "policy": "pass",
  "adapter": []
}
```

The key is **always present**, and empty when no adapter ran, so a consumer
never has to tell a missing key from an empty list. Each entry carries a stable
machine `name`, a human `label`, one of the four `state` values above, and a
`detail` explaining what was established or why it could not be.

An adapter reports checks; it does not report a verdict. Adapter results may
narrow the verdict but never widen it, so an adapter cannot turn a failed core
check, or evidence it could not gather, into a pass.

Per-subject adapter results are also retained under
`appraisal.adapterFindings`. Each entry identifies the adapter check and
subject, carries the same four-state vocabulary, and may include structured
`expected` and `observed` values. For example, an MST policy-commitment mismatch
records the statement-derived digest and authenticated `HOST_DATA` separately;
consumers do not need to parse either value out of an English diagnostic.

The array is always present and empty when no adapter produced subject-level
findings. Aggregate adapter checks remain the acceptance surface. Findings
explain those checks and drive the human transcript; their presence or display
order never grants a pass.

Internally, the shared assessment derives success from an explicit, non-empty
set of required check names, rather than trusting a separate pass boolean.
Each required name must occur exactly once and have state `pass`; missing or
duplicate results cannot pass. Checks outside that set still disclose limits
of the scoped claim, such as MST freshness and connection binding.

#### Where the evidence came from

`--binding-mode live-evidence` collects the evidence during the run;
`saved-evidence` replays a bundle captured earlier. The checks are identical.
What differs is the anchor: a saved bundle supplies the service certificate
that identity binding is checked against. Its unsigned manifest must match
`adapters.azure-confidential-ledger.target.host`, but a forged, self-consistent bundle can
substitute both evidence and anchor. A live run takes that certificate from the
public identity service and pins the connection to it.

Saving a live bundle does not preserve independently verifiable acquisition
provenance: offline replay trusts the supplied bundle's origin. File digests
detect changes relative to its unsigned manifest, not substitution of both.

The scope sentence and acquisition stage distinguish the two. The detailed
report/record names nodes and records live evidence as *observed at* a time this
run knows, or saved evidence as *recorded at* a collector-asserted time. Compact
scope states the provenance without repeating full node IDs. Freshness and
connection binding are `cannot-evaluate` either way.

A ledger that could not be reached yields `cannot-evaluate`, not a failure: a
service that did not answer is not a service that answered badly.

Receipt-key acquisition (`--online`) is distinct from resource evidence
acquisition (`live-evidence`), though the latter currently requires the former.
See [adapters](adapters.md) for policy, invocation, and the checks that determine
a scoped resource success.

## Diagnostics

Every problem is a structured diagnostic with a stable `code`, a `category`, a
`severity`, a human `message`, and an `action`.

`primaryDiagnostic` names the one that decided the verdict. Without it, a caller
has to scan several arrays and will usually report the first thing it finds
rather than the thing that stopped the deployment.

Categories:

| Category | Meaning |
|---|---|
| `input` | We could not use what you gave us. |
| `trust` | The trust material is missing, stale, or scoped elsewhere. |
| `crypto` | A signature or inclusion proof did not hold. |
| `binding` | The statement does not describe the artifact. |
| `policy` | Your own rules were not met. |
| `signer-identity` | Something about the signer we did not establish. |
| `unsupported` | A real feature of the input this build does not implement. |
| `internal` | The tool itself failed. |

`unsupported` is kept apart from `crypto` on purpose. "I do not implement this"
is never evidence of compromise, and must never be reported as though it were.

## `appraisal.notChecked`

Reported on every run, **including successes**. A green result that quietly
skipped the artifact binding is more dangerous than a red one, because nobody
goes looking for the caveat.

Each entry has a stable `code`, a `category`, a `message`, and an `impact`. The
codes exist so a fleet-wide report can answer "how many deployments went out
without artifact binding" — a question no amount of grepping English sentences
answers reliably.

## Trust provenance

`trust` is a first-class field, not prose:

```json
"trust": {
  "mode": "unsigned-scitt-keys",
  "limitations": [
    "the key set carries no publisher signature",
    "no revocation status is available offline",
    "no anti-rollback protection: an older key set will verify happily"
  ]
}
```

"The receipt signature is valid" means nothing without "valid under whose key,
and who vouched for it". There are two modes:

| `mode` | Set by | Means |
|---|---|---|
| `unsigned-scitt-keys` | `--scitt-keys` | a raw COSE key set, with no publisher signature |
| `acquired-key-set` | `--online` | fetched from the service, over a connection authenticated to its certificate |
| `no-key-set` | `--online` | nothing was obtained: selection refused, or every fetch failed |

`no-key-set` exists so an empty-handed run cannot read as a successful one.
A run that fetched nothing has verified no receipt signature, and the mode says
so rather than describing work that did not happen.

Neither of the first two is a chain of custody. `acquired-key-set` carries the
stronger statement of the two — somebody specific served these bytes — and its
`limitations` still say plainly that nothing here establishes revocation,
freshness, or anything about the statement's signer. See
[trust-material.md](trust-material.md).

## `acquisition`

Present only when `--online` was used. A record from an offline run has **no
`acquisition` key at all**, rather than an empty one: a consumer keying on the
field's presence gets the right answer without reading its contents.

```json
"acquisition": {
  "selected": ["contoso.confidential-ledger.azure.com"],
  "notAttempted": null,
  "ledgers": [
    {
      "issuer": "contoso.confidential-ledger.azure.com",
      "acquired": true,
      "provider": "azure-confidential-ledger",
      "identityUrl": "https://identity.confidential-ledger.core.azure.com/ledgerIdentity/contoso",
      "keysetUrl": "https://contoso.confidential-ledger.azure.com/.well-known/scitt-keys",
      "serviceCertSha256": "d988fadd…",
      "keysetSha256": "aae8e4d3…",
      "serviceKeyKid": "7bbd7fa5…",
      "acquiredAt": 1789675618,
      "ambiguousKids": [],
      "failure": null
    }
  ]
}
```

- `selected` is what the policy authorised, after `--ledger` narrowing. Empty
  when nothing was selected, with `notAttempted` explaining why — which
  distinguishes "no service was allowlisted" from "no receipt named one that
  was".
- `ledgers` lists **every** selected service, in issuer order, whether or not
  it answered. A block listing only successes would let a partial outage read
  as a complete picture.
- `failure` carries a stable `code`, the detail, and whether the fault was one
  of configuration. Configuration faults are knowable before any packet is
  sent, so they are usage errors rather than evidence about the service.
- `acquiredAt` is the real clock, never the `--now` override, because `--now`
  answers "when should this statement be judged" and writing it here would
  record a fetch as having happened at a time it did not. A run with `--now`
  set therefore has a `timestamp` and an `acquiredAt` that legitimately
  disagree.
- `ambiguousKids` names identifiers that more than one key in the served set
  claims. It is a warning (`AcquisitionAmbiguousKid`) and not a refusal: the
  material is usable and the service is reachable, so refusing would turn a
  labelling mistake into an outage. It is said out loud because a `kid`
  resolves to the first matching key, so for those identifiers the order of
  entries in the served set — not any policy — decides which key a receipt is
  checked against. Empty in the normal case.

The digests are the auditable part: `serviceCertSha256` says which certificate
the connection was authenticated to, and `keysetSha256` says exactly which
bytes were used. Two runs can be compared on those without trusting either
run's conclusion.

Two code vocabularies meet here, and they are not the same list. Inside the
`acquisition` block, `failure.code` is the acquire layer's own camelCase code
(`transport`, `tlsAuthentication`, `serviceKeyMismatch`, …). The top-level
`diagnostics` list restates each of those in the verifier's PascalCase
convention with an `Acquisition` prefix — `AcquisitionTransport`,
`AcquisitionServiceKeyMismatch` — so that one list does not carry two naming
styles.

`AcquisitionNotConfigured` has no counterpart in the block, because it is
raised by selection rather than by a fetch: nothing was contacted, so there is
no per-service outcome to record. It appears with `selected` empty and
`notAttempted` giving the reason.

`AcquisitionUnsupportedPlatform` is the one fetch-layer code raised before any
connection: the TLS implementation in this build needs an x86-64 CPU with AES,
PCLMULQDQ, BMI1, ADX, AVX and AVX2 (Intel Broadwell / AMD Excavator, 2014 or
later), and aborts the process rather than returning an error if they are
missing. The host is probed first so that a run on an older or
feature-masked agent still writes a record and still exits with a code a gate
can read. Verification itself has no such requirement — only `--online` does.

## The facts document carries `acquisition` too

`--facts` is the record with `relyingPartyPolicy` and `appraisal` removed, so
it keeps `acquisition` verbatim. Provenance is an observation — which endpoint
was asked, what it served, when — rather than a conclusion, and a reader asking
"whose key was this checked against" would otherwise see `trust` reporting an
acquired key set with nothing at all saying where it came from.

## A record is written on every path

If `--result` is supplied, a record is written **whether or not verification
completed**. A run that failed to parse the policy still produces a document
with `appraisal.exitCode`, `appraisal.primaryDiagnostic`, every check marked
`not-checked`, and every observation block marked `status: not-evaluated`.

Both shipped CI examples publish the record with `always()`. If an early
failure wrote no file, the archive would be empty exactly when someone needed
it — during an incident.

`every_failure_path_still_writes_a_record` in `tests/acceptance.rs` pins this.

### If the record cannot be written

A pass whose audit trail vanished is not a pass a gate should act on. If
`--result` or `--facts` is supplied and the write fails, a passing run is
downgraded to `usage-error` (exit 4). Both the printed document and any file
that *was* written are built from the downgraded assessment, so their `verdict`
and `exitCode` agree with the process. A run that was already failing keeps its
own, more important, verdict.

That guarantee is why `--facts` is written before `--result`. The facts
projection carries no `appraisal`, so a downgrade decided after it lands cannot
make what was written wrong. The record does carry one, so it is written last,
once every other write outcome is known. In the other order a successful
`--result` followed by a failed `--facts` would leave `"pass": true` and
`"exitCode": 0` on disk for a run that exits 4 — and the file is what gets kept
after the terminal output is gone.

The most common cause is an output path whose parent directory does not exist.

The same rule applies to stdout. A pass whose final text or JSON document could
not be written — or could not be flushed, which a buffered writer defers until
after every byte was accepted — is downgraded the same way, with the cause
reported on stderr. A failure to emit the progress transcript is treated
identically: a gate reading an incomplete record must not be told it is whole.

## Every failure names its cause

A non-pass verdict always has a `primaryDiagnostic`. This is structural, not
incidental: if no diagnostic was generated for a failing run, the tool emits
`UnexplainedFailure` and asks you to file a bug. A red gate with no stated
reason is worse than no gate, because the operator has nowhere to start.

## `--format json` is one protocol

When `--format json` is selected, stdout is a JSON document on every path,
including failures. A consumer must never have to parse two protocols depending
on which way the run failed.

**The one exception:** if argument parsing itself fails, there is no `--format`
to honour, because the flag that would have selected it is the thing that did
not parse. That case prints usage to stderr and exits 4.

### `--format json` and `--result` are the same document

There are two axes here, not three flags:

| | stdout | file |
|---|---|---|
| verification record | `--format json` | `--result <FILE>` |
| observations only | — | `--facts <FILE>` |

`verify --format json` and `verify --result <FILE>` emit **byte-for-byte the
same document**; both are `record::build`. The flag chooses the sink, not the
content, and supplying both is the normal case: gate on stdout, archive the
file.

`--facts` is a different *document*, not a different sink. It is the
observations with the verdict and the policy decision removed, for a system
that makes its own decision. See "The facts projection" below.

## Reading the payload

The payload travels in the inspect document, so extracting it is a `jq`
expression rather than a separate mode:

```bash
scitt-verifier inspect --statement s.cose --format json --verbose | jq -r .payload.json
```

A text payload appears under `.payload.text`, a JSON one is parsed into
`.payload.json`, and a binary one is hex under `.payload.hex`.

`--verbose` matters here: without it the payload is summarised, and the object
carries `"elided": true` so a consumer can tell a summary from the real thing.

`.payload.text` and `.payload.hex` are byte-exact. `.payload.json` is **not** —
it is parsed and re-serialised, so key order and whitespace are the
serialiser's, not the signer's. Anything hashing the payload must use
`.payload.hex`.

## `--decode`: an encoded claim, and its digest

Producers routinely carry a whole document — a policy, an SBOM, a manifest —
base64-encoded inside a single JSON claim, alongside a sibling claim holding
its digest. `--decode` names one such claim and reports the SHA-256 of the
**exact decoded bytes**, so that digest can be compared against whatever the
producer published, or against the artifact the document is supposed to
describe.

```bash
scitt-verifier inspect --statement s.cose \
  --decode "['security-policy-base64']" \
  --decode-out policy.rego
```

The path is the same notation `inspect` prints beside each claim and the same
one `payloadJson` policy rules take, so a path can be pasted between them
without translation. `--decode-as` selects the alphabet (`base64`, the default,
or `base64url`); `--decode-out` writes the decoded bytes to a file, byte-exact
and unescaped.

Under `--format json` the result is a root-level `decoded` object, a sibling of
`payload` rather than a member of it, because it is a derived view and not part
of what was signed:

```json
{
  "decoded": {
    "path": "['security-policy-base64']",
    "encoding": "base64",
    "bytes": 18808,
    "sha256": "0dc96f…",
    "utf8": true,
    "preview": "package policy\n\nimport future.keywords.every…",
    "previewTruncated": true,
    "authenticated": false
  }
}
```

`sha256` is over the decoded bytes, never over the base64 text and never over
the preview. The preview is bounded, and control characters in it are escaped
so a decoded document cannot repaint the report printed above it; `utf8: false`
means the bytes are shown as hex rather than lossily converted. Use
`--decode-out` when the bytes themselves matter.

`authenticated` is always `false`. It restates the document's own
`verified: false`, because a digest is the field most likely to be lifted out
of the report on its own — and decoding a claim proves nothing about whether
the statement carrying it was signed by anyone you trust. To gate on this, run
`verify` first and treat its exit code as the decision.

Nothing is inferred: the alphabet is never guessed from the value, whitespace
is refused rather than stripped, padding that is present but inconsistent is
refused rather than completed, and a value whose final character sets bits
beyond the bytes it decodes to is refused as non-canonical. None of these are
claims that a tolerant decoder would return *different* bytes — usually it
returns the same ones. The point is narrower: a digest published against a
claim attests to one spelling of it, and each tolerance widens the set of
inputs that would satisfy that digest.

Decoding a single claim is capped at 32 MiB of encoded input, reported against
the claim rather than left to an allocator. `--decode-out` refuses to write
over the file named by `--statement`: the statement is read before the write,
so overwriting it would succeed and leave you with no evidence and a report
saying everything was fine.

The payload is parsed by the same strict parser policy evaluation uses, so a
document with duplicate object keys is refused as ambiguous rather than having
its last value silently chosen.

## Where the failure boundaries sit

Four kinds of failure that must not look alike:

| Situation | Verdict | Exit | Reasoning |
|---|---|---|---|
| Missing or unreadable file, malformed policy | `usage-error` | 4 | The operator's problem. Nothing was established. |
| Malformed statement or key set | `cannot-evaluate` | 3 | A truncated download is not evidence of compromise. Never a pass. |
| Unknown kid, stale keys | `cannot-evaluate` | 3 | An operational chore, not an incident. |
| Unsupported algorithm or VDS | `cannot-evaluate` | 3 | A limitation of the tool, not a finding about the artifact. |
| No receipt verified | `cannot-evaluate` | 3 | Registration was not proven. An unproven claim is not a disproven one. |
| Invalid statement signature, binding mismatch | `untrusted` | 1 | An incident. |

A broken receipt is **not** exit 1. Receipts arrive in the unprotected header,
which no signature covers, so anyone who handles the file can append one
without holding a key. If a broken receipt could flip the verdict, every
mirror, registry, and CI cache would hold a veto over the gate, and the
operator would be told to stop shipping an artifact whose own signature is
sound. One verified receipt establishes transparency and noise appended beside
it cannot retract it; see RFC 9943 §7.1. Broken receipts are reported as
warnings, and a statement with none that verify is exit 3.

A malformed statement is **exit 3, not 1**. Earlier releases returned 1 on the
reasoning that a gate should stop on garbage input — but exit 1 means "this
artifact is untrusted", and a file that was truncated in transit is not evidence
that anyone tampered with anything. It is still never a pass.

There is deliberately no separate exit code for internal filesystem failures.
Five codes is already at the limit of what people remember, and a sixth buys
nothing that a diagnostic `code` does not.

## `inspect`

`inspect` describes a statement and makes no trust decision, so it never returns
1 or 2. It distinguishes two failures that are genuinely different:

| Situation | Exit |
|---|---|
| Described the statement | 0 |
| Could read the file, could not decode it | 3 |
| Described the statement, but `--decode` found no such claim or could not decode it | 3 |
| Could not read the file | 4 |
| `--decode-as` or `--decode-out` given without `--decode`, or an unparseable path | 4 |

A failed `--decode` still prints the full report on stdout and explains itself
on stderr. The reader asked to see the statement, and the likeliest cause is a
misspelled path or a producer who stopped emitting the field — both of which
are easier to diagnose with the claim listing in front of you.

## Determinism

The record is deterministic **for fixed inputs and a fixed `--now`**. That is
the whole guarantee, and it is narrower than it sounds:

- Without `--now`, `evaluatedAt` varies per run.
- `inputs` records the paths you passed, so two agents with different workspace
  layouts produce different documents from identical bytes — including the path
  separator, which differs between Windows and Linux agents. That block is
  marked `"canonical": false` for exactly this reason.

If you are diffing records across runs, pass `--now` and skip the `inputs`
block.

## Schema versioning

`schemaVersion` is currently `scitt-verifier/result/v0`, and the
observations-only projection written by `--facts` is
`scitt-verifier/facts/v0`.

`v0` is deliberate: this shape is still moving, and it says so. It freezes at
`v1` when the repository goes public.

The document is named *result* rather than *evidence* because in RATS
(RFC 9334 §8.1) "Evidence" is the *input* being appraised, while this document
is the tool's *output*.

The shape follows RFC 9943 §3: `signedStatement`, `receipts`, and
`artifactBinding` are top-level observation sections, and everything that is
this tool's judgement — `verdict`, `exitCode`, `checks`, `primaryDiagnostic`,
`diagnostics`, `notChecked` — sits under `appraisal`. The separation is the
point: a consumer that disagrees with our judgement can read the observations
and decide for itself.

The policy is `relyingPartyPolicy`, named for *whose* rules they are, because
RFC 9943 §3 reserves "Registration Policy" for the transparency service's own
admission rules. It is populated from the `--policy` document.

`relyingPartyPolicy.satisfied` answers whether the whole document was met, so
it requires both the statement assertions and every configured adapter check to
have passed; a check that did not run counts against it. The narrower fact —
whether the assertions alone held — is kept as `assertionsSatisfied`. Both are
`null` when no policy was supplied. The verdict and exit code are unaffected:
this changes what the record says, not what the tool decided. The change of
meaning would ordinarily move `schemaVersion`, but the schema is `v0` and still
moving by design.

Every observation block carries a `provenance` object and a `status`.

## Sections

| Section | What it is | Signed by |
|---|---|---|
| `inputs` | Local paths. Non-canonical | — |
| `trust` | How the trust material arrived, and its limits | — |
| `signedStatement` | Envelope, CWT claims, payload facts | the Issuer |
| `receipts` | Registration facts, one entry per receipt | the transparency service (presence: **nobody**) |
| `artifactBinding` | Which file the operator claims this describes | **nobody** |
| `relyingPartyPolicy` | The rules that were applied — the `--policy` document | — |
| `appraisal` | The verdict and the reasoning | — |

Two names differ between input and output on purpose. The `--policy` flag stays
short because it is mandatory and typed on every run, and inside a verifier
there is no other policy it could mean. The output field is
`relyingPartyPolicy` because a record outlives its command line: read six months
later by an auditor holding RFC 9943, bare `policy` would read as the
transparency service's Registration Policy, which is a different document
enforced by a different party at a different time.

### `signedStatement.certificateChain`

What path validation established, and the auditable identity of the anchor it
reached. Present in the facts document too, which carries no gaps and no policy
messages — so without this block a consumer reading `--facts` would have to
infer chain success from the *absence* of a warning.

| `outcome` | Meaning |
|---|---|
| `valid` | A path from the leaf to the anchor verified |
| `invalid` | A path was attempted and did not hold |
| `insufficient` | The material needed was not present — supply it and re-run |
| `unsupported` | The material was present and this build cannot check it |

`status: not-evaluated` means chain validation did not run at all.

On `valid`, two fields carry the weight. `rootSha256` names the anchor the path
actually reached, which is the value `requireChainToRootSha256` pins.
`anchoredExternally` says whether that anchor came from `--trusted-roots` or
from inside the statement itself: a chain anchored in its own embedded root is
internally consistent and vouched for by nobody. `pathNotBefore` and
`pathNotAfter` bound the window during which every certificate on the *selected*
path was simultaneously live — the path including an externally supplied anchor,
not the `x5chain` as transported.

### `signedStatement.certificatesValidAtRegistration`

Whether that window covered every registration time the receipts attest. The
times come from the `iat` of each receipt that verified completely, never from
the statement's own CWT: a signer holding an expired key controls the latter and
can set it to any convenient instant. It witnesses registration rather than the
signing moment, which is the closest independently attested time that exists.

`null` when the chain did not validate, or when no fully verified receipt
carried a time. As everywhere else in this document, `null` is not a failure.

### `artifactBinding.bound`

Three-valued, and the third value matters:

| `bound` | `status` | Meaning |
|---|---|---|
| `true` | `evaluated` | The artifact is the one the statement describes |
| `false` | `evaluated` | The artifact is **not** the one the statement describes |
| `null` | `not-requested` | Nobody asked — no `--artifact` was supplied |
| `null` | `not-evaluated` | A binding was requested and could not be made |

`null` never means "failed". Read `status`, not the truthiness of `bound`, to
tell "we did not ask" from "we asked and could not find out" — the artifact
being unreadable, or the statement's payload being detached, which
`payload-bytes` has nothing to compare against. Only `false` accuses anyone,
and a requested binding that could not be made yields `cannot-evaluate` (exit
3) rather than a pass.

### Provenance

Every observation block carries `provenance.coveredBy`, one of:

| Value | Meaning |
|---|---|
| `statement-signer` | Covered by the Issuer's signature over the protected header and payload |
| `transparency-service` | Covered by a log's signature over the verifiable data structure root — **a different signer from the Issuer** |
| `operator` | Asserted by whoever ran the tool. No signature |
| `unauthenticated` | Present in a COSE unprotected header. Covered by no signature |

The `receipts` block is the one to read carefully. Its *presence* is
`unauthenticated` — RFC 9943 §3 places receipts in the Signed Statement's
unprotected header, so anyone can add or strip one without breaking the
Issuer's signature. Each entry's *contents* are `transparency-service`. Those
are two different trust statements.

`provenance.signatureVerified` is `false` only when a signature was checked and
failed. Where no signature covers the block it is `null`, so "nobody signed
this" can never be misread as "the signature was bad".

### `status` versus `null`

A `null` field means the input did not carry that value. `status:
not-evaluated` means the run never got that far. Collapsing the two would make
"the statement declares no SVN" indistinguishable from "we failed before
parsing the statement" — and in a Rego policy both would be `undefined`, which
reads as a failed check.

## `--facts`: observations without a verdict

`--facts` writes the same observation blocks with `relyingPartyPolicy` and
`appraisal` removed, for systems that make their own decision — Ratify,
Kyverno, OPA, or a bespoke gate.

There is deliberately **no way to obtain this document without running a full
verification**. Facts about a statement nobody authenticated are worth nothing,
and a keyless extraction path is how unauthenticated claims end up in an
admission policy. `--facts` requires the same `--scitt-keys` and `--policy` as
any other run.

The verdict is *omitted* rather than emptied. A consumer that wants our
decision should read the full record; handing a verdict to a system that
intends to decide for itself invites it to forward ours as its own.
