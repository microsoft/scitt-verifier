# Changelog

## Unreleased

### The ledger adapter is now named `azure-confidential-ledger` (breaking)

The adapter appraises a deployed Azure Confidential Ledger. It was named after
MST, which is one service built on that ledger and not the thing being
appraised — the same conflation that lets a statement notarised by one ledger
be mistaken for evidence about another. The policy key is now
`adapters.azure-confidential-ledger`, the CLI value `--adapter
azure-confidential-ledger`, and the build feature
`adapter-azure-confidential-ledger`. There is no alias: an existing policy is
rejected by `deny_unknown_fields` rather than silently reinterpreted, and must
be updated.

### Node coverage counts attested keys, not names

Every aggregate rule asks whether all N nodes agreed, and `node_id` is a label
the collector chose. A saved bundle is unsigned, so one agreeing node copied
under three names satisfied a requirement for three nodes. Coverage now counts
distinct attested keys — the SHA-256 of the node's own public key that CCF
places in `REPORT_DATA`, which the hardware signature authenticates — and fails
when fewer distinct keys were attested than nodes were presented. Live
acquisition was never affected; this closes the saved-evidence path.

### Saved bundles are read within fixed bounds

A bundle supplied on the command line is untrusted input that was read without
limit, and its paths were checked lexically, so a component named entirely
normally could still leave the directory through a link. Manifest, per-file and
total sizes and the node count are now capped, and every path is canonicalised
and required to remain inside the bundle before its bytes are read.

### `relyingPartyPolicy.satisfied` accounts for adapter checks

The field reported only whether the statement assertions held, so it could read
`true` on a run where a required adapter check failed or could not run. It now
requires both, and the narrower fact is retained as `assertionsSatisfied`. The
verdict and exit code are unchanged — they were already correct — but the
record no longer disagrees with them. `schemaVersion` stays `v0`, which is
still moving by design.

### A TCB floor is now required to cover the node it appraises

The attestation library compares a minimum TCB only against a node of the same
CPU generation and skips every other entry, so a floor naming only `milan`
appraised a Genoa node against nothing and reported a pass. The adapter now
refuses a node whose generation the configured floor does not name, once the
report has authenticated and its generation is a fact rather than a claim.
This is reported as cannot-evaluate rather than a node failure: nothing about
the node is at fault, the policy simply configured no floor applicable to it.

### Records can no longer be written over saved evidence

`--result` or `--facts` naming a path inside the `--save-evidence` or
`--save-trust` directory overwrote a bundle file — typically `snapshot.json` —
with a verification record, and because the record write itself succeeded the
run still exited 0 having made the bundle unreplayable. The combination is now
refused while the command line is parsed, before any evidence is collected.

### Output failures are no longer silent

Errors from the progress transcript and from the final text or JSON write were
discarded, so a truncated or entirely missing result could accompany exit 0.
Both are now folded into the verdict: a pass whose output could not be
delivered is demoted, while a run that had already failed keeps its own verdict.
The final write is flushed as part of the write, since a buffered writer can
accept every byte and then fail to hand them on.

### The verbose report escapes what the transcript escapes

Node ids, policy ids and the diagnostics quoting them reached the completed
`--verbose` report as raw bytes, so a hostile value could emit newlines and
terminal control sequences — enough to print a line that reads like a verdict,
or to scroll the real one out of view. Every value in that report which did not
originate as a literal is now escaped and bounded, as the compact transcript
already did.

### Text verification reports progress as checks run

Human-readable `verify` output now begins with an append-only transcript emitted
at real input, statement, online key acquisition, artifact-binding, policy, and
adapter boundaries. The transcript is driven by typed events and does not
participate in verdict selection. JSON stdout remains the final verification
record only and stays equivalent to `--result`.
Untrusted transcript values are bounded and terminal control characters are
escaped before display, including an adapter-supplied check name.
Diagnostic severity survives into the transcript: one that decided the verdict
is reported as a failure rather than sitting among the trust limitations.
The adapter stage reports its aggregate checks, so an appraisal that stopped
before reaching any node still names the reason at the point it happened. A
reason shared by several checks is stated once and afterwards referred to by
the check that carries it.
Receipt outcomes and policy assertion results now appear at their real
statement and policy execution boundaries.
Statement identity facts are reported when verification completes, followed by
a typed assessment summary of diagnostics, omitted checks, and trust limits.
Default text output now stops after the concise verdict block; `--verbose`
retains the completed evidence report.
Human output now uses explicit identity labels, UTC timestamp renderings,
grouped receipt/ledger/node findings, a separated verdict block, and restrained
TTY-only color that respects `NO_COLOR` and never affects JSON or redirection.

MST adapter node outcomes now survive as generic structured
`appraisal.adapterFindings`, including separate expected and observed policy
commitments where the comparison ran. The same findings drive node-level
progress without making transcript order part of the acceptance contract.
This is an added field, so the record's `schemaVersion` does not move;
`docs/output.md` now states which changes do.

### Statement verification and optional adapters have separate boundaries

The README now starts with transparent statements and relying-party policy,
not deployment appraisal. Artifact binding and resource adapters are opt-in;
receipt support remains limited to the CCF VDS profile.

Network acquisition is renamed from `scitt-acquire` to `scitt-network`.
The pure MST appraisal package moves from `crates/scitt-attest` to
`adapters/azure-confidential-ledger`, named `scitt-adapter-azure-confidential-ledger`. There is no generic
attestation crate. CLI dispatch, MST orchestration, and bundle handling live in
`crates/scitt-verifier/src/adapters/`; networking stays in `scitt-network`.

The unpublished adapter policy shape is replaced, not retained as an alias:
`ledger` moves to `adapters.azure-confidential-ledger.target`, `trust` to
`adapters.azure-confidential-ledger.trust`, and `assertions.bindLedgerPolicy` to
`adapters.azure-confidential-ledger.binding`. Statement rules remain in `assertions`.
Unknown adapters/fields are rejected, and `Policy::evaluate` cannot silently
pass requirements that need adapter execution.

The CLI rejects policy/adapter-selector mismatches before acquisition and
requires a passing statement verdict before appraisal. Shared adapter results
derive success from explicit required checks rather than an independent
boolean. TLS evidence collection is in `scitt_network::acl::collect`;
the CLI decodes and joins the responses into the pure adapter's evidence types.
Saved bundles retain their existing trust limitations: their manifests and
service-certificate provenance are not authenticated on offline replay.

The `adapter-azure-confidential-ledger` build feature, `--adapter azure-confidential-ledger`,
`saved-evidence`/`live-evidence` modes, and acquisition behavior are unchanged.
`--online` selects receipt-key acquisition; live resource acquisition is an
additional explicit mode that currently requires it. See
[adapters](docs/adapters.md).

### Evidence can now be collected from the ledger itself

`--binding-mode live-evidence` collects the ledger's attestation evidence
during the run instead of reading a bundle someone recorded earlier. It
requires `--online`, and the ledger it contacts is the one named by
`adapters.azure-confidential-ledger.target.host` in the policy — never a flag, for the same reason the allowlist
is not a flag.

This is a security change, not a convenience. A saved bundle carries
`service.pem`, the certificate identity binding is checked *against*, so the
subject of the appraisal also supplies its own anchor: a self-consistent bundle
produced by an attacker's own ledger satisfies every check in the appraisal and
is wrong only in which service it describes. The previous release could catch
that by comparing the collector's unsigned manifest to the policy target, which
detects the wrong bundle but not a forged one.

A live run takes the service certificate from the public identity service over
the public web PKI, and pins the connection that carries the node reports to
exactly that certificate. Substituting a ledger no longer substitutes the
anchor with it. `bootstrap` in `scitt-network` was separated out of key
acquisition so both uses share one authenticated path and one network deadline.

`--save-evidence <DIR>` writes what a live run collected, in the same form
`--binding-mode saved-evidence` reads, so a verdict can be re-examined offline
later. Saving is part of the run: if the copy cannot be written the run fails
rather than reporting a verdict it did not preserve.

What has not changed: freshness and connection binding remain
`cannot-evaluate`. CCF offers no challenge-response attestation, so a report is
a recording whether this run fetched it or not; the endpoint load-balances, so
the node that served a response cannot be tied to the report it carried. A live
run now says *observed at* a time it knows rather than *recorded at* a time
someone else asserted, which is the only part of the scope that improves.

An unreachable ledger is `cannot-evaluate`, never a failure: a service that did
not answer is not a service that answered badly.

### The evidence must come from the ledger the policy names

The target host was parsed, validated non-empty, and then never compared against
anything. A bundle captured from one service was appraised against a policy
written for another, and the whole report — scope notice included — named the
subject the operator had asked about rather than the one the evidence came
from.

This is easy to get wrong in exactly the case the adapter exists for. A
production transparency service notarises builds for many deployments, so the
service that issued the receipt is usually *not* the service the statement
describes. Pointing the adapter at the notary's own evidence produced a
confident, wrong answer.

The bundle's `ledger` is now compared against `adapters.azure-confidential-ledger.target.host` before any node is
appraised, and a mismatch fails the run. Hostnames are compared case-insensitively
and tolerate a URL, a trailing root dot, or surrounding whitespace; a differing
port is a differing endpoint and is not normalised away. A policy with no
`adapters.azure-confidential-ledger` section no longer runs the adapter at all.

The comparison is against the collector's unsigned manifest, so it catches the
wrong bundle, not a forged one. Pinning the bundle's service certificate to the
one the public identity service publishes for that host is the adversarial
form; `live-evidence`, above, is that form.

### Ledger findings have their own verdicts

Adapter checks report on a service, not on the policy document, and the two
were previously collapsed. A run whose policy assertions all passed but whose
ledger check failed printed `STOP policy-failed` above `Policy decision: pass`,
which reads as a contradiction and invites the reader to distrust the report
rather than the ledger.

There are now two verdicts for adapter outcomes: `resource-transparent`
(exit 0) when the appraised nodes enforce the policy the statement embeds, and
`resource-failed` (exit 2) when a requirement about the ledger was not met.
`resource-failed` keeps `policy-failed`'s exit code, because to a pipeline
"the ledger does not enforce the policy you demanded" and "the signer is not
the one you demanded" call for the same stop — but the headline now names the
check that actually stopped the run.

### The conformance corpus can be regenerated

Every fixture was signed against one person's test ledger. When that ledger was
deleted the receipts stayed valid — they are self-contained — but the service
stopped answering, so `--online`, `scitt-keys fetch`, and every worked example
in the documentation failed against a host that no longer exists. There was no
way to produce replacement bytes, which meant the corpus could not be corrected
either.

`corpus/tools/generate_fixtures.py` now rebuilds the whole corpus: it mints
throwaway keys and certificates, signs, registers each statement on a named
transparency service, recaptures the transparent statement, derives the tampered
and appended variants structurally, and captures the service's key set. It
computes the pinned claim digest and signed length with `pyscitt` and `cbor2`,
independently of the code under test, so the cross-implementation check the
constants exist for survives regeneration.

The fixtures have been regenerated on a long-lived service and the pinned values
updated to match. Two consequences for anyone using the corpus directly:

- The key set is now `mst-test-scitt-keys.cbor`. It is no longer named after a
  hostname, because naming a file after a service is what forced this change to
  touch tests, workflows, the demo, and the documentation at once.
- `stale-scitt-keys.cbor` is now `other-service-scitt-keys.cbor`. It was never
  a rotated key set; it is a different service's keys, and it always tested that
  trust material which does not cover a receipt reports `cannot-evaluate`
  rather than a forgery.

The signing identities in the corpus are throwaway certificates minted for it.
The receipts remain genuine — each statement really was registered — so the
corpus is still usable as a cross-implementation check.

## 0.4.0

### Policy can assert on claims inside the payload

The assertions this tool shipped with all read the COSE envelope. The fields a
release gate actually wants — a build id, a source commit, a package version —
live in the payload, so a gate had to run `verify` and then pick the payload
apart with a second tool. That second step sat outside the decision, outside the
verification record, and outside the exit code the pipeline branches on.

`payloadJson` closes that gap:

```json
"payloadJson": [
  {"path": ["source", "commit"], "text": {"equals": "907a1bd…"}},
  {"path": ["build", "id"], "exists": true}
]
```

One policy now says *registered by this ledger **and** built from this commit*,
and both halves land in the record an auditor reads.

Paths are written exactly as they are for `protectedHeaders` rather than as
RFC 6901 JSON Pointers, so there is no escaping convention to get wrong: a key
containing `/` is just a string. A mis-escaped pointer would resolve to nothing
and report "no such claim", which is indistinguishable from a payload that
genuinely lacks the field.

Only a payload whose **declared** content type says JSON is read —
`application/json` or any RFC 6839 `+json` suffix. The bytes are never sniffed:
a document is JSON because its issuer signed a claim that it is. A hash
envelope, a detached payload, a missing content type, and any other declared
type all give `cannotEvaluate`; a statement that declares JSON and carries
something else **fails**, because that is the statement contradicting itself
rather than a missing input.

Types are not coerced. A build id written as the string `"138849098"` fails an
`int` matcher instead of being converted, and a repeated object key is refused
outright rather than resolved — parsers disagree about which copy wins, so a
signed document could otherwise satisfy this policy while meaning something else
to the next tool that read the same bytes.

### `inspect` shows the payload

`Payload / bytes 72096` named the shape and stopped, which proved a payload was
there and gave a policy author nothing to write a rule against. It is the same
dead end the uninterpreted-header listing was written to remove, one level down.
Each claim is now printed beside the `path` that reaches it, ready to paste into
a `payloadJson` rule.

This also fixes a mismatch between the help text and the behaviour: `--verbose`
advertised "the full payload", but only `--format json` ever produced it.

Sniffing is deliberately not done here either — `inspect` decodes exactly what
`payloadJson` will read, so the listing can never advertise a rule the policy
engine would refuse to evaluate.

### `exists`, for headers and payload claims

```json
{"path": [15, "svn"], "exists": true}
{"path": ["debug-mode"], "exists": false}
```

Every other matcher has to look at a value, so a header whose value cannot be
predicted — a nonce, a per-run identifier — left the author choosing between
pinning something that legitimately varies and asserting nothing. `false` is the
only way to write "this must not appear", and it is the one rule for which
absence is a `pass` rather than `cannotEvaluate`.

### Older binaries reject policies that use the new assertions

A policy containing `payloadJson` or `exists` is refused outright by 0.3.0 and
earlier, with exit 4 and `unknown field 'payloadJson'`. That is intended, and
worth planning a rollout around: a policy is a security control, and a binary
that silently skipped the rules it did not recognise would report a pass for
checks nobody ran. Upgrade the verifier before distributing a policy that uses
them.

### `--online` fetches transparency service keys during the run

Until now the only way to check a receipt was to hold the service's key set
already, which meant committing a binary blob to the repository and renewing it
by hand every time the service rotated. `--online` fetches it instead, and the
new `online: true` input on the Action does the same.

What it is allowed to fetch is decided by the policy's `issuer` allowlist, not
by the statement. A receipt cannot nominate the service that vouches for it —
that inversion is the whole reason the allowlist sits in a reviewed document.
`--online` and `--scitt-keys` are mutually exclusive.

The fetch is two authenticated steps: the identity service is asked over the
public web PKI which certificate the ledger presents, and the key set is then
fetched trusting only that certificate. The key set must contain the key the
ledger authenticated with, checked against the key material rather than the
`kid` label, or the acquisition fails.

Verification itself is unchanged and still opens no socket. An acquisition
failure is reported as an acquisition failure — never as a finding about the
artifact, and never as a silent fallback to some other key.

`--save-trust <dir>` writes the fetched key sets and service certificates for
later offline replay with `--scitt-keys`, alongside a manifest recording which
endpoint served what and when. It refuses to overwrite an existing snapshot,
and refuses to let `--result` or `--facts` land on a file it wrote.

The record grows an `acquisition` block describing every ledger contacted,
including those that failed. The facts document carries it too: provenance is an
observation, not a conclusion.

### Known limits

Revocation is still not checked, and `--online` does not change that — it
fetches keys, never evidence. Online acquisition needs an x86-64 host with AVX2
and ADX (2014 or later); the bundled TLS stack requires them, and a host without
them is now refused with a diagnostic instead of aborting the process.

## 0.3.0

### An example policy no longer names a real service

`corpus/policies/esrp-mst-prod.json` is now `corpus/policies/example-dr-pair.json`,
and the two hostnames it accepts are `contoso-cp` and `contoso-db` rather than
the production service it was originally written against. If you referenced the
old path, update it.

The policy was always a template rather than a description of a committed
fixture, so nothing about the corpus changes — but an example that names a real
deployment invites someone to copy the hostname along with the shape. The
fixture policies still name the service the fixtures actually came from, because
that is provenance and generalising it would make the record false.

### Artifact binding moves into the core, and reaches the browser

Binding answers a different question from verification — not "is this statement
genuine" but "is it about the file I am holding" — and the two fail
independently. Until now the comparison lived in the CLI's `main.rs`, which
meant it was reachable only from a terminal. Any other consumer had to
reimplement it, and the WASM demo did exactly that, in JavaScript.

That is the arrangement worth avoiding. A browser and a pipeline comparing the
same two files by different code would eventually disagree about a hash
envelope or a detached payload, and the disagreement would surface as a release
that should have been stopped. `scitt_receipt::bind` is now the only
implementation; the CLI and the new `bindArtifact` WASM export both call it.

```js
const result = JSON.parse(bindArtifact(statement, artifact, 'payload-bytes', 'app.tar.gz'));
// { outcome: 'bound' | 'mismatch' | 'cannotCompare', reason, detail, ... }
```

Two things changed in the move rather than being copied across:

**There is no `None` mode in the core.** "No binding was requested" is the
absence of a call, not a mode. Modelling it as one invites a caller to ask for a
comparison and receive a pass for a comparison nobody performed. The CLI still
accepts `--binding-mode none` and simply does not call.

**Reasons are structured, not prose.** Each outcome carries a
`BindingReason` with a machine-stable `code`, and the prose is rendered against
whatever name the caller has for the artifact — a path in a pipeline, an
uploaded file name in a browser. The core also stops at the finding and offers
no remedy: `--binding-mode payload-digest` is meaningless advice in a browser,
so the CLI appends it and the WASM export does not.

`cannotCompare` remains distinct from `mismatch` throughout, on both sides of
the boundary. A detached payload, a mode that does not fit the statement, or a
hash this build cannot compute are facts about the comparison. Reporting any of
them as a mismatch tells an operator to halt a release over a limitation of the
tool.

One message changed wording. Under `payload-digest`, a detached payload
previously read "there is no digest to compare the artifact against" and now
names the mode: "the statement payload is detached, so binding mode
payload-digest has nothing to compare *artifact* against". The outcome is
unchanged.

### `externalSignatures`: verify a detached signature carried in a header

Some producers put a *second party's* signature inside the statement's protected
header — a component supplier signing a manifest that a build service later
registers. Until now a policy could only describe such a header: assert that it
declares RS256, that its certificate names the expected supplier. None of that
is evidence. Every byte read was chosen by whoever assembled the statement, so a
descriptor containing 512 random bytes matched exactly as well as a real one.

The new assertion computes the signature:

```json
"externalSignatures": [
  {
    "path": ["external-signature", 0],
    "signedOver": "payload",
    "signerSubjectContains": "Example Component Supplier"
  }
]
```

`path` addresses the descriptor map; the verifier reads algorithm (`1`),
certificate (`33`) and signature (`-1`) from inside it. ES256/384/512,
PS256/384/512 and RS256/384/512 are supported — RS256 in particular, since it is
the algorithm on essentially every detached supplier signature and the upstream
COSE mapping omits it.

`signedOver` is required and has no default. A detached signature carries no
record of what it signed, so a verifier that guessed would report a forgery
whenever it guessed wrong — the worst error a gate can make, because it teaches
operators to disregard the result. Two conventions are supported:

* `"payload"` — a hand-rolled descriptor map, whose signature covers the payload
  bytes directly.
* `"coseSign1"` — a nested COSE_Sign1, whose `Sig_structure` binds the protected
  header and the payload together.

Anything else is refused at parse time with exit 4. Naming the *wrong*
convention for the value present gives `cannotEvaluate`, never `fail`.

**Prefer `coseSign1` if you control the producer.** With the nested payload
detached (`nil`) it costs five bytes more than the descriptor — 1,522 against
1,517, since the certificate chain dominates both — and in exchange the question
`signedOver` exists to answer stops being a convention: the encoding says which
bytes are covered, and any COSE library can check it. An *embedded* nested
payload that differs from the statement's now **fails**: two disagreeing copies
inside one signed statement would let a producer have a supplier endorse one
thing while registering another, with both signatures verifying.

**What a pass does not mean.** The external certificate chain is not validated
to a trusted root, so a signer who mints their own certificate passes. A run
that uses this assertion now declares that under **Not checked** as
`ExternalSignerChainNotValidated`. `signerSubjectContains` and
`signerIssuerContains` narrow the result to a named certificate, which catches
mistakes rather than forgery.

What it does establish is that a private key was used over these exact payload
bytes, and — because the descriptor is in the protected bucket — that the
registering party committed to it on the record at a time the receipt fixes.
Moving a genuine supplier signature onto a different statement fails.

An absent descriptor is `cannotEvaluate`, never `fail`. A pipeline has to be
able to tell "this supplier did not sign" from "this supplier's signature is
fake".

The nested path builds its own `Sig_structure` rather than calling the upstream
helper the envelope check uses. That helper returns one error for two different
questions — "this signature is wrong" and "I cannot map this algorithm" — so
routing RS256 through it reported every real supplier signature as a forgery.
Both fixtures are registered on a real ledger:
`corpus/fixtures/cbor-header.cose` and `corpus/fixtures/nested-sign1.cose`.

### `alg`: match a COSE algorithm by name

`protectedHeaders` entries take a third matcher beside `text` and `int`:

```json
{ "path": [1],                          "alg": { "oneOf": ["ES256", "ES384"] } }
{ "path": ["external-signature", 0, 1], "alg": { "equals": "RS256" } }
```

It accepts exactly what `int` accepts. What changes is the cost of a mistake.
COSE algorithm identifiers are adjacent negative integers — `-35`, `-36`, `-37`
are ES384, ES512, PS256 — so a mistyped digit yields a *different, valid* policy
that passes for the rest of its life, invisibly, and a reviewer cannot spot it
without a registry. A mistyped name resolves to nothing and is refused at parse
time with exit 4, before any signature is checked.

Reports name both sides, so a refusal needs no lookup:

```text
[FAIL] protectedHeaders — [1]: ES512 (-36) does not match: it must be ES384
```

Names are matched exactly; `es256` is refused rather than repaired. There is no
`min`/`max`, since these are registry codes rather than a scale. Use `int` for
an algorithm this build has no name for.

`int` continues to work at every path, so existing policies are unaffected.
Because policies are parsed with `deny_unknown_fields`, a policy using `alg`
is rejected by 0.2.0 and earlier — intended, and the reason it is called out
here.

## 0.2.0

Breaking changes to the output contract. All of them landed together and before
v1.0 deliberately: the schema is easier to change now than after it has
consumers. See [docs/output.md](docs/output.md) for the full contract.

**Upgrading from 0.1.0:** gate on `appraisal.verdict` rather than the top-level
`verdict`, and expect `artifact-transparent` or `statement-transparent` where
0.1.0 emitted `verified`. The GitHub Action's `evidence` input is now `result`.
Note also that a broken receipt no longer produces exit 1 — see below.

### A broken receipt no longer decides the verdict

Receipts travel in the Signed Statement's *unprotected* header, which no
signature covers. Anyone who hands you the file — a mirror, a registry, a CI
cache — can append one without holding a key. Until now the verdict was decided
by scanning *every* receipt, so a single appended receipt with a corrupted
signature turned exit 0 into exit 1, reporting `untrusted` and telling the
operator *"Do not deploy this artifact"* about an artifact whose own signature
verified perfectly. That handed every party in the delivery path a veto over
the gate, and made the tool accuse the wrong thing.

`untrusted` (exit 1) is now reserved for the two findings that actually indict
the bytes in front of you:

- the Signed Statement's own signature failing
- an artifact binding mismatch

Transparency is a *positive* proof. One verified receipt establishes it, and
noise appended beside it cannot retract it. This follows RFC 9943 §7.1, which
sets the bar at trusting "at least one Issuer of a Receipt" and permits a
Relying Party to "verify only a single Receipt that is acceptable to them" and
disregard the rest.

**What changes for you:**

- A statement with at least one verified receipt passes, whatever else is
  attached. Broken receipts are reported as **warnings** in `diagnostics`, with
  remediation text that describes the receipt rather than the artifact.
- A statement with *no* verified receipt is now `cannot-evaluate` (exit 3)
  rather than `untrusted` (exit 1). Nothing was disproven; registration simply
  could not be established. If you gate on exit 1 alone, you must now also
  treat exit 3 as non-passing — as the documentation has always advised.
- `checks.receiptInclusion` no longer takes the value `fail`. It is `pass` when
  something verified and `cannot-evaluate` otherwise.

Two fixtures pin this: `appended-receipt.cose` (a corrupted receipt appended
beside a genuine one — still passes) and `tampered-statement.cose` (its only
receipt broken — exit 3, not exit 1).

### Policy assertions read only verified receipts

`requireKidBoundToKey` considered every receipt on the statement, including
ones whose signing key never resolved. Receipts arrive in the Signed
Statement's *unprotected* bucket, which no signature covers, so appending one
takes no key and breaks nothing — and a single appended receipt was enough to
force `cannotEvaluate` on a statement that was otherwise fine. It now considers
only fully verified receipts.

The rule is not weakened by this. `fully_verified()` requires the receipt's
signing key to have been *found*, not that its `kid` was derived from it, so a
genuine receipt whose kid is not its key's digest still fails as before.

`StatementFacts::verified_receipts()` now exists so that this filtering is a
method rather than a convention repeated at each call site, which is how the
`issuer` assertion came to be missing it too. `inspect` and the record's receipt
listing still enumerate every receipt, because "what is present" is the question
they answer.

**This does not close the appended-receipt problem.** The verdict itself is
still decided by scanning every receipt, so an appended receipt with a broken
signature still turns a passing verify into exit 1. That is tracked
separately; see [docs/limitations.md](docs/limitations.md).


### `artifactBinding` distinguishes "could not compare" from "did not match"

`bound` was a two-state boolean carrying three meanings. A statement with a
detached payload reported `false` — the same value as an artifact that genuinely
differed — so a binding mode that simply cannot apply came back as exit 1, *do
not deploy this artifact*. An unreadable artifact reported `null`, the same
value as never having asked.

- `bound` is `true` or `false` only when a comparison actually happened
- `status` now derives from the outcome rather than from whether `--artifact`
  was passed, so `not-evaluated` marks a binding that was requested and could
  not be made
- a requested binding that could not be made yields `cannot-evaluate` (exit 3)
  instead of falling through to `statement-transparent`

See [docs/output.md](docs/output.md) for the full table.

### Documented which standards are actually implemented

A new **Standards** section in the README states plainly that the tool
implements the RFC 9943 architecture and parses receipts per RFC 9942, but that
the only verifiable data structure it verifies is `CCF_LEDGER_SHA256` from
`draft-ietf-scitt-receipts-ccf-profile-04` — an Internet-Draft whose codepoint
is requested rather than assigned. `RFC9162_SHA256`, the only VDS RFC 9942
itself registers, is *not* implemented and is refused.

This is a documentation change only; no behaviour moved. It is called out
because the omission is the kind a reader assumes away: "RFC 9942 receipts"
reads as though the RFC's own proof format works, and it does not.

`labels::VDS_PROOFS` is renamed `labels::VDP` to match RFC 9942's name for
header 396.

### The verdict now says whether the artifact was checked

`verified` is replaced by two verdicts, both exit 0:

- `artifact-transparent` — the artifact you supplied is the one that was registered
- `statement-transparent` — the statement is transparent, but no artifact was checked

Previously a run that never opened the artifact printed the same word as one
that compared it byte for byte, which meant the most important distinction the
tool makes was invisible in its own output. The remaining verdicts moved to
kebab-case for consistency: `policy-failed`, `cannot-evaluate`, `usage-error`.

**Gate on the verdict, not on exit 0.**

### The decision comes first

Human output now leads with the verdict, the primary diagnostic, the four check
states, and the recommended action. Detailed evidence follows. Previously the
verdict was the last line, which in a long CI log is the part that gets scrolled
past.

### A record is written on every path

If `--result` is supplied, a record is now written even when the run fails
before verification starts — a malformed policy, an unreadable key set, a
missing file. Both shipped CI examples publish the record with `always()`; an
early failure previously left the archive empty exactly when someone needed it.

### `--format json` is one protocol

Failures now emit JSON on stdout too. Previously parse, input, and trust
failures printed plain text to stderr, so a pipeline consuming JSON had to
handle two protocols depending on how the run failed.

The one exception is a failure to parse the arguments themselves, where there is
no `--format` to honour.

### New first-class fields

- `primaryDiagnostic` — the one diagnostic that explains the exit code
- `trust` — how the trust material arrived (`mode`, `issuerScope`, `limitations`)
- `checks` — the four check states as a map
- `diagnostics` — structured problems with `code`, `category`, `severity`, `action`

`notChecked` entries changed from strings to objects with a stable `code`,
`category`, `message`, and `impact`, so a fleet-wide report can count runs that
skipped artifact binding rather than grepping English sentences.

### The record is structured around the SCITT vocabulary

The `details` bag is gone. The document now separates three things it used to
run together:

- **Observations** — `signedStatement`, `receipts`, `artifactBinding`
- **The rules** — `relyingPartyPolicy`
- **The decision** — `appraisal`, holding `verdict`, `exitCode`, `checks`,
  `primaryDiagnostic`, `diagnostics`, and `notChecked`

The observation blocks use the nouns from RFC 9943 §3 — Signed Statement,
Receipt, Verifiable Data Structure, Verifiable Data Proof — so a reader holding
the spec needs no glossary for ours. `artifactBinding` sits outside that
vocabulary on purpose: SCITT defines no relationship between a statement and a
deployed file, so it is our invention, asserted by the operator.

`relyingPartyPolicy` is named in full rather than `policy`, because RFC 9943 §3
already gives "Registration Policy" to the *transparency service*. Ours is the
Relying Party's — RFC 9943's own name for the role this tool performs — applied
long after registration. The ambiguity is about *whose* rules these are, so the
name answers that. It is populated from the `--policy` document.

### Every observation carries provenance

Each block now records which key, if any, covers it: `statement-signer`,
`transparency-service`, `operator`, or `unauthenticated`.

This matters most for receipts. Their *presence* is unauthenticated — RFC 9943
§3 places them in the Signed Statement's unprotected header, so anyone can add
or strip one without breaking the Issuer's signature — while their *contents*
are covered by the transparency service, a different signer entirely. A flat
document invited a downstream policy engine to treat both alike.

`fullyVerified` was removed from receipt entries: it was our judgement leaking
into the observations. Read `appraisal.checks.receiptInclusion` instead.

### `status` distinguishes "not evaluated" from "absent"

Every observation block carries `status`. A `null` field means the input did not
carry that value; `status: not-evaluated` means the run never got that far.
Previously both rendered as `null`, which made "the statement declares no SVN"
indistinguishable from "we failed before parsing the statement" — and in a Rego
policy both are `undefined`, which reads as a failed check.

### `--evidence` is now `--result`, and `--facts` is new

In RATS (RFC 9334 §8.1) "Evidence" is the *input* being appraised, so the old
name pointed at the wrong end of the pipeline. `--evidence` is refused with an
explanation rather than silently accepted.

`--facts` writes the observation blocks with `relyingPartyPolicy` and `appraisal`
removed, for systems that make their own decision. There is deliberately no way
to obtain it without a full verification: facts about a statement nobody
authenticated are worth nothing, and a keyless extraction path is how
unauthenticated claims end up in an admission policy.

### Schema versioning

`schemaVersion` is now `scitt-verifier/result/v0`, and `--facts` emits
`scitt-verifier/facts/v0`.

`v0` is deliberate — this shape is still moving, and it says so. It freezes at
`v1` when the repository goes public.

`scitt-verifier/evidence/*` is retired and will not be reused. `evidence/v1`
means what v0.1.0 emitted, permanently; reusing the string for a different shape
would leave a consumer no way to tell them apart.

### Policy results are spelled out

`[????]` is replaced by `[CANNOT EVALUATE]`. `NOT CHECKED` and `CANNOT EVALUATE`
are now distinct everywhere: the first means nobody asked, the second means we
asked and could not find out.

### A malformed statement is now exit 3, not exit 1

Exit 1 means "this artifact is untrusted". A statement truncated in transit is
not evidence that anyone tampered with anything, so it is now
`cannot-evaluate`. It remains a non-zero exit and is never a pass.

### `inspect` separates unreadable from undecodable

A file that could not be read exits 4; a file that was read but could not be
decoded as COSE_Sign1 exits 3. Previously both exited 4, contradicting the
documented contract.

### Fixed

- The text report gated its diagnostics list on there being more than one,
  intending not to repeat the primary diagnostic. It instead hid a lone
  diagnostic whenever that diagnostic was not the primary one. It now prints
  whatever the primary did not already say.
- The README claimed every design commitment had a test that fails if it
  erodes. Four did; "offline by default" and "no prerequisites" are
  whole-program properties no example run establishes. Offline is now genuinely
  enforced — `tests/design_commitments.rs` fails if a networking crate enters
  the dependency graph or any source file names a socket API. The README says
  which commitment is enforced by the release pipeline instead.
- The `issuer` policy assertion accepted any receipt's self-declared `iss`,
  including receipts whose signature never verified or whose key was never
  found. Receipts travel in the statement's *unprotected* bucket, so anyone
  holding the file can append one. It now considers only fully verified
  receipts, matching `registeredAfter` and `minReceipts`, and reports
  `cannotEvaluate` when none of them declares an issuer.
- `Assessment::incomplete()` emitted an empty `appraisal.notChecked`, so every
  run that stopped early — unreadable statement, malformed policy, unusable
  trust material — reported that nothing had been skipped. Those runs skip
  more than a complete one, not less.
- `docs/limitations.md` offered `signerSubjectContains` and
  `signerIssuerContains` as the mitigation for an unvalidated certificate
  chain. Against the attacker described there they mitigate nothing, because
  he mints the certificate and therefore chooses the strings. Both documents
  now say what actually protects you, and the assertion table in
  `docs/policy.md` marks the two as weak.
- `action.yml` rendered `notChecked` entries by string concatenation, which
  breaks against the new object form. It now reports the code and message, and
  surfaces `primaryDiagnostic` as an annotation.
- The GitHub Actions example gated on `verdict == 'verified'`; it now gates on
  `artifact-transparent`. It also passed the removed `evidence:` input, which
  `action.yml` renamed to `result:`.
- The Azure Pipelines example treated any exit 0 as success; it now checks the
  verdict before deploying.

## 0.1.0

First release.
