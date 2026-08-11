# Changelog

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
