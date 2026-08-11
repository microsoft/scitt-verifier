# Changelog

## Unreleased

Breaking changes to the output contract. All of them landed together and before
v1.0 deliberately: the schema is easier to change now than after it has
consumers. See [docs/output.md](docs/output.md) for the full contract.

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
- **The rules** — `appraisalPolicy`
- **The decision** — `appraisal`, holding `verdict`, `exitCode`, `checks`,
  `primaryDiagnostic`, `diagnostics`, and `notChecked`

The observation blocks use the nouns from RFC 9943 §3 — Signed Statement,
Receipt, Verifiable Data Structure, Verifiable Data Proof — so a reader holding
the spec needs no glossary for ours. `artifactBinding` sits outside that
vocabulary on purpose: SCITT defines no relationship between a statement and a
deployed file, so it is our invention, asserted by the operator.

`appraisalPolicy` is named after RATS (RFC 9334 §8.5) rather than `policy`,
because RFC 9943 §3 already gives "Registration Policy" to the *transparency
service*. Ours is the relying party's, applied long after registration.

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

`--facts` writes the observation blocks with `appraisalPolicy` and `appraisal`
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

- `action.yml` rendered `notChecked` entries by string concatenation, which
  breaks against the new object form. It now reports the code and message, and
  surfaces `primaryDiagnostic` as an annotation.
- The GitHub Actions example gated on `verdict == 'verified'`; it now gates on
  `artifact-transparent`.
- The Azure Pipelines example treated any exit 0 as success; it now checks the
  verdict before deploying.

## 0.1.0

First release.
