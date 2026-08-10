# Changelog

## Unreleased

Breaking changes to the output contract. All of them landed together and before
v1.0 deliberately: the evidence schema is easier to change now than after it has
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

### Evidence is written on every path

If `--evidence` is supplied, a record is now written even when the run fails
before verification starts — a malformed policy, an unreadable key set, a
missing file. Both shipped CI examples publish evidence with `always()`; an
early failure previously left the archive empty exactly when someone needed it.

### `--format json` is one protocol

Failures now emit JSON on stdout too. Previously parse, input, and trust
failures printed plain text to stderr, so a pipeline consuming JSON had to
handle two protocols depending on how the run failed.

The one exception is a failure to parse the arguments themselves, where there is
no `--format` to honour.

### New first-class evidence fields

- `primaryDiagnostic` — the one diagnostic that explains the exit code
- `trust` — how the trust material arrived (`mode`, `issuerScope`, `limitations`)
- `checks` — the four check states as a map
- `diagnostics` — structured problems with `code`, `category`, `severity`, `action`

`notChecked` entries changed from strings to objects with a stable `code`,
`category`, `message`, and `impact`, so a fleet-wide report can count runs that
skipped artifact binding rather than grepping English sentences.

`statement`, `receipts`, `artifactBinding`, `policy`, and `problems` moved under
`details`.

`schemaVersion` is now `scitt-verifier/evidence/v2`.

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
