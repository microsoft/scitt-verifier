# Copilot instructions

## What this repository is

`scitt-verifier` decides whether a SCITT transparent statement is trustworthy,
offline, and returns an exit code that pipelines branch on. It is a security
gate. The failure that matters is not a crash — it is a `PASS` printed for
something nobody actually checked, because that answer is believed and acted on.

Read `CONTRIBUTING.md` first; the rules there are enforced in CI and are not
negotiable. What follows is the part that is easy to get wrong.

## The rule that overrides the others

**Never make a failing test pass by changing what it expects.**

Pinned digests in `crates/scitt-receipt/tests/conformance.rs` and the values in
`corpus/README.md` are cross-checked against the .NET prototype and `pyscitt`.
If one no longer matches, the meaning of "the same statement" has changed and
every receipt issued under the old meaning is affected. That is a finding to
report, not a constant to update.

The same applies to assertions in `crates/scitt-verifier/tests/acceptance.rs`.
Loosening an assertion, deleting a case, or widening a matcher until it passes
converts a real failure into a silent one.

If you cannot make a test pass honestly, say so and stop.

## Fail closed, always

A check that did not run is never a pass. Results are `Option<bool>`; `None`
means "did not run" and must not be collapsed into success. Absent input yields
`CannotEvaluate`, never `Pass` — see step 2 of "Adding a policy assertion" in
`CONTRIBUTING.md`.

Exit code 3 (`cannot-evaluate`) is **not** a pass. It means the tool could not
answer. Code 0 is the only success, and it carries two distinct verdicts:
`artifact-transparent` (an artifact was supplied and matched) and
`statement-transparent` (no artifact was checked). Do not blur them.

An unimplemented flag or assertion exits 4 with an explanation. Accepting and
skipping it reports success for work nobody did.

## Say only what was verified

Output, docs, and comments describe what this build actually does — not what is
planned, and not what a reader might assume. Two live examples:

* The signing certificate chain is **not** validated to a trusted root, and
  revocation is never checked. Both appear in `appraisal.notChecked` at runtime.
* A header this build does not interpret is printed and marked
  `(not interpreted)`. It is rendered so it can be audited, not because its
  contents were understood.

If a change means something is no longer verified, add it to
`appraisal.notChecked`. Runtime, not just documentation.

## Fixtures are real bytes

Everything in `corpus/fixtures/` came from a real transparency service. Do not
synthesise a statement, a receipt, or a key set to make a test convenient — a
verifier that only works on inputs we generated proves nothing about the ones it
will meet. Add a real artifact and record its provenance in `corpus/README.md`.

`.gitattributes` marks `*.cose`, `*.cbor`, and `*.bin` binary because git will
otherwise rewrite line endings in `artifact.bin` and break the binding check.
`fixtures_are_byte_exact` fails if that regresses.

## Real, but never someone else's

"Real bytes" is a claim about provenance — the statement was signed by a real
key and registered on a real service — not a licence to commit whatever real
file happened to be at hand. Partner and customer material must not enter this
repository at all: not as a fixture, not quoted in a doc, not as a test string,
and not as a comment describing where a bug was found. It is easy to add and
effectively permanent, because history keeps it after the file is deleted.

Treat a hardware BOM, an SBOM, a build manifest, or a signature obtained from
another organisation as evidence to reproduce, not to copy. Mint the equivalent
instead: generate a throwaway key, sign a stand-in payload, register it, and
commit that. The result is usually the better fixture — smaller, and complete
enough to verify, since you hold the key material the original withheld.

The same applies to prose. Examples in `docs/`, `corpus/README.md`, and test
data should use neutral, obviously-invented identifiers, so that no part number,
serial, subject, or organisation name in this repository refers to anything that
exists. Where an example must resemble a real one to make its point, describe
the shape and invent the value.

If a change would be weakened by generalising it, say so and stop — do not
resolve the tension by committing the original.

## Layout

| Path | Role |
|---|---|
| `crates/scitt-receipt` | Core: parsing, crypto, receipts, binding. Embeddable — no I/O, no clock, no verdicts, no dependency on the other crates. CI's `boundary` job enforces this by grep |
| `crates/scitt-policy` | Relying-party policy: parsing and evaluation |
| `crates/scitt-verifier` | The CLI: argument handling, reporting, exit codes |
| `crates/scitt-wasm` | Browser bindings and the demo page |
| `corpus/` | Real fixtures and example policies |
| `docs/` | `policy.md`, `output.md`, `trust-material.md`, `limitations.md`, `architecture.md`, `distribution.md` |

Crypto and CBOR come from `tav-cose` / `tav-crypto`
(microsoft/TEE-Attestation-Verification), pinned to an exact git revision. An
upgrade is a reviewed commit here, never an upstream tag moving. Do not add a
second crypto or CBOR dependency; check what TAV already exposes first.

## Build and test

```console
cargo fmt --all -- --check
cargo clippy --all-targets      # not --all-features: crypto backends are exclusive
cargo test --workspace
```

`RUSTFLAGS: -D warnings` in CI, so a warning is a failure. The release binary
has a 4 MiB budget and the WASM bundle 1 MiB; both are enforced.

## Style

Comments explain **why**, not what. The existing ones argue for a decision and
name what would go wrong otherwise — match that. Do not add comments that
restate the code, and do not strip the reasoning out of existing ones.

Prose in docs and output is plain and direct. No marketing, no hedging, no
emoji.

## When adding a policy assertion

Follow the five steps in `CONTRIBUTING.md`. The one most often skipped is
step 3: update `is_empty`, or a policy containing only the new assertion is
rejected as empty. Test all three outcomes, including `cannotEvaluate`.

`deny_unknown_fields` means older binaries reject policies that use a new
assertion. That is intended; mention it in release notes.
