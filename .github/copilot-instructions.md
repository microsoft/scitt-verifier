# Copilot instructions

## What this repository is

`scitt-verifier` verifies SCITT transparent statements and evaluates the relying
party's policy, offline by default. Artifact binding and resource adapters are
optional; a deployed ledger is not the general subject of verification. Receipt
proof support is currently CCF VDS only. It returns pipeline exit codes and is a security
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
answer. Code 0 is the only success, and it carries distinct verdicts:
`artifact-transparent` (an artifact was supplied and matched) and
`statement-transparent` (no artifact was checked), or `resource-transparent`
(the selected adapter's scoped requirements held). Do not blur them.

An unimplemented flag or assertion exits 4 with an explanation. Accepting and
skipping it reports success for work nobody did.

## Say only what was verified

Output, docs, and comments describe what this build actually does — not what is
planned, and not what a reader might assume. Two live examples:

* Supported signing certificate chains are validated. Without independent
  `--trusted-roots` or a policy pin to an independently selected root, an
  embedded anchor establishes internal consistency, not external trust.
  Unsupported chain checks and absent external anchoring are reported;
  revocation is never checked.
* A header this build does not interpret is printed and marked
  `(not interpreted)`. It is rendered so it can be audited, not because its
  contents were understood.

If a change means something is no longer verified, add it to
`appraisal.notChecked`. Runtime, not just documentation.

## The report is part of the verdict

Every value drawn from a statement, a policy or a bundle is untrusted text.
Escape it on **every** path that reaches a terminal — the compact transcript,
the verbose report and anything added later — or a crafted node label can emit
newlines and terminal controls that scroll a failure away or forge a verdict
line. `safe()` in `crates/scitt-verifier/src/report.rs` does the escaping; use
it rather than formatting the value directly.

A verdict that was not written was not delivered. Writing to stdout and
flushing can fail, and the caller must handle the error rather than discard it;
a pass whose record is missing or truncated is demoted, not reported as 0.

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
| `crates/scitt-policy` | Statement assertions and typed requirements in `src/adapters/{mod.rs,acl.rs}`; no I/O |
| `crates/scitt-network` | Network acquisition of receipt keys and resource evidence; no policy decisions |
| `adapters/azure-confidential-ledger` | `scitt-adapter-azure-confidential-ledger`: pure appraisal of ACL/CCF node evidence; no I/O, no CLI verdicts. Renamed to `acl` inside `scitt-verifier`, because the published name is what a consumer types and `acl` alone means access-control list |
| `crates/scitt-verifier` | CLI arguments, reporting, exit codes; `src/adapters/` owns dispatch, adapter orchestration, bundle loading and acquisition orchestration |
| `crates/scitt-wasm` | Browser bindings and the demo page |
| `corpus/` | Real fixtures and example policies |
| `docs/` | `policy.md`, `adapters.md`, `output.md`, `trust-material.md`, `limitations.md`, `architecture.md`, `distribution.md` |

Policy JSON separates `assertions` from
`adapters.azure-confidential-ledger.{target,trust,binding}`. The old top-level `ledger`/`trust`
and `assertions.bindLedgerPolicy` shape is not supported.
`Policy::evaluate` must not pass when required adapters cannot run; the CLI
evaluates statement assertions and then adapters explicitly. Keep SNP/UVM
types specific to the Azure Confidential Ledger adapter. There is no generic
attestation crate or plugin framework.

A requirement that does not apply to the evidence is not satisfied by it. A
minimum TCB configured for one processor generation says nothing about a
report from another, so the adapter demands a floor covering the generation it
actually authenticated rather than letting an inapplicable minimum stand in
for one. The same reasoning governs counting: node coverage counts distinct
attested keys, because a saved bundle is unsigned and the cheapest forgery is
one agreeing node copied under several names.

Saved evidence is attacker-supplied input. `src/adapters/load.rs` bounds what
it will read — file, manifest and total sizes, and node count — and refuses any
path that leaves the bundle directory after canonicalisation, not just one that
says `..`.

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

The adapter is behind a feature and is not built by the commands above. Lint
and test it explicitly:

```console
cargo clippy -p scitt-verifier --features adapter-azure-confidential-ledger --all-targets
cargo clippy -p scitt-adapter-azure-confidential-ledger --features azure-confidential-ledger --all-targets
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
