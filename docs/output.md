# The output contract

Everything in this document is a contract. A pipeline branches on these values,
so changing one is a breaking change and moves the evidence `schemaVersion`.

## The verdict

`verify` produces exactly one verdict.

| Verdict | Exit | What it claims |
|---|---|---|
| `artifact-transparent` | 0 | The artifact you supplied is the one that was registered, the receipt proves inclusion, and your policy is satisfied. |
| `statement-transparent` | 0 | The statement is transparent and your policy is satisfied — but **no artifact was checked**. |
| `untrusted` | 1 | The statement's own signature or the artifact binding did not hold. Do not deploy. |
| `policy-failed` | 2 | Everything is cryptographically sound; your own rules rejected it. |
| `cannot-evaluate` | 3 | The tool could not answer the question. **This is not a pass.** |
| `usage-error` | 4 | The invocation or its inputs were wrong. Nothing was established. |

### Why exit 0 is two verdicts

These are different claims, and only one of them is what a release gate is
actually asking:

- `statement-transparent` — *some* statement was registered on a transparency
  service and satisfies your policy.
- `artifact-transparent` — *the bytes you are about to deploy* were registered.

A tool that prints one word for both lets a run that never opened the artifact
look identical to one that compared it byte for byte. If you are gating a
deployment, **gate on `artifact-transparent`**, not on exit 0.

Exit 0 is shared deliberately: a team adopting the gate incrementally should not
have their build break the day they add `--artifact`. The distinction lives in
the verdict, where it can be checked explicitly.

## Check states

Each of the four checks reports one of four states. They are not
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

`not-checked` and `cannot-evaluate` are the pair most worth keeping apart. The
first is an incomplete invocation; the second is a broken one.

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
  "issuerScope": "contoso.confidential-ledger.azure.com",
  "limitations": [
    "the key set carries no publisher signature",
    "no revocation status is available offline",
    "no anti-rollback protection: an older key set will verify happily"
  ]
}
```

"The receipt signature is valid" means nothing without "valid under whose key,
and who vouched for it". Today there is one mode, because `--scitt-keys` takes a
raw COSE key set with no publisher signature. See
[trust-material.md](trust-material.md) for how to obtain one and what the
sidecar does and does not prove.

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
downgraded to `usage-error` (exit 4) and the emitted document is built from the
downgraded assessment so that its `verdict` and `exitCode` agree with the
process. A run that was already failing keeps its own, more important, verdict.

The most common cause is an output path whose parent directory does not exist.

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

## Where the failure boundaries sit

Four kinds of failure that must not look alike:

| Situation | Verdict | Exit | Reasoning |
|---|---|---|---|
| Missing or unreadable file, malformed policy | `usage-error` | 4 | The operator's problem. Nothing was established. |
| Malformed statement or key set | `cannot-evaluate` | 3 | A truncated download is not evidence of compromise. Never a pass. |
| Unknown kid, stale keys, issuer mismatch | `cannot-evaluate` | 3 | An operational chore, not an incident. |
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
| Could not read the file | 4 |

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

The `scitt-verifier/evidence/*` name is **retired and will not be reused**.
`evidence/v1` means what v0.1.0 emitted, permanently — reusing the string for a
different shape would leave a consumer no way to tell them apart. The name
changed because in RATS (RFC 9334 §8.1) "Evidence" is the *input* being
appraised, while this document is the tool's *output*; the old name pointed at
the wrong end of the pipeline.

Relative to the retired `evidence/v2` draft:

- the `details` bag is gone. `signedStatement`, `receipts`, and
  `artifactBinding` are now top-level sections, named after RFC 9943 §3
- `verdict`, `exitCode`, `checks`, `primaryDiagnostic`, `diagnostics`, and
  `notChecked` moved under `appraisal`
- the policy moved to `relyingPartyPolicy` — named for *whose* rules they are,
  because RFC 9943 §3 reserves "Registration Policy" for the transparency
  service's own admission rules. It is populated from the `--policy` document.
- every observation block carries a `provenance` object and a `status`
- `fullyVerified` was removed from receipt entries: it was our judgement
  leaking into the observations. Read `appraisal.checks.receiptInclusion`
- `--evidence` was renamed `--result`; the old flag is refused with an
  explanation rather than silently accepted

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
