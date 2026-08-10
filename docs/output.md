# The output contract

Everything in this document is a contract. A pipeline branches on these values,
so changing one is a breaking change and moves the evidence `schemaVersion`.

## The verdict

`verify` produces exactly one verdict.

| Verdict | Exit | What it claims |
|---|---|---|
| `artifact-transparent` | 0 | The artifact you supplied is the one that was registered, the receipt proves inclusion, and your policy is satisfied. |
| `statement-transparent` | 0 | The statement is transparent and your policy is satisfied — but **no artifact was checked**. |
| `untrusted` | 1 | A signature, inclusion proof, or artifact binding did not hold. Do not deploy. |
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

## `notChecked`

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

## Evidence is written on every path

If `--evidence` is supplied, a record is written **whether or not verification
completed**. A run that failed to parse the policy still produces a document
with `exitCode`, `primaryDiagnostic`, and every check marked `not-checked`.

Both shipped CI examples publish the evidence artifact with `always()`. If an
early failure wrote no file, the archive would be empty exactly when someone
needed it — during an incident.

`every_failure_path_still_writes_evidence` in `tests/acceptance.rs` pins this.

### If the evidence cannot be written

A pass whose audit trail vanished is not a pass a gate should act on. If
`--evidence` is supplied and the write fails, a passing run is downgraded to
`usage-error` (exit 4) and the emitted document is rebuilt so that its `verdict`
and `exitCode` agree with the process. A run that was already failing keeps its
own, more important, verdict.

The most common cause is an evidence path whose parent directory does not exist.

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
| Invalid signature, bad inclusion proof, binding mismatch | `untrusted` | 1 | An incident. |

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

Evidence is deterministic **for fixed inputs and a fixed `--now`**. That is the
whole guarantee, and it is narrower than it sounds:

- Without `--now`, `evaluatedAt` varies per run.
- `inputs` records the paths you passed, so two agents with different workspace
  layouts produce different documents from identical bytes — including the path
  separator, which differs between Windows and Linux agents.

If you are diffing evidence across runs, pass `--now` and compare the `checks`,
`verdict`, `primaryDiagnostic`, and `details` blocks rather than the whole
document.

## Schema versioning

`schemaVersion` is currently `scitt-verifier/evidence/v2`.

v2 changed, relative to v1:

- `verdict` gained `artifact-transparent` / `statement-transparent`, replacing
  `verified`; the remaining values moved to kebab-case
- `primaryDiagnostic`, `trust`, `checks`, and `diagnostics` are new
- `notChecked` entries changed from strings to objects
- `statement`, `receipts`, `artifactBinding`, `policy`, and `problems` moved
  under `details`

A v1 consumer matching `"verdict": "verified"` would have silently stopped
matching, which is why the version moved with it.
