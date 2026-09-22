# Architecture

## The boundary that matters

Statement verification is the common path. Resource appraisal is optional,
not a prerequisite for verifying a transparent statement.

| Component | Responsibility |
|---|---|
| `crates/scitt-receipt` | Parse, verify signatures and receipts, compare artifact bytes; facts only, no I/O or clock |
| `crates/scitt-policy` | Evaluate statement assertions and parse typed adapter requirements; no I/O or clock (`now` is supplied) |
| `crates/scitt-network` | Acquire receipt keys and live resource evidence; no policy decisions |
| `adapters/mst-ledger` (`scitt-adapter-mst-ledger`) | Pure appraisal of supplied MST ledger evidence against typed requirements |
| `crates/scitt-verifier` | Load inputs, select acquisition and adapter paths, combine checks, report verdicts and exit codes |

`scitt-policy/src/adapters/{mod.rs,mst_ledger.rs}` owns the policy namespace
and MST-specific requirements. CLI
`scitt-verifier/src/adapters/mod.rs` provides dispatch and the shared appraisal
result; `mst_ledger.rs` translates MST requirements and findings, and `load.rs`
handles local evidence bundles. `live.rs` calls
`scitt_network::mst_ledger::collect`, then decodes and joins the returned node
views into a pure evidence bundle. TLS bootstrap, pinned connections, and
bounded HTTP collection belong to `collect`, not the CLI or pure adapter.

Before network acquisition, the CLI rejects a mismatch between the selected
adapter and the policy's adapter requirements. It then requires the full
statement verdict to pass (signature, receipt, chain handling, and statement
policy) before running the adapter against the accepted in-memory statement.
`Policy::evaluate` remains
fail closed for callers that cannot run adapter requirements: statement-only
evaluation must not silently satisfy a policy that also requires appraisal.
Adapter results may narrow acceptance, never rescue a failed statement check.

The internal `AdapterAssessment` contains `checks`, `required_checks`, `scope`,
and `notes`. It does not carry an independent pass boolean. `scoped_pass()`
derives acceptance from a non-empty required-check list: every required name
must resolve to exactly one check whose state is `Pass`. Missing, duplicate,
failed, or unevaluated required checks block success. Other checks still report
scope limitations; they cannot stand in for a required check.

There is no generic `scitt-attest` crate, plugin loader, or universal SNP
evidence model. SNP and UVM concepts belong to the MST adapter. A future image,
hardware, or MAA adapter could use this separation, but none is implemented
by the existence of the dispatch seam.

## Where the network is, and is not

`--online` fetches receipt-signing keys from policy-allowlisted transparency
services. `--binding-mode live-evidence` additionally acquires resource evidence
from `adapters.mst-ledger.target.host`; the two destinations need not be the
same. Live evidence currently requires `--online`, but key acquisition alone
does not request an appraisal. See [adapters](adapters.md).

`scitt-network` owns network I/O. It returns acquired material, not a verdict.
Verification uses the same core whether keys came from `--scitt-keys` or
`--online`. The pure adapter likewise appraises supplied evidence without
opening sockets or loading files.

The dependency boundaries are deliberate:

- The core, policy, and pure adapter cannot reach network clients.
- CLI network access goes through `scitt-network`.
- Network acquisition does not depend on relying-party policy evaluation.

Check reachability from those roots, not merely whether a networking package
appears in `Cargo.lock`: an optional or unrelated dependency says nothing about
what the pure verification path can do.

### What a fetch establishes

Only that the service serving the keys is the one that authenticated the
connection, and that the key set it served contains the key that certificate
binds to. The check is on key material, not on `kid` text: a service that
returned a key set omitting its own signing key is rejected rather than
believed.

It does not establish that a key is unrevoked, that the set is current, that
the receipt was honestly issued, or anything at all about whoever signed the
statement. `--online` removes the chore of distributing a key set. It does not
convert a transparency service into a trusted authority.

## Why the core is separate

The same verification logic has at least two consumers with incompatible
assumptions:

* A **deployment gate** wants exit codes, file paths, and a terminal.
* A **ledger explorer** in a browser wants none of those and cannot have them.

A core that reads files cannot be compiled to WASM without shims. A core that
returns "exit 1" has already decided something the browser has no business
being told. So the core returns facts, and each consumer decides what a fact
means.

This is not speculative reuse. The Merkle leaf construction in
`crates/scitt-receipt/src/receipt.rs` is byte-for-byte the same computation as
the one in
[CCF-Ledger-Explorer](https://github.com/microsoft/CCF-Ledger-Explorer)'s
`receipt-verification.ts`. Two implementations of the same algorithm is one
implementation too many.

The boundary is enforced in CI (`.github/workflows/ci.yml`, job `boundary`) by
grepping the core for `std::fs`, `SystemTime`, `ExitCode`, network clients, and
any coupling to policy or CLI crates. Greps are crude, but they fail on the
first `use std::fs` someone adds "just here", which is when the erosion actually
happens.

### What is in the core

* SCITT header labels (394 / 395 / 396) and CWT claims
* The claim digest — re-encoding with an empty unprotected bucket
* The statement signature check
* CCF leaf hashing and the Merkle path walk
* COSE_KeySet parsing, kid resolution, issuer scoping
* The `claims_digest` binding back to the statement
* Artifact binding over supplied bytes (not loading the artifact from disk)

### What is not

* Relying-party policy — a trust decision, not a fact
* Loading artifacts and evidence from files
* Domain-specific resource appraisal
* The evidence document, exit codes, and verdict vocabulary — all consumer
  concerns
* Anything that reads the clock

The test for a borderline case: *could a ledger explorer consume this without
embarrassment?* If it would have to ignore half the return value, it belongs
outside.

## Reuse from the CCF team

`scitt-receipt` builds on two crates from
[microsoft/TEE-Attestation-Verification](https://github.com/microsoft/TEE-Attestation-Verification),
written by CCF maintainers:

| Crate | What we use it for |
|---|---|
| `…-cose` | CBOR (EverParse/EverCBOR, formally verified) and `cose_verify1` |
| `…-crypto` | Pluggable crypto backends, certificate parsing, chain validation |

Two properties made this the right base rather than a general-purpose COSE
crate:

1. **The CBOR encoder is deterministic**, and Microsoft Signing Transparency
   statements round-trip through it byte-identically. That matters because the
   claim digest is computed over a *re-encoded* statement; a non-canonical
   encoder would silently change the digest and break every receipt.
2. **The crypto backend is swappable at compile time** — pure Rust, OpenSSL, or
   WebCrypto. The pure-Rust backend needs no OpenSSL, no C compiler, and no
   external crypto library. Native builds still require a Rust-compatible
   linker; the same core also supports the WASM consumer.

We verify real PS256 statements with 4-certificate chains through the pure-Rust
path, so this is measured rather than assumed.

## Verification order, and why

1. **Parse**, keeping the protected bucket's bytes exactly as received. The
   signature is over those bytes; canonicalising them would be a correctness bug
   even on the many inputs where it happens to round-trip.
2. **Compute the claim digest** by re-encoding with an empty unprotected bucket.
   Receipts are added to the unprotected bucket *after* registration, so they
   must be removed before hashing — otherwise attaching a receipt changes the
   digest that receipt commits to.
3. **Verify the statement signature** against the key in its own leaf
   certificate. This establishes internal consistency only.
4. **For each receipt**: compute the leaf, walk the Merkle path, resolve the
   signing key *scoped to the issuer*, verify the root signature, and compare
   the receipt's `claims_digest` to step 2.
5. **Return facts.**

Step 4's ordering is deliberate. The issuer is checked before the kid, so a key
that is legitimate for a different transparency service can never satisfy this
receipt. Filtering after a successful match would work identically — right up
until someone refactors the filter away.

Step 4's final comparison is the one that is easy to omit and fatal to omit.

## Multiple receipts

A statement may carry more than one receipt, registered with more than one
transparency service. All of them are evaluated. Reading only the first would
let a single weak service satisfy a policy that deliberately asked for a
specific issuer, and would do so silently.

The verdict never treats an extra receipt as fatal: transparency is a positive
proof, and RFC 9943 §7.1 lets a Relying Party verify one acceptable receipt and
disregard the rest. Were it otherwise, anyone who handled the file could append
a blob to the unprotected header bucket and veto a gate on an artifact that is
fine.

That leaves a gap only the operator can close, because only they know what shape
to expect. The `receiptCount` policy assertion counts receipts *present* rather
than receipts that verified, so it sees an insertion the verdict deliberately
ignores. It fails as a policy decision, which is the honest category: the file
was handled after the service returned it, while the artifact is still exactly
what its Issuer signed.

Where a single receipt carries multiple inclusion proofs, only the first is
evaluated and the evidence says so.

### Keys from one service never verify another's receipt

Online mode makes this concrete. A statement may carry receipts from several
services, and a policy may allowlist several. The keys are never merged into
one pool.

Instead, each acquired key set is handed to its own verification pass, and a
receipt's result is taken only from the pass belonging to the service that
receipt names. Two services publishing the same `kid` cannot stand in for one
another, because the receipt naming service A is never shown service B's keys
at all — there is no lookup to confuse, rather than a lookup that has to be
careful.

The matching is done on the issuer recorded in each receipt's own facts, not on
its position in the envelope. Receipts that fail to parse are absent from the
facts while still present in the file, so the two sequences drift apart exactly
when a malformed blob has been appended — which is precisely when attributing
one receipt's keys to another would matter most.

A receipt whose service was not selected, or could not be reached, is reported
as never consulted: `key lookup (not attempted)`, with the reason. It is not
reported as an unknown key. Saying otherwise would describe a deliberate
scoping decision as a gap in the trust material, and send an operator looking
for a key rotation that never happened.

## Tri-state, not boolean

Every check result is `Option<bool>`:

| Value | Meaning |
|---|---|
| `Some(true)` | Ran and passed |
| `Some(false)` | Ran and failed |
| `None` | Did not run |

`None` is never treated as success. `ReceiptFacts::fully_verified()` requires
`Some(true)` explicitly for each check, so adding a new check that fails to run
degrades the verdict rather than being quietly ignored.
