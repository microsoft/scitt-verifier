# Architecture

## The boundary that matters

```
                 bytes in
                    │
        ┌───────────▼────────────┐
        │     scitt-receipt      │   facts, no opinions
        │  parse · digest · COSE │   no I/O · no clock · no exit codes
        │  Merkle · key lookup   │
        └───────────┬────────────┘
                    │ StatementFacts
        ┌───────────▼────────────┐
        │     scitt-policy       │   facts → decision
        │  assertions over facts │   no I/O · no clock (now is a parameter)
        └───────────┬────────────┘
                    │ PolicyDecision
        ┌───────────▼────────────┐        ┌──────────────────────┐
        │    scitt-verifier      │◀───────│    scitt-acquire     │
        │  CLI · evidence · exit │  keys  │  the only socket     │
        └────────────────────────┘        │  --online only       │
                                          └──────────────────────┘
```

Everything above the bottom row could run in a browser.

## Where the network is, and is not

`--online` fetches signing keys from the transparency service that issued a
receipt. That is one crate, `scitt-acquire`, and it is the only place in the
tree that can open a socket.

The arrow points one way on purpose. `scitt-acquire` produces key material and
nothing else: it does not see the policy, does not evaluate assertions, and
cannot produce a verdict. Verification runs afterwards, in the same core crates
that run offline, over the same `StatementFacts`. A run with `--online` and a
run with `--scitt-keys` reach the decision by identical code; they differ only
in where the bytes came from.

Three properties hold structurally rather than by convention, and
`tests/design_commitments.rs` walks the dependency graph to prove each one:

- `scitt-receipt` and `scitt-policy` cannot reach a network crate on any path.
  A verdict that depended on a socket could be changed by whoever controls the
  socket.
- Networking reaches the CLI only through `scitt-acquire`. Without this,
  `--online` would be indistinguishable from the whole tool having quietly
  become a network client.
- `scitt-acquire` does not depend on `scitt-policy`. Fetching trust material
  and judging it are separate jobs, and only the second may reach a conclusion.

That test used to assert something blunter: that no network crate appeared
anywhere in `Cargo.lock`. It could not survive `--online` existing, and
replacing it was a reviewed decision rather than a convenience. What replaced
it is more precise, not merely more permissive. Lockfile presence was always a
proxy — it flagged optional dependencies that are never compiled, and would
have flagged a crate pulled in by a dev-dependency of an unrelated package.
Reachability from named roots is the property actually claimed, and is now
checked directly.

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
any reference to the other two crates. Greps are crude, but they fail on the
first `use std::fs` someone adds "just here", which is when the erosion actually
happens.

### What is in the core

* SCITT header labels (394 / 395 / 396) and CWT claims
* The claim digest — re-encoding with an empty unprotected bucket
* The statement signature check
* CCF leaf hashing and the Merkle path walk
* COSE_KeySet parsing, kid resolution, issuer scoping
* The `claims_digest` binding back to the statement

### What is not

* Relying-party policy — a trust decision, not a fact
* Artifact binding — needs a filesystem
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
   platform linker, which is what makes both a static binary and a future WASM
   build possible from one source tree.

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
