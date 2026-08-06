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
        ┌───────────▼────────────┐
        │    scitt-verifier      │   files, terminals, exit codes
        │  CLI · evidence · exit │
        └────────────────────────┘
```

Everything above the bottom box could run in a browser.

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
let a single weak service satisfy a policy that deliberately asked for two, and
would do so silently.

Where a single receipt carries multiple inclusion proofs, only the first is
evaluated and the evidence says so.

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
