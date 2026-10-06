# scitt-wasm

WebAssembly bindings for `scitt-receipt`, so browsers can verify SCITT
transparent statements with the same core the CLI uses.

## Why this crate exists

Verifying a transparent statement in a browser previously meant either shipping
the bytes to a service — which defeats the point of offline, client-side
verification — or reimplementing CCF's Merkle leaf construction in JavaScript.
The second option has already been done more than once, and the details that get
missed are exactly the ones that matter: the claims-digest binding, the
`kid`-to-key-material check, and the distinction between a check that failed and
a check that never ran.

## Design

**Synchronous.** Built with `crypto_pure_rust`, not `crypto_webcrypto`. WebCrypto
is async, which would make `verify_statement` async and push `await` through
every caller for no gain — the pure-Rust backend verifies these statements in
single-digit milliseconds.

**No verdicts.** The API returns facts, never an `isValid` boolean. "Valid" means
something different to a deployment gate than to someone browsing a ledger, so
the judgement belongs to the consumer. In particular a statement whose only
receipt fails is *unproven*, not *disproven*, and an API that collapses those
into one boolean cannot express the difference.

**JSON strings, not serde.** Mapping to JSON lives here rather than in
`scitt-receipt`, so the core keeps its dependency boundary (enforced by the
`boundary` CI job) and gains no serde derives on account of a browser consumer.
`scitt-verifier` keeps its own mapping in `report.rs` for the same reason.

## Building

Requires `wasm-pack` and the `wasm32-unknown-unknown` target.

```sh
rustup target add wasm32-unknown-unknown

# For the Node conformance harness
wasm-pack build --target nodejs --out-dir pkg-node --release

# For browsers
wasm-pack build --target web --out-dir pkg-web --release
```

On Windows without Visual Studio, use the GNU toolchain — the wasm target still
needs a *host* linker for build scripts and proc-macros:

```sh
rustup toolchain install stable-x86_64-pc-windows-gnu
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'
```

`Cargo.toml` passes `--enable-bulk-memory` to `wasm-opt`. Without it, the
`wasm-opt` bundled with wasm-pack rejects the bulk-memory operations that
current rustc emits by default.

## Testing

```sh
wasm-pack build --target nodejs --out-dir pkg-node --release
node tests/corpus.node.mjs
```

The harness runs the fixtures in `corpus/` through the real JavaScript boundary
and asserts the pinned cross-implementation values, including the four negative
cases. It caught a double-hashing bug in this wrapper and a documentation error
in `corpus/README.md` that the Rust suite could not see, because both sides of
the boundary have to agree for the pinned digests to come out right.

## API

| Export | Returns |
|---|---|
| `verifyStatement(statement, keySet, trustedRoots?)` | Facts about the statement and every receipt, including `chainValidation` for the signer's certificate chain |
| `verifyStatementWithServiceCert(statement, keySet, serviceCertPem, trustedRoots?)` | The same facts, using only the key set entry bound to the service certificate; for a key set fetched over a channel the page cannot authenticate |
| `evaluatePolicy(statement, keySet, policy, now, trustedRoots?, serviceCertPem?)` | One outcome per assertion in a caller-supplied policy |
| `bindArtifact(statement, artifact, mode, artifactName)` | Whether the statement is about *this* file |
| `inspectStatement(statement)` | Structure only, with no trust material and therefore no evidence |
| `statementPayload(statement)` | The payload as content, or a digest declared as one |
| `decodeClaim(statement, path, encoding)` | One encoded string claim in a JSON payload, decoded, with the SHA-256 of the decoded bytes |
| `claimDigest(statement)` | The digest a receipt commits to |
| `describeReceipt(receipt)` | A standalone receipt's contents |
| `describeCertificate(der)` | A single certificate's contents |
| `version()` | The crate version |

All return JSON strings. Errors are thrown as JavaScript exceptions.

`trustedRoots` is optional PEM text holding one or more `CERTIFICATE` blocks.
The chain is always validated; without roots it is validated only up to the
root the statement itself carries, and `chainValidation.anchoredExternally` is
`false` — a consistent chain, not an identified signer, because anyone can mint
a root. With roots, a chain that does not reach one is `invalid`. An empty
string or a PEM with no certificate in it throws rather than being read as "no
roots". `chainValidation.outcome` is `valid`, `invalid`, `insufficient` (too
few certificates to evaluate) or `unsupported` (an algorithm this build does
not validate, such as an ECDSA-signed chain), and has the same shape as the
CLI's `certificateChain` record.

Passing `serviceCertPem` to `evaluatePolicy` restricts the key set the same way
`verifyStatementWithServiceCert` does; a key set with no key bound to the
certificate throws rather than evaluating policy over unchecked receipts.

`decodeClaim` takes a path in the same syntax as the CLI's `--decode`, such as
`['security-policy-base64']`, and an encoding of `base64` or `base64url`. It
never guesses the encoding and never decodes a claim it was not asked for.
Decoding is not verification: the bytes are only as trustworthy as the
statement that carries them.

`now` is a whole number of seconds since the Unix epoch —
`Math.floor(Date.now() / 1000)`, or a fixed value for a reproducible run. It is
a parameter because the core does not read the clock, so freshness is the
caller's input rather than the library's assumption.

`mode` is likewise a parameter, and `bindArtifact` never infers it from the
statement. Choosing `payload-digest` for the caller because the statement
happens to be a hash envelope would report a relationship the operator never
asserted. It is `"payload-bytes"` or `"payload-digest"`; anything else throws
rather than being guessed at.

`bindArtifact` has three outcomes, and the third carries the weight:
`bound`, `mismatch`, and `cannotCompare`. The last one means the question could
not be answered — a detached payload, a mode that does not fit, a hash this
build cannot compute. It is a fact about the comparison, not about the
artifact, and rendering it as a failure accuses an operator of shipping the
wrong file when the fault was in the request.

## What this crate will not tell you

There is no `isValid`, and `evaluatePolicy` returns no verdict — only one
`outcome` per assertion, over a policy the caller supplied. Combining those
outcomes into a decision is the consumer's job: `scitt-verifier` does it in
`decide()` for the terminal, and a page does it for a browser. That is why
depending on `scitt-policy` does not put an opinion in this bundle — the
opinion is in the policy document, which arrives from outside.
