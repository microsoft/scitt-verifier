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
| `verifyStatement(statement, keySet, issuer?)` | Facts about the statement and every receipt |
| `inspectStatement(statement)` | Structure only, with no trust material and therefore no evidence |
| `claimDigest(statement)` | The digest a receipt commits to |
| `describeReceipt(receipt)` | A standalone receipt's contents |
| `describeCertificate(der)` | A single certificate's contents |
| `version()` | The crate version |

All return JSON strings. Errors are thrown as JavaScript exceptions.
