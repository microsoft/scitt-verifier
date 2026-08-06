# Conformance corpus

Fixtures and policies used by the test suite, and a reference for anyone
implementing SCITT receipt verification independently.

## Fixtures

| File | What it is |
|---|---|
| `transparent-statement.cose` | A genuine transparent statement from Microsoft Signing Transparency: PS256, a four-certificate chain, and one CCF receipt |
| `tampered-statement.cose` | The same statement with a byte flipped in the signed region |
| `payload-tampered.cose` | The same statement with a modified payload — the receipt is untouched and still valid *for the original statement* |
| `artifact.bin` | The 21-byte artifact the genuine statement's payload equals — `Hello from MST Team\r\n`, **CRLF included** |
| `bad-artifact.bin` | A different artifact, for the negative binding case |
| `musa-mst-july-scitt-keys.cbor` | The transparency service's signing keys, as a COSE_KeySet |
| `stale-scitt-keys.cbor` | A key set from before a rotation — parses fine, contains the wrong kid |

`payload-tampered.cose` is the most instructive of these. Its receipt is
genuine, its inclusion proof is valid, and its root signature verifies. It is
still not evidence about this payload, because the claims digest no longer
matches. Any implementation that omits the binding check will accept it.

Every file here is exact bytes from a transparency service, so `.gitattributes`
marks `*.cose`, `*.cbor`, and `*.bin` as binary. This is not cosmetic:
`artifact.bin` is pure ASCII ending in CRLF, and without that rule git will
classify it as text and rewrite the line ending on checkout, changing its length
and breaking the binding check. `fixtures_are_byte_exact` in the acceptance
suite fails loudly if that ever happens again.

`stale-scitt-keys.cbor` exercises the other distinction worth defending: a
rotated key must produce a different outcome from a forged artifact. One is an
operational chore, the other is an incident, and a verifier that reports them
identically will train its users to ignore both.

## Pinned values

Independently confirmed against the .NET prototype and `pyscitt`:

| Property | Value |
|---|---|
| Signed statement length | 8462 bytes |
| Claim digest (SHA-256) | `5207494c12c986e33324c602e535717f67f0a6b56235f413e4a07d4d66d59565` |
| Merkle root | `f369f5f4ce1e2bf6aa120e7f86e907130ede4ed75944e663d4c7b0a14da35993` |
| Statement algorithm | PS256 (COSE −37) |
| Receipt algorithm | ES256 (COSE −7) |

These are asserted in `crates/scitt-receipt/tests/conformance.rs`. **A failure
there is not a test to update.** If the claim digest changes, the definition of
"the same statement" has changed, and every receipt ever issued against the old
definition is affected.

## Policies

| File | Purpose |
|---|---|
| `minimal.json` | The smallest policy that is not empty. Too weak for production — it accepts any transparency service |
| `fixture-mst.json` | Matches the committed fixture. Used by the conformance suite |
| `wrong-issuer.json` | Scoped to a service the fixture was not registered with. Must fail with exit 2 |
| `example-release-gate.json` | A starting point for a real deployment gate |

## Reusing this corpus

The fixtures are real bytes from a real transparency service, not synthesised.
If you are implementing verification independently — in TypeScript for a browser,
in Go, in another language — these are useful as a cross-implementation check.
The pinned digests above are the values to reproduce.
