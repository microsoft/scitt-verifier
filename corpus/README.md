# Conformance corpus

Fixtures and policies used by the test suite, and a reference for anyone
implementing SCITT receipt verification independently.

## Fixtures

| File | What it is |
|---|---|
| `transparent-statement.cose` | A genuine transparent statement from Microsoft Signing Transparency: PS256, a four-certificate chain, and one CCF receipt |
| `tampered-statement.cose` | The same statement with a byte flipped inside the *receipt* — the Issuer's signature over the statement still verifies, but the transparency service's signature over the Merkle root does not |
| `appended-receipt.cose` | The genuine statement with a second, corrupted receipt appended to the unprotected header — no key required, since nothing signs that bucket |
| `payload-tampered.cose` | The same statement with a modified payload — the receipt is untouched and still valid *for the original statement* |
| `artifact.bin` | The 21-byte artifact the genuine statement's payload equals — `Hello from MST Team\r\n`, **CRLF included** |
| `bad-artifact.bin` | A different artifact, for the negative binding case |
| `musa-mst-july-scitt-keys.cbor` | The transparency service's signing keys, as a COSE_KeySet |
| `stale-scitt-keys.cbor` | A key set from before a rotation — parses fine, contains the wrong kid |
| `cbor-header.cose` | A component manifest registered on a second service, carrying a detached supplier signature under a **CBOR-valued text label**, `external-signature`. ES256, a two-certificate chain, one CCF receipt |
| `musa-mst-aug-scitt-keys.cbor` | The second service's keys, for `cbor-header.cose` and `nested-sign1.cose` |
| `nested-sign1.cose` | The same claim in COSE's own shape: a tag-18 COSE_Sign1 with a **detached payload** under the text label `external-statement`. RS256 supplier signature, ES256 envelope, one CCF receipt |

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

`appended-receipt.cose` and `tampered-statement.cose` together pin what a
broken receipt may and may not do. Receipts travel in the unprotected header,
which no signature covers, so anyone who handles the file can append one
without holding a key. If that could flip a verdict, every mirror, registry,
and CI cache would hold a veto over the gate — and the operator would be told
not to deploy an artifact that is provably fine. So `appended-receipt.cose`
still passes (a genuine receipt verifies, and RFC 9943 §7.1 asks for "at least
one"), while `tampered-statement.cose`, whose only receipt fails, is
`cannot-evaluate` rather than `untrusted`: its bytes are exactly what the
Issuer signed, and what is missing is proof of registration. An unproven claim
is not a disproven one.

`cbor-header.cose` covers the case where a header's value is not a scalar. COSE
permits any CBOR under any label, and RFC 9052 makes text labels private use, so
a supplier may put an arbitrary structure in a protected header — here a
detached signature over the same manifest the payload carries, alongside the
algorithm, key id, thumbprint and certificate that describe it. It is the wire
shape CoseSignTool's `--cbph` produces. Two things make it worth committing:
`inspect` has to stay legible when it meets a structure it has no opinion about,
and a `protectedHeaders` path has to reach into one. No other fixture exercises
either, because every container-valued header they carry (`x5t`, `x5chain`) has
a renderer of its own.

Its limits are equally the point. The detached signature is real — RS256 over
the same bytes the payload carries — and `externalSignatures` computes it. What
the fixture cannot establish is *whose* signature it is: the supplier
certificate is self-signed, so subject and issuer name the same throwaway
identity, and pinning either proves only that whoever assembled the fixture
chose that string. That makes it the honest demonstration of the assertion's
ceiling. The two identities are also deliberately unrelated: the envelope is
signed by a load-test identity, while the header's `x5chain` carries a separate,
throwaway supplier certificate generated for this fixture alone. Nothing in this
file corresponds to a real product, part, or signer.

`nested-sign1.cose` carries the same claim in the shape COSE already defines: a
tag-18 COSE_Sign1 under the text label `external-statement`, with its payload
**detached** (`nil`) so the outer statement's bytes are not duplicated. At the
size of a certificate chain the wrapper costs five bytes over the hand-rolled
descriptor — 1,522 against 1,517 — while removing the question the descriptor
cannot answer, since `Sig_structure` names exactly which bytes are covered
instead of leaving it to convention.

It exists because the two shapes are read by different code paths and must not
silently read each other. It also guards a specific defect: the upstream COSE
helper this crate uses for the envelope has no RSA PKCS#1 entry and returns the
same error for "cannot map this algorithm" as for "this signature is wrong", so
routing the nested case through it reported every real RS256 supplier signature
as a forgery. The nested path builds its own `Sig_structure` for that reason,
and this fixture is what proves it.

## Pinned values

Independently confirmed against the .NET prototype and `pyscitt`:

| Property | Value |
|---|---|
| Signed statement length | 8462 bytes |
| Claim digest (SHA-256) | `5207494c12c986e33324c602e535717f67f0a6b56235f413e4a07d4d66d59565` |
| Merkle root | `f369f5f4ce1e2bf6aa120e7f86e907130ede4ed75944e663d4c7b0a14da35993` |
| Statement algorithm | PS256 (COSE −37) |
| Receipt algorithm | ES384 (COSE −35) |

These are asserted in `crates/scitt-receipt/tests/conformance.rs`. **A failure
there is not a test to update.** If the claim digest changes, the definition of
"the same statement" has changed, and every receipt ever issued against the old
definition is affected.

## Policies

| File | Purpose |
|---|---|
| `minimal.json` | The smallest policy that is not empty. Too weak for production — it accepts any transparency service |
| `fixture-mst.json` | Matches the committed fixture. Used by the conformance suite |
| `fixture-mst-unpinned-count.json` | `fixture-mst.json` without `receiptCount`, so the suite can prove the verdict disregards an appended receipt separately from an operator opting in to a count |
| `wrong-issuer.json` | Scoped to a service the fixture was not registered with. Must fail with exit 2 |
| `example-release-gate.json` | A starting point for a real deployment gate |
| `example-dr-pair.json` | A gate for a service running under a primary and a disaster recovery hostname, since `issuer` matching is exact |

The `example-` policies name invented hosts. They are templates to edit, not
policies to run: the two `fixture-` entries and `wrong-issuer.json` are the only
ones that describe the committed fixtures.

## Reusing this corpus

The fixtures are real bytes from a real transparency service, not synthesised.
If you are implementing verification independently — in TypeScript for a browser,
in Go, in another language — these are useful as a cross-implementation check.
The pinned digests above are the values to reproduce.
