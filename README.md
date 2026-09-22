# scitt-verifier

Verify a [SCITT](https://scitt.io) transparent statement and apply **your
relying-party policy**. The CLI checks the statement signature, receipt
inclusion and binding to that statement, then evaluates the rules you supply.
It is offline by default.

The statement is the starting point: it can describe a document, software
artifact, build, or another subject. You do not need a deployed ledger to use
the verifier. Comparing an artifact's bytes or appraising a resource through
an adapter is an explicit, optional step.

**Receipt support today is CCF only**: RFC 9942 COSE receipts using
`CCF_LEDGER_SHA256`, including Microsoft Signing Transparency and self-hosted
[scitt-ccf-ledger](https://github.com/microsoft/scitt-ccf-ledger). General
statement verification does not mean every receipt scheme is implemented.

## Install

Download a binary from [Releases](https://github.com/microsoft/scitt-verifier/releases),
or build from source:

```console
cargo build --release
```

The executable is `target/release/scitt-verifier` (`.exe` on Windows).
The default build does not include the MST ledger adapter; see
[optional adapters](#optional-resource-adapters).
The package is not published to crates.io because of transitive git
dependencies; see [distribution](docs/distribution.md).

## Quick start: statement and policy

From a checkout, verify the committed fixture without a network request:

```console
scitt-verifier verify \
  --statement corpus/fixtures/transparent-statement.cose \
  --scitt-keys corpus/fixtures/mst-test-scitt-keys.cbor \
  --policy corpus/policies/fixture-mst.json
```

With a source build, use the executable under `target/release/` or add that
directory to `PATH`. The expected verdict is `statement-transparent` (exit 0).
No artifact or running resource was checked. The corpus policy is for this
fixture, not a production trust policy.

For your own statements, obtain and review the service keys and write a policy
for the identities and claims you accept. For example:

```json
{
  "policyId": "example/statement-gate",
  "policyVersion": "1",
  "assertions": {
    "issuer": ["example-log.confidential-ledger.azure.com"],
    "statementSubject": { "equals": "example-release-manifest" },
    "receiptCount": 1,
    "requireKidBoundToKey": true
  }
}
```

`issuer` selects acceptable **receipt issuers**, not statement signers.
Statement identity and payload rules are separate assertions. A policy is
required; the verifier supplies no default trust decision. Unknown fields are
rejected, and a required check that cannot run never becomes a pass.
See the [policy reference](docs/policy.md) for signer, root-pinning, age,
protected-header, and signed JSON payload rules.

To examine a file before writing rules:

```console
scitt-verifier inspect --statement statement.cose
```

`inspect` reports what the file says; it verifies nothing.
Use `verify --format json` for a machine-readable decision, or
`--result result.json` to preserve the verification record.

### Trust material: local or acquired

`--scitt-keys keys.cbor` uses a local COSE_KeySet. Authenticating its source and
reviewing rotations are your responsibility. To acquire keys during
verification instead, replace `--scitt-keys` with `--online`:

```console
scitt-verifier verify --statement statement.cose --policy policy.json \
  --online --save-trust trust-snapshot
```

Receipt-key acquisition contacts only services allowed by
`assertions.issuer`; `--ledger` can narrow that list, never widen it.
`--save-trust` preserves the acquired material for later offline replay.
Acquisition authenticates who served the bytes, not key revocation or freshness.
See [obtaining trust material](docs/trust-material.md), including the separate
`tools/scitt-keys.py` acquisition tool and self-hosted service support.

## Optional artifact binding

To check that a statement describes bytes you hold, add both an artifact and
the binding mode that matches how the statement was signed:

```console
scitt-verifier verify --statement document.cose --policy policy.json \
  --scitt-keys keys.cbor --artifact document.json --binding-mode payload-bytes
```

| Mode | Comparison |
|---|---|
| `none` (default) | No artifact comparison; success is `statement-transparent` |
| `payload-bytes` | The artifact equals the statement payload byte for byte |
| `payload-digest` | The artifact hashes to the RFC 9995 COSE Hash Envelope payload, using its declared algorithm |

A successful artifact comparison yields `artifact-transparent`. Binding is
never inferred from a filename, content type, or URL; the wrong mode is
*cannot compare*, not evidence of tampering. Neither mode judges the quality
or safety of those bytes.

## Optional resource adapters

An adapter can relate an accepted statement to evidence about its subject.
The only implemented adapter is `mst-ledger`: it compares an execution policy
embedded in the statement with policy enforcement evidenced by attested ledger
nodes. It is not required for ordinary statement or artifact verification.

Build it explicitly:

```console
cargo build --release --features adapter-mst-ledger
```

Select it with `--adapter mst-ledger` and either `--binding-mode saved-evidence`
or `--binding-mode live-evidence`. Requirements live under
`adapters.mst-ledger` in the relying-party policy.

**Receipt-key acquisition and resource acquisition are distinct.** `--online`
alone fetches receipt keys, not resource evidence. `live-evidence` additionally
collects evidence from the policy's target and currently requires `--online`.
Saved evidence can be appraised entirely offline with local receipt keys.
Neither mode establishes attestation freshness or binding to the node serving
your current connection.

See [adapters](docs/adapters.md) for policy shape, commands, trust inputs, and
the narrower meaning of `resource-transparent`. Image, hardware, and MAA
adapters are not supported features.

## Guarantees and limits

- **No network by default.** Local-key verification opens no socket. Networking
  is isolated in `scitt-network`; the core and pure adapter perform no I/O.
- **Facts and acceptance are separate.** A valid signature proves possession
  of a key, not a person's identity. Supported certificate chains are validated,
  but an embedded root establishes only internal consistency. Supply independent
  `--trusted-roots` or require an independently selected root fingerprint in
  policy; certificate-name substrings are not a substitute.
- **A receipt binds registration to this statement.** It does not establish
  public access to the ledger, honest service operation, artifact safety, or
  the current state of a running deployment.
- **Missing checks are not successes.** Unsupported input and unavailable
  evidence are distinguished from failed checks. `appraisal.notChecked`,
  `trust.limitations`, and adapter checks disclose the scope even on success.
- **No revocation checking.** `--online` does not change that. Age constraints
  run only when requested by policy; `did:x509` claims are not automatically
  resolved against the signing chain.

For algorithm, certificate-path, and evidence limitations, read
[limitations](docs/limitations.md). Trust in the transparency service and the
signer remains a relying-party decision, not something registration settles.

## Supported receipt schemes

The vocabulary follows [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html);
receipt envelopes follow [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html).
The implemented proof format is narrower:

| Verifiable data structure | Status |
|---|---|
| `CCF_LEDGER_SHA256` (2) | Supported; [CCF receipt profile draft](https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/), registration requested, not yet assigned |
| `RFC9162_SHA256` (1) | Not supported; refused with `UnsupportedVds` |

Other VDS values are refused, not interpreted as CCF proofs. In particular,
RFC 9162 receipts cannot be verified by this build.

## Exit codes and verdicts

| Code | Verdict | Meaning |
|---|---|---|
| 0 | `statement-transparent` | Statement verified and policy satisfied; no artifact checked |
| 0 | `artifact-transparent` | Also matched the supplied artifact using the declared mode |
| 0 | `resource-transparent` | Also satisfied the adapter's scoped resource requirements |
| 1 | `untrusted` | Statement cryptography or artifact binding failed |
| 2 | `policy-failed` | Relying-party statement rules rejected the statement |
| 2 | `resource-failed` | An adapter requirement was not met |
| 3 | `cannot-evaluate` | Required verification could not be completed; **not a pass** |
| 4 | `usage-error` | Invalid invocation or input |

Require both exit 0 **and the verdict appropriate to your task**. A statement
success cannot substitute for an artifact comparison or a resource appraisal.
The [output contract](docs/output.md) defines diagnostics, check states, and
the `scitt-verifier/result/v0` record. The CLI and record shape remain unstable
before v1.0; pin releases in automation.

## Pipeline use

```yaml
- uses: microsoft/scitt-verifier@v0.4.0
  with:
    statement: document.cose
    artifact: document.json
    binding-mode: payload-bytes
    scitt-keys: .well-known/scitt-keys.cbor
    policy: .github/policies/release-gate.json
```

See [examples](examples/) for GitHub Actions and Azure Pipelines.
The Azure Pipelines example uses `script:`/`bash:` so a non-zero native exit
code fails the task; do not replace it with a PowerShell task that ignores
`$LASTEXITCODE`.

## Documentation and layout

| Guide | Contents |
|---|---|
| [Policy](docs/policy.md) | Statement assertions and namespaced adapter requirements |
| [Trust material](docs/trust-material.md) | Keys, acquisition, provenance, and rotation |
| [Adapters](docs/adapters.md) | Optional MST ledger evidence appraisal |
| [Output](docs/output.md) | Verdicts, check states, and JSON record |
| [Limitations](docs/limitations.md) | What this build cannot establish |
| [Architecture](docs/architecture.md) | Core, policy, network, adapter, and CLI boundaries |
| [Distribution](docs/distribution.md) | Build and packaging choices |

```text
crates/scitt-receipt       Parsing, crypto, receipts, and byte binding; no I/O.
crates/scitt-policy        Statement rules and typed adapter requirements.
crates/scitt-network       Network acquisition; no acceptance decisions.
adapters/mst-ledger        Pure MST ledger appraisal (scitt-adapter-mst-ledger).
crates/scitt-verifier      CLI orchestration, reporting, and exit codes.
crates/scitt-wasm          Browser bindings and demo.
corpus/                   Conformance fixtures and example policies.
examples/                 Pipeline samples.
tools/                    Standalone trust-material acquisition.
```

## Contributing and licence

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues through
[SECURITY.md](SECURITY.md). MIT licence: [LICENSE](LICENSE).
This project reuses MIT-licensed components from
[microsoft/TEE-Attestation-Verification](https://github.com/microsoft/TEE-Attestation-Verification).
