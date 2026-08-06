# scitt-verifier

A small, offline command-line tool that answers one question:

> **Was this artifact registered on a transparency service, and does the receipt
> actually describe the thing I am about to deploy?**

It verifies [SCITT](https://scitt.io) transparent statements backed by a
[CCF](https://github.com/microsoft/CCF) ledger — including
[Microsoft Signing Transparency](https://learn.microsoft.com/azure/confidential-ledger/)
and self-hosted
[scitt-ccf-ledger](https://github.com/microsoft/scitt-ccf-ledger) deployments.

```console
$ scitt-verifier verify \
    --statement sbom.spdx.json.cose \
    --artifact  sbom.spdx.json \
    --binding-mode payload-bytes \
    --scitt-keys .well-known/scitt-keys.cbor \
    --policy     release-gate.json

Verdict: verified (exit 0)
```

## Why this exists

A signature tells you **who** produced an artifact. It does not tell you that
anyone *else* can see that they did.

If an attacker obtains a signing key, they can sign a malicious build and it
will validate perfectly. Nothing about the signature reveals that it was made
outside your release process. A **transparency service** closes that gap: the
signed statement is registered on an append-only, publicly verifiable ledger,
and the resulting **receipt** proves the registration happened. A signature made
in secret can no longer pass as a signature made in public.

That only helps if somebody checks the receipt. This is the tool that checks it.

### What makes this different from a signature check

| Check | A signature verifier says | `scitt-verifier` says |
|---|---|---|
| Signature | valid | valid |
| Registered on a ledger | — | yes, at this index, at this time |
| Receipt is about **this** statement | — | yes, the claims digest matches |
| Statement is about **this** artifact | — | yes, and here is how that was established |
| Issuer is one you accept | — | yes, per *your* policy document |
| What was **not** checked | — | listed explicitly, including on success |

The third row is the one that gets skipped. A receipt with a flawless inclusion
proof that commits to a *different* statement is real, valid evidence — about
something else. Verifying it and stopping there is a convincing way to prove
nothing.

## Design commitments

These are constraints, not aspirations. Each has a test that fails if it erodes.

**Offline by default.** Verification never opens a socket. The trust material is
an input you commit to your repository. A gate that phones home is a gate that
fails during an outage, and one that can be steered by whoever controls the
network.

**No prerequisites.** A single static binary. No runtime to install on the build
agent, and nothing that changes behaviour when the agent image is updated.

**Binding is declared, never inferred.** The tool will not guess which artifact a
statement describes from a filename or a content type. You say `--binding-mode`,
or the evidence records that no binding was established.

**A policy is always required.** There is no default policy, because a default
would be this tool making a trust decision on your behalf. Whether
`did:x509:0:sha256:…` is an identity you accept is not knowable here.

**Unimplemented options are refused, not ignored.** Pass a flag this build does
not implement and it exits 4. A gate that silently skips a renamed check is
worse than no gate, because it reports success.

**"I cannot tell" is a distinct answer.** Exit 3 means the tool could not
answer — usually stale trust material. It is not folded into "pass" and not
folded into "compromised", because the response to each is different.

**What was not checked is reported, always.** Including on success. A green
result that quietly skipped the artifact binding is more dangerous than a red
one, because nobody goes looking for the caveat.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Verified, policy satisfied | Proceed |
| 1 | Cryptographic or binding failure | **Stop.** Treat as an incident |
| 2 | Genuine, but your policy rejected it | Review the policy or the artifact |
| 3 | Could not be evaluated | Refresh trust material; do not proceed |
| 4 | Usage or input error | Fix the invocation |

Exit 3 is not a pass.

## Installing

Download a binary from [Releases](https://github.com/microsoft/scitt-verifier/releases),
or build from source:

```console
cargo build --release
```

Note that `scitt-verifier` is not published to crates.io: it depends
transitively on a formally verified CBOR parser that is distributed by git, and
crates.io does not permit git dependencies. See [docs/distribution.md](docs/distribution.md).

## Using it in a pipeline

GitHub Actions:

```yaml
- uses: microsoft/scitt-verifier@v0
  with:
    statement: sbom.spdx.json.cose
    artifact: sbom.spdx.json
    binding-mode: payload-bytes
    scitt-keys: .well-known/scitt-keys.cbor
    policy: .github/policies/release-gate.json
    issuer: your-ledger.confidential-ledger.azure.com
```

Azure Pipelines: see
[`examples/azure-pipelines-deploy-gate.yml`](examples/azure-pipelines-deploy-gate.yml).
**Use `script:` or `bash:`, never `powershell:`** — the PowerShell task does not
fail on a non-zero exit code from a native program, which silently disables the
gate.

Full examples live in [`examples/`](examples/).

## Policy documents

```json
{
  "policyId": "contoso/release-gate",
  "policyVersion": "3",
  "assertions": {
    "issuer": ["contoso.confidential-ledger.azure.com"],
    "signerIssuerContains": "Contoso Corporation",
    "minReceipts": 1,
    "maxAgeDays": 90,
    "requireKidBoundToKey": true
  }
}
```

An assertion this build does not recognise is a hard error, so a policy written
for a newer version cannot appear to pass on an older binary. An assertion that
*cannot* be evaluated — a minimum SVN against a statement that declares none —
resolves to `cannotEvaluate`, never to `pass`.

See [docs/policy.md](docs/policy.md) for the full assertion reference.

## Repository layout

```
crates/scitt-receipt    Verification core. No I/O, no clock, no verdicts.
crates/scitt-policy     Relying-party policy evaluation.
crates/scitt-verifier   The CLI.
corpus/                 Conformance fixtures and example policies.
action.yml              Composite GitHub Action.
examples/               GitHub Actions and Azure Pipelines samples.
```

`scitt-receipt` is deliberately isolated so it can be embedded elsewhere — a
browser-based ledger explorer, another service — without inheriting a CLI's
assumptions. CI enforces the boundary. See
[docs/architecture.md](docs/architecture.md).

## Status

Early. The verification core is exercised against real Microsoft Signing
Transparency statements and its digests are cross-checked against two
independent implementations, but the CLI surface should be considered unstable
until v1.0. Known gaps are listed in [docs/limitations.md](docs/limitations.md)
and reported at runtime in the `notChecked` field of every evidence record.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).

This project reuses the `cose` and `crypto` crates from
[microsoft/TEE-Attestation-Verification](https://github.com/microsoft/TEE-Attestation-Verification),
also MIT-licensed.
