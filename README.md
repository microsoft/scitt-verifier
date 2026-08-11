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

PASS artifact-transparent

Policy document:     contoso/release-gate v7
Trust material:      unsigned SCITT key set, scoped to contoso.confidential-ledger.azure.com
Statement signature: pass
Receipt inclusion:   pass
Artifact binding:    pass
Policy decision:     pass
```

Drop `--artifact` and the verdict becomes `statement-transparent` — still exit
0, but a narrower claim, because nothing was checked against the bytes you are
deploying. The two are kept apart on purpose; see
[docs/output.md](docs/output.md).

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

## What it can and cannot tell you

Questions it answers:

- **Is this file the exact thing that was registered?** The one that matters
  most. You get this answer only if you pass `--artifact`; without it the tool
  says so rather than implying it.
- **Did a transparency service really record this, or is someone just claiming
  it did?** The receipt has to verify against trust material you supplied.
- **Has anything been altered since registration?** Statement, payload, or
  receipt.
- **Which service vouched for it** — and with `--issuer`, whether that is the
  one you meant, rather than any ledger that happens to be in your key file.
- **Who signed it, and does that satisfy my rules?** Kept deliberately separate
  from the cryptography: "valid, but I don't accept this signer" (exit 2) is a
  different situation from "this does not verify" (exit 1).
- **Can I deploy this right now?** One verdict, decidable by a script.
- **What is actually inside this thing?** `inspect`, with no trust claim
  attached.
- **What did you not check?** The `appraisal.notChecked` list — reported on success too.

Questions it does **not** answer, and will not pretend to:

- **Is the artifact any good?** Transparency proves an artifact was recorded —
  not that it is safe, unbackdoored, or fit to ship. This is an audit trail, not
  a scanner. A malicious build that was properly registered passes.
- **Is the signer trustworthy?** It proves *which* key signed, not that the key
  belongs to who you think. The certificate chain is not validated.
- **Has this been revoked, or is it too old to trust?** The tool is offline and
  will not guess. Age is only checked if your policy asks.
- **Are my trust keys legitimate?** It uses the key file you hand it. Where that
  file came from is your responsibility — which is why the output labels it an
  *unsigned* SCITT key set.

In one line: it answers **"is this the thing that was recorded, and does it meet
my rules?"** — never "is this thing safe?"

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
or the record says that no binding was established.

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

## Standards

The tool implements the SCITT architecture defined in
[RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html). Its vocabulary is the
RFC's — Signed Statement, Receipt, Transparent Statement — and so is the output
document's structure. The separation this tool insists on between verifying a
receipt and applying a relying-party policy is the RFC's separation, not one we
invented.

Receipts are parsed as [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html)
COSE receipts: header 394 carries receipts in the Signed Statement's
*unprotected* bucket, 395 the verifiable data structure, 396 the verifiable data
proofs, and −1 within that bucket the inclusion proofs.

Where the header says which Merkle construction to verify, one algorithm is
supported:

| Verifiable data structure | Defined by | Supported |
|---|---|---|
| `CCF_LEDGER_SHA256` (2) | [draft-ietf-scitt-receipts-ccf-profile-04](https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/) — registration requested, not yet assigned | Yes |
| `RFC9162_SHA256` (1) | RFC 9942 §5.1 | **No** — refused with `UnsupportedVds` |

So: the envelope is RFC 9942, but the only proof format verified today is the
CCF profile's, which is still an Internet-Draft. If you hold receipts from a
Sigstore-style RFC 9162 log, this build cannot verify them — it rejects the
receipt rather than misreading one proof format as another. That gap is
[tracked](docs/limitations.md#verifiable-data-structures-other-than-ccf_ledger_sha256)
and is the next substantial piece of verification work.

## Exit codes and verdicts

| Code | Verdict | Meaning | What to do |
|---|---|---|---|
| 0 | `artifact-transparent` | The artifact you supplied was registered | Proceed |
| 0 | `statement-transparent` | Transparent, but no artifact was checked | Proceed only if you meant to skip binding |
| 1 | `untrusted` | Cryptographic or binding failure | **Stop.** Treat as an incident |
| 2 | `policy-failed` | Genuine, but your policy rejected it | Review the policy or the artifact |
| 3 | `cannot-evaluate` | Could not be evaluated | Refresh trust material; do not proceed |
| 4 | `usage-error` | Usage or input error | Fix the invocation |

Exit 3 is not a pass.

**Gate on the verdict, not on exit 0.** Both success verdicts exit 0 so that
teams can adopt the gate before they wire up artifact binding — but only
`artifact-transparent` says anything about the bytes being deployed. The full
contract, including diagnostics, check states, and the evidence schema, is in
[docs/output.md](docs/output.md).

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

## Obtaining the transparency service keys

`--scitt-keys` takes the service's signing keys as a COSE_Key_Set. The verifier
never fetches them: acquisition is a separate, occasional step whose output you
commit and review.

```console
pip install cryptography cbor2
python tools/scitt-keys.py fetch \
  --issuer your-ledger.confidential-ledger.azure.com \
  --out    .well-known/scitt-keys.cbor
```

This pins TLS to the service certificate published by the Azure identity
service, requires the service's own key to appear in the key set it serves, and
writes a provenance sidecar so the key set is reviewable in a pull request. It
needs no credentials. It refuses to run in CI unless you declare it a scheduled
rotation job.

See [docs/trust-material.md](docs/trust-material.md), including the
rotation-as-a-pull-request pattern and support for self-hosted ledgers.

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
tools/                  Trust-material acquisition. Not part of the gate.
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
and reported at runtime in the `appraisal.notChecked` field of every
verification record.

The output contract changed after v0.1.0: `verified` was replaced by the two
artifact-aware verdicts, the record was restructured around the RFC 9943
vocabulary, and `--evidence` became `--result`. The schema is now
`scitt-verifier/result/v0`. If you pinned against v0.1.0 output, read
[docs/output.md](docs/output.md) before upgrading.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).

This project reuses the `cose` and `crypto` crates from
[microsoft/TEE-Attestation-Verification](https://github.com/microsoft/TEE-Attestation-Verification),
also MIT-licensed.
