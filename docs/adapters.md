# Resource adapters

Statement verification and relying-party policy evaluation do not require a
resource adapter. An adapter adds a domain-specific comparison between an
accepted statement and evidence about its subject. It cannot turn an
unaccepted statement into a success.

The only implemented adapter is `mst-ledger`. It appraises evidence that ledger
nodes enforce the execution policy embedded in a transparent statement.
Image reproducibility, hardware, and MAA adapters are architectural possibilities,
not supported commands or evidence formats.

## Build and select the MST ledger adapter

```console
cargo build --release --features adapter-mst-ledger
```

The feature is off by default. Select it at runtime with `--adapter mst-ledger`
and an evidence binding mode. A build unable to run the required adapter reports
`cannot-evaluate` rather than ignoring the requirements.

The selector and policy must agree: omitting `--adapter mst-ledger` when the
policy requires it, or selecting it without `adapters.mst-ledger`, is a usage
error rejected before network acquisition. Appraisal runs only after the full
statement verdict passes, not merely after parsing or a valid signature.

## Policy shape

Statement rules stay in `assertions`. MST-specific target, trust inputs, and
binding requirements live together under `adapters.mst-ledger`:

```json
{
  "policyId": "example/ledger-policy-gate",
  "policyVersion": "1",
  "assertions": {
    "issuer": ["example-log.confidential-ledger.azure.com"],
    "statementSubject": { "equals": "example-execution-policy" },
    "receiptCount": 1
  },
  "adapters": {
    "mst-ledger": {
      "target": {
        "host": "example-target.confidential-ledger.azure.com"
      },
      "trust": {
        "uvmIssuer": "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "uvmEku": "1.2.3.4"
      },
      "binding": {
        "path": ["security-policy-base64"],
        "encoding": "base64",
        "maxDecodedBytes": 1048576,
        "nodeCoverage": "all-enumerated",
        "expectNodeCount": 3,
        "uvmFeed": "example-uvm-feed",
        "minUvmSvn": 1,
        "minimumTcb": [
          { "generation": "genoa", "reportedTcb": "0x0101010101010101" }
        ]
      }
    }
  }
}
```

The same example is available as
[`corpus/policies/mst-ledger.json`](../corpus/policies/mst-ledger.json).
This illustrates the schema, **not deployable trust values**; the UVM root
fingerprint is an all-zero placeholder. Replace the
hostnames, signer/subject constraints, UVM root, EKU, feed, SVN, TCB floors,
node count, and claim path with independently approved values for your
environment. Do not learn acceptance thresholds from the evidence being judged.

The old unpublished top-level `ledger` and `trust` fields and
`assertions.bindLedgerPolicy` are removed, not aliases. Move their contents to
`adapters.mst-ledger.target`, `.trust`, and `.binding` respectively. Unknown
adapter names and fields are rejected. Include meaningful statement assertions:
adapter configuration is not a replacement for accepting the statement.

### Target and trust

| Field under `adapters.mst-ledger` | Meaning |
|---|---|
| `target.host` | Ledger being appraised, not necessarily the service that issued the receipt |
| `trust.uvmIssuer` | Bare `did:x509` root reference for the UVM endorsement, without `::` policy components |
| `trust.uvmEku` | Required dotted-OID EKU for the UVM endorsement signer; separate so it cannot be silently dropped from a DID |

The target comes from the reviewed policy, not an adapter-target flag.
`assertions.issuer` and `--ledger` govern **receipt-key acquisition**, not this
target. A receipt service may notarise statements for many unrelated resources.

UVM trust is distinct from statement-signing trust (`--trusted-roots` and
statement assertions) and from receipt-signing keys (`--scitt-keys` or
`--online`). AMD roots are pinned by the attestation dependency; there is no
configurable AMD-root override or debug-disable switch in this schema.

### Binding requirements

| Field under `binding` | Meaning |
|---|---|
| `path` | Non-empty payload claim path, using the same string/index segments as `payloadJson` |
| `encoding` | `base64` or `base64url`; never guessed |
| `maxDecodedBytes` | Optional positive bound on decoded execution-policy size |
| `nodeCoverage` | `all-enumerated`; every node in the evidence must be appraised |
| `expectNodeCount` | Optional positive expected count; detects a smaller-than-expected enumeration |
| `uvmFeed` | Required UVM endorsement feed |
| `minUvmSvn` | Minimum UVM guest SVN, separate from the statement's `minSvn` assertion |
| `minimumTcb` | Non-empty generation-specific floors; each `reportedTcb` is a `0x`-prefixed 64-bit hexadecimal string |
| `expectPolicySha256` | Optional 64-hex-character SHA-256 pin for one exact decoded execution policy |

`minimumTcb` must name the generation of every node it will appraise. A floor
is compared only against a node of the same CPU generation, so one listing only
`milan` establishes nothing about a Genoa node — and, left unchecked, that node
would reach the end of the comparison having passed a check that never ran.
A node whose generation the floor does not name is therefore reported as
cannot-evaluate. Nothing about that node is at fault; the policy configured no
floor applicable to it, which is the same fail-open an empty floor produces.

The comparison digest is derived from the same in-memory statement that passed
verification, not from unauthenticated `inspect` output or a second file read.
`expectPolicySha256` additionally rejects an otherwise accepted statement for
the wrong execution policy.

Coverage is over the nodes enumerated by the evidence. It is not proof that
no other nodes exist; choose `expectNodeCount` when your policy knows the count.

## Live evidence

```console
scitt-verifier verify --statement statement.cose --policy ledger-policy.json \
  --online --adapter mst-ledger --binding-mode live-evidence \
  --save-trust trust-snapshot --save-evidence evidence-snapshot
```

Two acquisitions occur: `--online` obtains keys for acceptable receipts, and
`live-evidence` collects resource evidence from `adapters.mst-ledger.target.host`.
The CLI currently requires `--online` for live evidence; it does not accept a
local receipt-key file in that mode. `--online` by itself never enables resource
appraisal.

For supported Azure Confidential Ledger hosts, the resource's service
certificate is obtained from the public identity service over public Web PKI.
The connection carrying node evidence is pinned to that certificate. The ledger
cannot replace the external anchor with one of its own choosing.

`--save-evidence` writes the collected bundle for replay. Failure to preserve
requested evidence fails the run. An unreachable service is `cannot-evaluate`,
not a finding that its policy is wrong.

`--result` and `--facts` may not name a path inside a `--save-evidence` or
`--save-trust` directory: a verification record written there would overwrite a
bundle file and leave the bundle unreplayable. The combination is refused while
the command line is parsed, so no directory is created and nothing is collected.

## Saved evidence

```console
scitt-verifier verify --statement statement.cose --policy ledger-policy.json \
  --scitt-keys keys.cbor --adapter mst-ledger --binding-mode saved-evidence \
  --evidence evidence-snapshot
```

This path makes no network request. The directory contains `snapshot.json` and
the per-node evidence it names. Use the matching key set from a trust snapshot
for an offline replay of a live run.

The manifest's ledger must match `adapters.mst-ledger.target.host`, but the
manifest is unsigned. Its hostname and collection time are claims. Likewise,
the saved bundle supplies the service certificate used for identity binding:
an attacker can substitute both evidence and its anchor in a self-consistent
bundle. Host matching catches the wrong bundle, not a forged one. A saved
appraisal is therefore weaker than live acquisition with an external anchor.

Bundle file digests detect changed bytes relative to the manifest; they do not
authenticate the manifest, collector, hostname, or collection time. Saving a
live acquisition does not create a signed provenance record. During offline
replay, the verifier cannot re-establish that the saved service certificate
came from the public identity service. Protecting the captured bundle's origin
and integrity remains the relying party's responsibility.

## What a success means

`resource-transparent` (exit 0) requires an accepted statement and the adapter's
decisive checks: ledger identity/key binding, SNP/UVM validation, execution
policy versus `HOST_DATA`, and enumerated-node coverage. A failed requirement
yields `resource-failed` (exit 2); unavailable required evidence yields
`cannot-evaluate` (exit 3).

Freshness and connection binding remain `cannot-evaluate` even on a scoped
resource success. CCF supplies no challenge-response attestation here, and a
load-balanced endpoint does not prove that the report describes the node
serving your connection. A live run reports when evidence was **observed**;
a replay reports the collector's claimed **recorded** time. Neither proves
the current runtime state or the safety of the workload.

Adapter checks appear under `appraisal.checks.adapter`. Always retain their
details and the scope statement with the verdict; see [output](output.md).
The code and dependency boundaries are described in [architecture](architecture.md).
