# Resource adapters

Statement verification and relying-party policy evaluation do not require a
resource adapter. An adapter adds a domain-specific comparison between an
accepted statement and evidence about its subject. It cannot turn an
unaccepted statement into a success.

Four adapters are implemented:

- `azure-confidential-ledger` appraises evidence that ledger nodes enforce the
  execution policy embedded in a transparent statement. It is behind a build
  feature; see [the MST ledger adapter](#build-and-select-the-mst-ledger-adapter).
- `image-reproduction` compares a rebuild you supply with the reproduction
  record a statement commits to. Every build has it; see
  [image reproduction](#image-reproduction).
- `azure-attestation` compares MAA certificate evidence with the execution
  policy in an accepted statement. It is feature-gated and establishes a
  scoped SNP/HOST_DATA comparison, not MAA service identity or enforcement;
  see [MAA](#microsoft-azure-attestation-maa).
- `amd-snp-device` binds a fresh SEV-SNP report to the device a hardware BOM
  statement names. It is behind a build feature; see
  [AMD SNP device](#amd-snp-device).

A policy configures at most one adapter, and a run selects at most one. A
policy naming two is refused as a usage error: split it into one policy per
adapter.

## Microsoft Azure Attestation (MAA)

Build with `cargo build --release --features adapter-azure-attestation`.
Select `--adapter azure-attestation`. This is the only CLI selector;
`adapter-azure-attestation` is the Cargo feature name, not a selector.
Like the ledger adapter, it runs only
after the complete statement verdict passes, and only against that accepted
in-memory statement.

The supported certificate profile is `acisevsnp`. MAA's `/certs` response
contains large certificates with these extensions:

| OID | Value |
|---|---|
| `1.3.6.1.4.1.311.105.1000.1` | DER UTF8String containing JSON evidence: `SnpReport`, `VcekCertChain`, `Endorsements` |
| `1.3.6.1.4.1.311.105.1000.2` | DER UTF8String `acisevsnp` |

`SnpReport` and `VcekCertChain` use base64url. `VcekCertChain` decodes to the
AMD PEM chain. The adapter authenticates the SNP report signature and AMD
collateral with the pinned attestation library. Every evidence-bearing
certificate must be assessed; ordinary certificates without this evidence
are outside the attested scope. `Endorsements`, including its UVM
endorsement, is not interpreted or verified.

The SHA-256 of the exact decoded execution-policy bytes is compared with
authenticated `HOST_DATA`. This is a digest comparison, not a comparison with
the base64 text and not a hash of reformatted policy text. The claim lives in
the signed statement's payload; the receipt authenticates that statement.

Three checks must pass: `snp-validation`, `cce-policy-host-data`, and
`maa-certificate-coverage`. Success means the AMD-authenticated reports in
the supplied certificate evidence contain the expected `HOST_DATA`.
**It does not mean the MAA endpoint runs or enforces this policy.** Neither
the certificate's actual public key nor its JWK `kid` is bound to the report,
and no UVM endorsement, guest enforcement, relying-party TCB/SVN threshold,
freshness or serving-connection binding is established. Those are runtime
limitations, not implicit requirements of this narrow comparison.

The HTTP header `x-ms-maa-service-version` is preserved as unsigned metadata,
not compared as an acceptance requirement. It does not authenticate an
executing build.

### MAA policy and acquisition

```json
{
  "policyId": "example/maa-policy",
  "policyVersion": "1",
  "assertions": {
    "issuer": ["example-log.confidential-ledger.azure.com"],
    "statementSubject": { "equals": "example-attestation-build" },
    "receiptCount": 1
  },
  "adapters": {
    "azure-attestation": {
      "target": { "host": "example.region.attest.azure.net" },
      "binding": {
        "path": ["security-policy-base64"],
        "encoding": "base64",
        "maxDecodedBytes": 1048576
      }
    }
  }
}
```

All example identities are placeholders. Choose acceptable statement signer
and receipt identities independently of the evidence being judged. The adapter
has no configurable UVM or platform-policy requirements; such fields are
refused rather than accepted and skipped. An omitted selector cannot drop a
configured adapter's requirements.
The same schema example is available as
[`corpus/policies/azure-attestation.json`](../corpus/policies/azure-attestation.json).

```console
scitt-verifier verify --statement statement.cose --policy maa-policy.json \
  --online --adapter azure-attestation --binding-mode live-evidence \
  --maa-endpoint "https://example.region.attest.azure.net" \
  --save-trust trust-snapshot --save-evidence maa-snapshot --verbose
```

`--maa-endpoint` is required for live MAA acquisition and takes precedence over
`target.host`, even if the policy names a different host. The policy target is
optional for live acquisition. Omitting the endpoint is a usage error (exit 4);
the policy host is never a live acquisition fallback.
The effective target is reported and saved in the bundle's `targetHost`;
it is an acquisition choice, not authenticated SNP report identity.

Live acquisition makes one bounded HTTPS request to the selected target's
`/certs`, with public Web PKI, no redirects, and no fallback endpoint.
The endpoint must be an HTTPS origin with a lowercase DNS host ending
`.attest.azure.net`, optionally followed by one trailing slash. Credentials,
explicit ports, paths (including `/certs`), queries and fragments are refused.
The flag requires MAA live-evidence mode and `--online`; it is not accepted
for saved replay or another adapter. Receipt-key
acquisition remains separate and governed by `assertions.issuer`.
The policy file must configure `adapters.azure-attestation`; an ACL-only
policy cannot be used for MAA merely by changing the CLI selector.

Saved evidence is a directory containing `maa-evidence.json`: an object with
`schemaVersion: 1`, `targetHost`, `serviceVersion`, and `certs` (the `/certs`
JSON object). Replay it without network access:

```console
scitt-verifier verify --statement statement.cose --policy maa-policy.json \
  --scitt-keys keys.cbor --adapter azure-attestation \
  --binding-mode saved-evidence --evidence maa-snapshot
```

The loader requires a regular file of at most 4 MiB and refuses paths escaping
the evidence directory. On Unix, opening is nonblocking and the opened file's
type is checked again, so a FIFO substituted during opening is also refused.
Saved replay requires policy `target.host` to match the captured `targetHost`.
If a CLI endpoint overrode the policy target during capture, set the replay
policy target to that captured host.
A saved bundle's target and build header are unsigned collector metadata:
replay checks their consistency, not their origin. Neither live nor saved
evidence establishes report freshness, revocation, fleet completeness, or
binding to the serving TLS connection. These gaps are reported at runtime.

### MAA end-to-end success test

The committed MAA snapshot authenticates real SNP reports with matching
HOST_DATA in pure-adapter tests. The existing registered JSON statement
fixture does not contain the matching execution policy, so the CLI tests use
it to exercise missing-claim and HOST_DATA-mismatch outcomes, not a fabricated
success. No synthetic statement, receipt or key set substitutes for a real
registered fixture.

An opt-in CLI test exercises the complete offline success path, including
statement signature, receipt, policy, SNP authentication and HOST_DATA
comparison. Set `SCITT_MAA_E2E_DIR` to a directory containing a genuine
`statement.cose`, its independently selected receipt `keys.cbor`, a
`policy.json` configuring the matching claim and saved target, and an
`evidence/maa-evidence.json` bundle. Then run:

```console
cargo test -p scitt-verifier --features adapter-azure-attestation --test maa genuine_matching_statement_and_saved_maa_evidence_exit_zero -- --ignored
```

The test requires exit 0, `resource-transparent`, passing statement checks
and all three passing adapter checks; missing inputs fail rather than skip.
It is ignored by default because no matching registered statement is in the
corpus. Keep customer or partner inputs outside the repository.

## Build and select the MST ledger adapter

```console
cargo build --release --features adapter-azure-confidential-ledger
```

The feature is off by default. Select it at runtime with `--adapter azure-confidential-ledger`
and an evidence binding mode. A build unable to run the required adapter reports
`cannot-evaluate` rather than ignoring the requirements.

The selector and policy must agree: omitting `--adapter azure-confidential-ledger` when the
policy requires it, or selecting it without `adapters.azure-confidential-ledger`, is a usage
error rejected before network acquisition. Appraisal runs only after the full
statement verdict passes, not merely after parsing or a valid signature.

## Policy shape

Statement rules stay in `assertions`. MST-specific target, trust inputs, and
binding requirements live together under `adapters.azure-confidential-ledger`:

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
    "azure-confidential-ledger": {
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
[`corpus/policies/azure-confidential-ledger.json`](../corpus/policies/azure-confidential-ledger.json).
This illustrates the schema, **not deployable trust values**; the UVM root
fingerprint is an all-zero placeholder. Replace the
hostnames, signer/subject constraints, UVM root, EKU, feed, SVN, TCB floors,
node count, and claim path with independently approved values for your
environment. Do not learn acceptance thresholds from the evidence being judged.

The old unpublished top-level `ledger` and `trust` fields and
`assertions.bindLedgerPolicy` are removed, not aliases. Move their contents to
`adapters.azure-confidential-ledger.target`, `.trust`, and `.binding` respectively. Unknown
adapter names and fields are rejected. Include meaningful statement assertions:
adapter configuration is not a replacement for accepting the statement.

### Target and trust

| Field under `adapters.azure-confidential-ledger` | Meaning |
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

Coverage counts **distinct attested keys**, not `node_id` values. `node_id` is
a label the collector chose, and a saved bundle is unsigned, so the cheapest
way to appear to satisfy a three-node requirement is to present one agreeing
node three times under different names. The key counted is the SHA-256 of the
node's own public key that CCF places in the first 32 bytes of `REPORT_DATA`,
which the hardware signature authenticates; coverage fails when fewer distinct
keys were attested than nodes were presented.

## Live evidence

```console
scitt-verifier verify --statement statement.cose --policy ledger-policy.json \
  --online --adapter azure-confidential-ledger --binding-mode live-evidence \
  --save-trust trust-snapshot --save-evidence evidence-snapshot
```

Two acquisitions occur: `--online` obtains keys for acceptable receipts, and
`live-evidence` collects resource evidence from `adapters.azure-confidential-ledger.target.host`.
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
  --scitt-keys keys.cbor --adapter azure-confidential-ledger --binding-mode saved-evidence \
  --evidence evidence-snapshot
```

This path makes no network request. The directory contains `snapshot.json` and
the per-node evidence it names. Use the matching key set from a trust snapshot
for an offline replay of a live run.

The manifest's ledger must match `adapters.azure-confidential-ledger.target.host`, but the
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

Because the bundle is untrusted input, reading it is bounded: the manifest,
each evidence file, and the bundle's total size have fixed ceilings, as does
the number of nodes — checked before any file is opened. Every path named by
the manifest is canonicalised and must remain inside the bundle directory, so a
link out of it is refused before its bytes are read.

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

## Image reproduction

The `image-reproduction` adapter answers one question: *does the rebuild you
supplied match the reproduction record this statement commits to — the same
recorded inputs, and the same ordered filesystem layers?*

It is useful when a publisher registers a statement about how an image was
built, and you, or a runner you control, have rebuilt that image from the
same source. It turns "our rebuild matched" from a log line into a verdict
tied to a statement the publisher signed and a transparency service recorded.

### What it does not establish

- **That the rebuild was independent.** The rebuilt record is whatever you
  hand in. The tool runs no build, and a copy of the published record passes.
  Whoever controls the evidence directory controls this half of the
  comparison.
- **That a published image has these layers**, or that any deployment runs
  them. No registry is contacted and no dm-verity root is derived.
- **That the source is safe.** Reproducibility says the bytes follow from the
  source; it says nothing about the source.

The scope statement in every record says the same, so it survives being
quoted without this page.

### Policy

```json
{
  "policyId": "image-reproduction-example",
  "policyVersion": "1",
  "assertions": {
    "issuer": ["example.confidential-ledger.azure.com"],
    "statementIssuer": { "equals": "did:x509:0:sha256:...::eku:..." }
  },
  "adapters": {
    "image-reproduction": {
      "profile": "mst-tbs",
      "sourceRepository": "https://github.com/microsoft/scitt-ccf-ledger",
      "component": { "app": "mst", "variant": "public" }
    }
  }
}
```

| Field | Meaning |
|---|---|
| `profile` | Which statement claims and record fields mean what. This build understands only `mst-tbs`; any other value makes every check `cannot-evaluate`, never a reading under the wrong rules. |
| `sourceRepository` | The only repository the statement may name. Compared exactly, with no normalisation. |
| `component.app`, `component.variant` | The only component the statement may be about. Compared exactly. One signing identity issues statements for every component and variant it builds, so without this a debug image's statement would satisfy a policy written for the production one. |

All are required and none may be empty. Neither can be set on the command
line. Pin `statementIssuer` as well: the adapter trusts the published record
only because an accepted statement commits to it, so the policy decides whose
statements count.

### Statement payload

The `mst-tbs` profile reads the payload the MST release pipeline registers
for each image (`generate_tbs_payload` in CCFCommon's
`add-snp-policies.sh`). The statement must carry it inline with content type
`application/json`. A detached payload gives `cannot-evaluate`; a payload
whose content type is missing or not JSON fails, since the publisher signed a
statement that is not a reproduction claim.

```json
{
  "schema-version": 2,
  "source": { "commit": "...", "branch": "..." },
  "build": { "id": "...", "number": "..." },
  "component": {
    "app": "mst",
    "variant": "public",
    "image": "<registry>/<repository>@sha256:...",
    "provenance": {
      "source-repository": "https://github.com/microsoft/scitt-ccf-ledger",
      "source-commit": "<40 lowercase hex>",
      "source-date-epoch": 1790269424,
      "version": "0.20.1-0-g00101f7",
      "context-sha256": "<64 lowercase hex>",
      "ccf-version": "7.0.17",
      "reproduction-record-sha256": "<64 lowercase hex>",
      "reproduction-record-uri": "https://github.com/microsoft/scitt-ccf-ledger/releases/download/0.20.1/reproduce.json",
      "image-digest": "sha256:..."
    }
  },
  "security-policy-base64": "...",
  "security-policy-sha256": "..."
}
```

The adapter reads `schema-version`, `component.app`, `component.variant` and
every `component.provenance` field except `image-digest`. The others —
`source`, `build`, `component.image`, `image-digest` and the security policy
— describe the pipeline run and the deployed image, and are not checked.
`reproduction-record-uri` is reported so a reader knows where to fetch the
published record; it is never fetched.

A `schema-version` other than 2 is `cannot-evaluate`: version 1 payloads, and
statements for images built before scitt-ccf-ledger 0.20, carry no
provenance. A missing `component.provenance` on a version 2 payload, a missing
or malformed field, or a component other than the policy's is a failure.
Duplicate keys are refused.

### Evidence

```console
scitt-verifier verify --statement statement.cose --scitt-keys keys.cbor \
  --policy policy.json \
  --binding-mode saved-evidence --adapter image-reproduction --evidence DIR
```

`DIR` holds two files with fixed names:

| File | What it is |
|---|---|
| `published-reproduce.json` | The publisher's reproduction record, byte for byte. |
| `rebuilt-reproduce.json` | The record your rebuild wrote. |

For `mst-tbs` both are the `reproduce.json` written by
scitt-ccf-ledger's reproduction script, `schema_version` 1. Each file is read
within a 64 KiB bound, and a path that resolves outside `DIR` is refused.
`--binding-mode live-evidence` is refused for this adapter: there is nothing
live to collect.

### Checks

All five are required, in this order:

| Name | Passes when |
|---|---|
| `reproduction-claim` | The payload is readable, its `schema-version` is supported, and its `component.app` and `component.variant` are the policy's. |
| `source-repository` | The statement's `source-repository` is the policy's `sourceRepository`. |
| `record-binding` | The SHA-256 of `published-reproduce.json` equals `reproduction-record-sha256`, and its `source_commit`, `scitt_version`, `context_sha256`, `ccf_version` and `source_date_epoch` agree with the statement's `source-commit`, `version`, `context-sha256`, `ccf-version` and `source-date-epoch`. |
| `rebuild-inputs` | The rebuild recorded the same `source_commit`, `scitt_version`, `context_sha256`, `source_date_epoch`, `base_image`, `ccf_version`, `ccf_rpm_sha256`, `ccf_reproduce_sha256` and `tdnf_snapshottime`. |
| `rebuild-layers` | The rebuild's ordered layer digests equal the published record's. |

Input drift fails, even when the layers happen to match: a rebuild from
different inputs is not evidence about the recorded build. `docker_version`,
`buildx_version` and `image_id` may legitimately differ between two builds
with identical layers; a difference is reported as a note and is never
compared. When layers differ, every differing position is reported with its
expected and observed digests, so one inserted layer shows as a difference at
each later position.

A failed check yields `resource-failed` (exit 2). A missing or unreadable
file, or a record in a schema this profile does not read, yields
`cannot-evaluate` (exit 3). Only an accepted statement whose five checks all
pass is `resource-transparent` (exit 0).

## AMD SNP device

The `amd-snp-device` adapter answers one question: *is the chip that signed
this fresh SEV-SNP report the device whose serial number this hardware BOM
statement records?*

It is useful when a manufacturer registers a hardware bill of materials for
each processor, and you want evidence, on the machine itself, that you are
running on the part the statement describes. It turns "this is the chip we
bought" into a verdict tied to a statement the manufacturer signed and a
transparency service recorded.

Build it explicitly:

```console
cargo build --release --features adapter-amd-snp-device
```

### Try it in five minutes

The repository has everything needed to see the adapter work, no hardware
required: a registered hardware BOM (`corpus/fixtures/amd-snp-device/`), a
policy for it, and a public Turin report from the chip that BOM names. From
the repository root:

```console
# 1. Build with the adapter.
cargo build --release --features adapter-amd-snp-device

# 2. Assemble an evidence directory from the public Turin fixture.
fx=adapters/amd-snp-device/tests/fixtures
mkdir -p /tmp/snp-demo
cp $fx/turin_attestation_report.bin /tmp/snp-demo/report.bin
cp $fx/turin_vcek.pem /tmp/snp-demo/vcek.der
cat $fx/turin_kds_ask.pem $fx/turin_kds_ark.pem > /tmp/snp-demo/cert_chain.pem

# 3. Verify.
target/release/scitt-verifier verify \
  --statement corpus/fixtures/amd-snp-device/statement.cose \
  --scitt-keys corpus/fixtures/mst-test-scitt-keys.cbor \
  --policy corpus/policies/amd-snp-device.json \
  --binding-mode saved-evidence --adapter amd-snp-device --evidence /tmp/snp-demo
```

In PowerShell, step 2 is:

```powershell
$fx = 'adapters/amd-snp-device/tests/fixtures'; $ev = "$env:TEMP\snp-demo"
New-Item -ItemType Directory -Force $ev | Out-Null
Copy-Item $fx/turin_attestation_report.bin $ev/report.bin
Copy-Item $fx/turin_vcek.pem $ev/vcek.der
Get-Content $fx/turin_kds_ask.pem, $fx/turin_kds_ark.pem | Set-Content $ev/cert_chain.pem
```

The end of the output:

```text
[5/5] Bind SNP report to the statement's device
  PASS device-claim packaged soc part EXAMPLE-PART-1 revision A0 serial 59790FB1C39F35C1
  PASS snp-report signed by a Turin VCEK that chains to AMD's pinned root, and the VCEK certifies the reported TCB
  PASS tcb-floor Turin reported TCB 0x5100000004010101 meets the floor 0x5100000004010101
  CANNOT EVALUATE freshness no nonce was supplied, so the report could have been produced at any time
  PASS device-binding the statement's serial 59790FB1C39F35C1 is the hardware ID of the chip that signed the report

STOP cannot-evaluate
```

Exit code 3 is the right answer here. The statement, receipt and policy pass,
and the report really was signed by the chip the BOM names, but a public
report can be replayed by anyone, so the tool will not call it fresh. Add a
`nonce.hex` the report was not made for (any 32 bytes of hex) and `freshness`
fails with exit 2. Only evidence collected on the device against a new nonce
can reach exit 0.

### Use it on your own hardware

Three roles are involved. One organisation may play all of them.

| Who | Does what | Produces |
|---|---|---|
| **Producer** (manufacturer or integrator) | Records each processor in a hardware BOM, signs it and registers it on a transparency service | A transparent statement per device |
| **Operator** (on the machine) | Asks the processor for a fresh report | An evidence directory |
| **Verifier** (anywhere) | Runs `scitt-verifier` on the statement and evidence | A verdict |

**1. Producer: write and register the BOM.** The payload is SPDX 3 JSON-LD
with content type `application/spdx+json` (any JSON type works). It must
contain exactly one `hardware_PhysicalHardware` node of the category the
verifier's policy names, and that node's `hardware_serialNumber` must be the
chip's hardware ID in hex: the first 8 bytes of the report's `CHIP_ID` on
Turin, all 64 on Milan and Genoa. The collection script prints it as `chip`.
For example:

```json
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    { "type": "CreationInfo", "@id": "_:creation", "specVersion": "3.0.1" },
    {
      "type": "hardware_PhysicalHardware",
      "spdxId": "urn:example.invalid:part",
      "creationInfo": "_:creation",
      "name": "Example packaged SoC",
      "hardware_partNumber": "EXAMPLE-PART-1",
      "hardware_hardwareVersion": "A0",
      "hardware_serialNumber": "59790FB1C39F35C1",
      "hardware_category": [{ "type": "DefinedType", "typeFromSource": "packaged soc" }]
    }
  ]
}
```

Sign it as a COSE_Sign1 statement and register it like any other; the
operator or verifier then needs the resulting transparent statement (the
`.cose` file with its receipt). `corpus/tools/generate_fixtures.py`
(`hbom_statement`) is a worked example using pyscitt.

**2. Operator: collect evidence on the device.** Today
`tools/collect-snp-evidence.ps1` supports confidential containers. It needs
`crictl` on the host, a command inside the guest (by default
`get-snp-report`) that takes a nonce as hex and prints the SNP report as hex,
and HTTPS access to AMD's Key Distribution Service the first time it sees a
chip:

```powershell
.\tools\collect-snp-evidence.ps1 -ContainerId <id> -OutDir C:\evidence\run1
```

It prints the chip's generation, hardware ID and reported TCB, and writes
`report.bin`, `vcek.der`, `cert_chain.pem` and `nonce.hex`. On a machine
without containers, produce the same four files with any tool that requests
a report with your nonce as `REPORT_DATA`; the verifier authenticates every
byte and does not care how they were gathered. Collect again for every run:
reusing a directory reuses its nonce.

**3. Verifier: write a policy and run.** Start from
`corpus/policies/amd-snp-device.json` and change three things: `issuer` to
your transparency service, `statementIssuer` to the producer's identity, and
`minimumTcb` to the oldest firmware you accept for each generation you run.
The script's `reported TCB` line, and the `tcb-floor` detail of any run,
show the current machine's value in the format the policy takes. Then:

```console
scitt-verifier verify --statement device.cose --scitt-keys keys.cbor \
  --policy policy.json \
  --binding-mode saved-evidence --adapter amd-snp-device --evidence C:\evidence\run1
```

`keys.cbor` is the transparency service's key set; `--online` fetches it
instead (see [trust material](../README.md#trust-material-local-or-acquired)).

### Reading the result

| You see | It means | What to do |
|---|---|---|
| Exit 0, `resource-transparent` | The accepted BOM names the chip that signed this fresh report, at or above your firmware floor | Nothing; this is the pass |
| Exit 3, `freshness` cannot-evaluate, `nonce.hex absent` | The evidence has no nonce, so the report may be old | Collect with the script, which always writes one |
| Exit 2, `freshness` fail | The report was not produced for this nonce: reused or mismatched evidence | Collect again; do not copy evidence between runs |
| Exit 2, `device-binding` fail | The report came from a different chip than the BOM names | Treat as a finding: wrong machine, or wrong statement |
| Exit 2, `tcb-floor` fail | The firmware is older than your floor | Update the machine's firmware, or review the floor |
| Exit 3, `tcb-floor` cannot-evaluate | The policy has no floor for this generation | Add one to `minimumTcb` |
| Exit 2, `device-claim` fail | The statement names no device, or several, of the policy's `category`, or no hex serial | Check the BOM and the `category` value |
| Exit 3, `snp-report` cannot-evaluate | An evidence file is missing | Check the four file names under Evidence below |
| Exit 2 or 4 before step 5 | The statement, receipt or policy failed; the adapter never ran | See [exit codes](../README.md#exit-codes-and-verdicts) |

Add `--format json` for a machine-readable record; each check is in
`appraisal.checks.adapter`.

### What it does not establish

- **What software the guest runs.** The launch measurement is reported as a
  note and not compared with any endorsed value, so a pass says which chip
  answered, not which guest image asked it to. `appraisal.notChecked` lists
  `GuestMeasurementNotAppraised`.
- **That the BOM is true.** The statement's issuer and registration are
  verified; whether the manufacturer recorded the right parts is the
  manufacturer's claim.
- **That serial and hardware ID are one identifier by definition.** The
  profile compares them byte for byte. That they are meant to agree is the
  manufacturer's convention, not something a report or certificate proves.
- **Revocation.** The AMD chain is validated to the pinned root for the
  report's generation; no revocation list is consulted
  (`AmdCertificateRevocationNotChecked`).

### Policy

```json
{
  "policyId": "amd-snp-device-example",
  "policyVersion": "1",
  "assertions": {
    "issuer": ["example.confidential-ledger.azure.com"],
    "statementIssuer": { "equals": "did:x509:0:sha256:...::eku:..." }
  },
  "adapters": {
    "amd-snp-device": {
      "profile": "spdx3-hbom",
      "category": "packaged soc",
      "minimumTcb": [
        { "generation": "turin", "reportedTcb": "0x5100000004010101" }
      ]
    }
  }
}
```

| Field | Meaning |
|---|---|
| `profile` | How the statement payload is read. This build understands only `spdx3-hbom`: an SPDX 3 JSON-LD document whose `@graph` holds `hardware_PhysicalHardware` nodes. Any other value makes every check `cannot-evaluate`. |
| `category` | The `hardware_category` `typeFromSource` of the one device the statement must describe, compared exactly. A BOM lists several parts, some sharing a serial, so the category says which one is the chip. |
| `minimumTcb` | One floor per generation (`milan`, `genoa` or `turin`), each a 64-bit `0x` hex value in the report's byte order, read little-endian. A report must meet the floor for its own generation in every component. |

All are required, `minimumTcb` may not be empty, and a generation may appear
once. Pin `statementIssuer` as well: the adapter trusts the serial only
because an accepted statement records it.

### Evidence

Collect it on the device. `tools/collect-snp-evidence.ps1` generates a
32-byte random nonce, asks the guest for a report bound to it, and fetches the
matching VCEK and AMD chain from AMD's Key Distribution Service (cached, so
`-Offline` can reuse them):

```console
.\tools\collect-snp-evidence.ps1 -ContainerId <id> -OutDir DIR
scitt-verifier verify --statement hbom.cose --scitt-keys keys.cbor \
  --policy policy.json \
  --binding-mode saved-evidence --adapter amd-snp-device --evidence DIR
```

`DIR` holds four files with fixed names:

| File | What it is |
|---|---|
| `report.bin` | The raw SNP report as the guest returned it (at most 4 KiB). |
| `vcek.der` | The VCEK for the reporting chip and TCB, DER or PEM (16 KiB). |
| `cert_chain.pem` | AMD's `cert_chain` as KDS serves it: ASK then ARK (32 KiB). |
| `nonce.hex` | The nonce the guest was asked to place in `REPORT_DATA`, 16 to 64 bytes as hex (1 KiB). |

A path that resolves outside `DIR` is refused. `--binding-mode
live-evidence` is refused: the evidence has to be collected on the device,
which the verifier may not be.

### Checks

All five are required, in this order:

| Name | Passes when |
|---|---|
| `device-claim` | The statement payload is embedded JSON and names exactly one device of the policy's `category`, with a hexadecimal `hardware_serialNumber`. |
| `snp-report` | The report's signature verifies under the VCEK, the VCEK chains to the pinned AMD root for the report's generation, and the VCEK certifies the report's TCB. |
| `tcb-floor` | The authenticated reported TCB meets the configured floor for its generation. |
| `freshness` | The authenticated `REPORT_DATA` begins with the supplied nonce. |
| `device-binding` | The VCEK carries a hardware ID (Turin 8 bytes, Milan and Genoa 64), the report's `CHIP_ID` is that ID, and it equals the statement's serial. |

A failed check yields `resource-failed` (exit 2). Missing evidence, a nonce
that is all zeros or too short, or a generation with no configured floor
yields `cannot-evaluate` (exit 3). A report that fails authentication leaves
the checks that depend on it `cannot-evaluate`. Only an accepted statement
whose five checks all pass is `resource-transparent` (exit 0).

### SNP device end-to-end tests

`crates/scitt-verifier/tests/amd_snp_device.rs` runs the "try it" scenario
above through the built binary and pins its outcomes: exit 3 with no nonce,
exit 2 with a nonce the report was not made for. No committed test fabricates
a fresh report.

An opt-in test covers exit 0. Collect evidence on the device with
`tools/collect-snp-evidence.ps1`, register a hardware BOM naming that chip,
and set `SCITT_SNPDEV_E2E_DIR` to a directory containing `statement.cose`,
`keys.cbor`, a `policy.json` configuring `amd-snp-device`, and the evidence
under `evidence/`. Then run:

```console
cargo test -p scitt-verifier --features adapter-amd-snp-device --test amd_snp_device genuine_device_and_fresh_report_exit_zero -- --ignored
```

The test requires exit 0, `resource-transparent` and all five checks
passing; missing inputs fail rather than skip. Keep partner device evidence
and hardware BOMs outside the repository.