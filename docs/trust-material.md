# Obtaining trust material

`scitt-verifier verify` needs the transparency service's signing keys. By
default it will not fetch them for you: a run is offline unless you pass
`--online`. This document explains how to get the keys, why acquisition is kept
apart from verification, and what the resulting files do and do not prove.

There are two ways, and the difference is not convenience but blast radius:

| | Command | Network at gate time | Use it when |
|---|---|---|---|
| Pinned | `--scitt-keys keys.cbor` | never | the gate must not be able to fail open |
| Acquired | `--online` | yes, to allowlisted services only | distributing a key set is the larger risk |

Start pinned. Reach for `--online` when the cost of stale key material is
higher than the cost of a network dependency — most often during rotation,
where a pinned gate fails closed on every build until someone lands a pull
request.

This document concerns **receipt-signing keys**. Optional resource adapters
have separate targets and trust inputs under `adapters.<name>`. For example,
`azure-confidential-ledger` obtains live evidence from `adapters.azure-confidential-ledger.target.host`, not
from the receipt issuer selected by `assertions.issuer` or `--ledger`.
`--online` alone does not appraise a resource; `live-evidence` additionally
requests that work and currently requires `--online`. See [adapters](adapters.md).

`tools/scitt-keys.py` automates the pinned procedure. It is a prototype of a
planned `scitt-keys` binary; the command surface below is expected to be stable.

```console
pip install cryptography cbor2
```

## Acquiring keys at verification time

```console
scitt-verifier verify \
  --statement build.cose \
  --policy    policy.json \
  --online
```

The policy decides which services may be contacted, through the same
`assertions.issuer` allowlist that decides which issuers are acceptable:

```json
{ "assertions": { "issuer": ["contoso.confidential-ledger.azure.com"] } }
```

Without that allowlist, `--online` refuses and makes no request. This is the
whole design, not a safety check bolted on:

- **The statement cannot choose a destination.** Receipts live in the COSE
  *unprotected* header bucket, which no signature covers, so anyone holding the
  file can append one naming any service they like. A receipt naming a service
  the policy does not accept produces no request at all — it is reported as not
  selected.
- **`--ledger` narrows, never widens.** `--ledger contoso...` restricts a run to
  one allowlisted service. Naming one the policy does not accept is refused, so
  the flag cannot be used to work around the policy from the command line.
- **Failures stay failures.** An unreachable service is reported with a
  diagnostic code and the exact URL attempted. It never falls back to another
  key, and never becomes a pass.

`--save-trust <DIR>` writes what was fetched — the key sets and service
certificates as served, plus a manifest of digests — so a later run can replay
the same material offline with `--scitt-keys`. Each service configuration that
was read is saved beside them as `<issuer>.configuration.json`, byte for byte,
with its digest in the manifest; it is kept for audit and nothing replays it.
It refuses to overwrite an
existing snapshot, and it refuses to let `--result` or `--facts` write over a
file it produced in the same run: a record is a description of a conclusion,
the snapshot is evidence, and the write that would destroy the evidence is the
one that otherwise succeeds quietly.

Online acquisition needs an x86-64 host with AES, PCLMULQDQ, BMI1, ADX, AVX and
AVX2 — Intel Broadwell or AMD Excavator, 2014 or later — because the bundled
pure-Rust TLS stack requires them. Verification itself does not. A host without
them is refused with `AcquisitionUnsupportedPlatform` rather than allowed to
abort the process, so the run still leaves a record.

### What `--online` does not give you

A successful fetch establishes who served the keys, over a connection
authenticated to that service's own certificate, and that the key set contains
the key that certificate binds to. It does **not** establish that a key is
unrevoked, that the set is current rather than replayed, or anything about the
statement's signer. The limitations recorded under `trust.limitations` say so
on every run.

### The service's current configuration

After the key sets, `--online` asks each acquired ledger for `/configuration`
over the same connection, pinned to the same service certificate, within the
same overall time limit. With `--verbose` the document is shown after the
verdict, in full and escaped; it is always recorded under `serviceConfiguration` (see
[output.md](output.md#serviceconfiguration)). For a SCITT CCF ledger it
includes the registration policy script and whether unauthenticated
registration is allowed.

It is shown so a reader can see what the service accepts, and it is limited in
exactly the ways that matter:

- It is what the service says **now**, not the policy any statement was
  registered under, and not a prediction that this statement would be accepted
  today.
- It is **not signed** and not bound to any receipt. The TLS connection is its
  only authentication, and a saved copy loses that.
- A registration policy is the **service's**, not the relying party's. It is
  never executed, and it cannot relax, satisfy, or replace an assertion in your
  policy.
- It says nothing about the code the service runs.

It never changes the verdict or the exit code. A ledger that does not serve the
endpoint, refuses it, times out, redirects, or returns something that is not a
JSON object is reported as such in that section, and nothing else changes. A
ledger whose keys were not acquired is not asked, because no authenticated
connection to it was established. This is one extra request per acquired
ledger.

## Why the pinned path is a separate tool

The verifier is offline by default because a deployment gate that depends on a
live service is a gate that fails open the first time the service has a bad
afternoon. It is also a gate whose answer is decided by whoever controls the
network at the moment it runs.

So acquisition and verification can be separated in time and in blast radius:

| | Who runs it | How often | Network |
|---|---|---|---|
| `scitt-keys fetch` | a person, or a scheduled job that opens a pull request | when keys rotate | yes |
| `scitt-verifier verify` | every deployment | every build | **no**, unless `--online` |

`fetch` refuses to run when `CI` is set unless you pass `--refresh`, because the
one legitimate reason to fetch inside a pipeline is a scheduled rotation job.

## Fetching

```console
python tools/scitt-keys.py fetch \
  --issuer mst-test-scitt-verifier.confidential-ledger.azure.com \
  --out    .well-known/scitt-keys.cbor
```

```text
service certificate: https://identity.confidential-ledger.core.azure.com/ledgerIdentity/mst-test-scitt-verifier
  subject CN=CCF Service
  sha-256 b021d80900d21bead1fb8b98f9442d7ed94ab5aa5bf26216202eb615e86dc768
key set: https://mst-test-scitt-verifier.confidential-ledger.azure.com/.well-known/scitt-keys
  175 bytes, sha-256 b146b954b2ba79eec5e59748d96064b5f18dfe4b13f90cf5868207985d6faf0e
  1 key(s), service key present and bound

new trust material: 1 key(s)
```

Commit both the `.cbor` and the `.provenance.json` beside it.

### What it actually does

1. **Fetch the CCF service certificate** from the Azure identity service. That
   host is certified by the public Azure PKI, and it is the single assumption the
   whole chain rests on.
2. **Pin TLS to that certificate and nothing else.** The system trust store is
   not consulted. A CCF ledger is not certified by any public authority — the
   leaf it presents is `CN=CCF Node`, issued by the `CN=CCF Service` certificate
   from step 1 — so falling back to the system roots would mean accepting an
   entirely different service.
3. **`GET /.well-known/scitt-keys`**, which returns a COSE_Key_Set as CBOR: the
   exact bytes `--scitt-keys` expects, with no conversion.
4. **Assert self-binding.** `hex(SHA-256(SubjectPublicKeyInfo))` of the pinned
   service certificate must appear as a `kid` in the key set it just served.

Step 4 is what makes this more than trust-on-first-use. Without it, a successful
fetch only proves that *some* host holding that certificate served *some* bytes.
With it, the key set is bound to the identity the Azure identity service
attested to. If the assertion fails, nothing is written.

No credentials are involved at any point. Every endpoint in the chain is
unauthenticated, so `fetch` needs no Azure identity, no token, and no SDK.

### Ledgers not managed by Azure

A self-hosted `scitt-ccf-ledger` has no entry in the Azure identity service, so
step 1 cannot run. Get the CCF service certificate from whoever operates the
ledger and supply it directly:

```console
python tools/scitt-keys.py fetch \
  --issuer      scitt.example.internal \
  --service-cert service_cert.pem \
  --out         .well-known/scitt-keys.cbor
```

Steps 2 to 4 are unchanged, including the self-binding assertion.

### `/jwks` is deliberately not a fallback

If `/.well-known/scitt-keys` returns 404, the ledger predates the endpoint and
should be upgraded. `fetch` fails rather than falling back to `/jwks`.

`/jwks` returns JSON JWK, which carries no `kid` in the form the receipt uses —
it would have to be re-derived as `hex(SHA-256(SPKI DER))`. Getting that
derivation subtly wrong produces a key set that parses cleanly and then fails to
resolve the receipt's key, which is indistinguishable from a stale trust store.
That is the kind of failure this project exists to avoid, so the conversion is
not offered.

## Reviewing

```console
python tools/scitt-keys.py show .well-known/scitt-keys.cbor
python tools/scitt-keys.py diff old-keys.cbor new-keys.cbor
```

`fetch` and `diff` share exit codes so a caller can branch on either:

| Exit | Meaning |
|---|---|
| 0 | Unchanged, or newly created |
| 1 | Trust could not be established — nothing was written |
| 2 | Usage error, including a CI fetch without `--refresh` |
| 3 | **Keys added** — normal rotation, commit it |
| 4 | **Keys removed** — a person should look |

Exit 4 exists because both routine rotation and disaster recovery *retain* old
keys: a recovered instance serves the old and new keys together, and receipts
carry a `kid`, so verification keeps working across rotations. A healthy diff
therefore only ever adds lines. A removal means either a deliberate operator
action you should know about, or something worse — and receipts issued under a
removed key can no longer be verified.

## Rotation as a pull request

The recommended pattern is a scheduled job that fetches and opens a pull request
when anything changes:

```yaml
on:
  schedule:
    - cron: "0 6 * * 1"

jobs:
  refresh-trust-material:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install cryptography cbor2
      - id: fetch
        run: |
          set +e
          python tools/scitt-keys.py fetch --refresh \
            --issuer "${{ vars.SCITT_ISSUER }}" \
            --out    .well-known/scitt-keys.cbor
          code=$?
          set -e
          case $code in
            0) echo "changed=false" >> "$GITHUB_OUTPUT" ;;
            3) echo "changed=true"  >> "$GITHUB_OUTPUT"
               echo "title=Transparency service keys added" >> "$GITHUB_OUTPUT" ;;
            4) echo "changed=true"  >> "$GITHUB_OUTPUT"
               echo "title=REVIEW: transparency service keys were REMOVED" >> "$GITHUB_OUTPUT" ;;
            *) echo "::error::could not establish trust in the fetched keys"
               exit $code ;;
          esac
      - if: steps.fetch.outputs.changed == 'true'
        uses: peter-evans/create-pull-request@v6
        with:
          title: ${{ steps.fetch.outputs.title }}
          branch: refresh-scitt-keys
```

Note that exits 3 and 4 are *outcomes*, not failures, while 1 and 2 fail the job.
Collapsing them — for example with a bare `continue-on-error: true` — would hide
a trust failure behind a routine rotation, which is the specific confusion this
tool's exit codes exist to prevent.

Rotation then surfaces as a reviewable diff days before it would have broken a
deployment, and the audit trail is your existing pull request history.

## What the provenance sidecar does and does not prove

`fetch` writes a JSON sidecar recording the issuer, the identity endpoint, the
service certificate subject and digest, the self-binding result, the key set
digest, the key identifiers, and the fetch time.

**It is a record for reviewers, not a cryptographic proof.** Anyone who can edit
the `.cbor` can edit the sidecar. Its value is that it makes an otherwise opaque
1,219-byte blob reviewable in a pull request, and it lets `show` detect a key set
that has been modified since it was fetched.

The protection is procedural: the files are committed, changes appear in a diff,
and a human approves them. That is the same protection your repository already
provides for the code being signed.

A cryptographically self-defending format — a publisher-signed Transparent Trust
List authenticated against a pinned publisher key — would remove the need to
trust the acquisition channel at all. That is planned, and it is why `fetch`
records provenance in a structured form now.

## Related

* [`limitations.md`](limitations.md) — what the verifier does not check
* [`distribution.md`](distribution.md) — why the key set belongs in your repository
