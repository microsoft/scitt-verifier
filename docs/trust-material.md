# Obtaining trust material

`scitt-verifier verify` needs the transparency service's signing keys, and it
will not fetch them for you. This document explains how to get them, why the
acquisition is deliberately a separate step, and what the resulting files do and
do not prove.

`tools/scitt-keys.py` automates the procedure. It is a prototype of a planned
`scitt-keys` binary; the command surface below is expected to be stable.

```console
pip install cryptography cbor2
```

## Why this is a separate tool

The verifier is offline because a deployment gate that depends on a live service
is a gate that fails open the first time the service has a bad afternoon. It is
also a gate whose answer is decided by whoever controls the network at the moment
it runs.

So acquisition and verification are separated in time and in blast radius:

| | Who runs it | How often | Network |
|---|---|---|---|
| `scitt-keys fetch` | a person, or a scheduled job that opens a pull request | when keys rotate | yes |
| `scitt-verifier verify` | every deployment | every build | **no** |

`fetch` refuses to run when `CI` is set unless you pass `--refresh`, because the
one legitimate reason to fetch inside a pipeline is a scheduled rotation job.

## Fetching

```console
python tools/scitt-keys.py fetch \
  --issuer musa-mst-july.confidential-ledger.azure.com \
  --out    .well-known/scitt-keys.cbor
```

```text
service certificate: https://identity.confidential-ledger.core.azure.com/ledgerIdentity/musa-mst-july
  subject CN=CCF Service
  sha-256 651449f86ead650db7d53b909e10fd18826eb85f0db9fcd2d6093d3aec9dfab5
key set: https://musa-mst-july.confidential-ledger.azure.com/.well-known/scitt-keys
  1219 bytes, sha-256 570d8845a264b260939fc86bc7ba2b2a23c3c7223211247e1da97585cd995322
  7 key(s), service key present and bound

new trust material: 7 key(s)
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
