# Limitations

Nothing in this list requires reading the documentation to discover: every
limitation below is also reported at runtime. They do not all surface on the
same channel, and the difference is the point.

* **`appraisal.notChecked`** — a check this run did not perform, as a structured
  entry with a stable `code`, a `category`, and an `impact`. Reported
  unconditionally, including on success.
* **`trust.limitations`** — what the trust material itself cannot establish,
  regardless of how the run went.
* **`receipts.entries[].problems`** — something about a specific receipt that
  stopped a check from running or made it fail.
* **Refusal** — an input this build declines to interpret at all, reported as a
  diagnostic with exit 3. A refusal is not a silent gap; it ends the run.

Each section below names its channel, and its stable code where it has one.
Those codes are pinned by `docs_report_what_they_claim` in
`crates/scitt-verifier/tests/design_commitments.rs`, so a code named here that
no longer exists in the source fails the build.

That is deliberate. A verification tool that overstates its coverage is worse
than no tool, because it converts an open question into false confidence.

## Supported, with limits

### COSE Hash Envelope binding (`payload-digest`)

When a statement is produced by indirect signing (RFC 9995), the payload **is
already a digest** of the artifact rather than the artifact itself, and
protected header 258 names the hash algorithm used. `--binding-mode
payload-digest` hashes your artifact with that algorithm and compares.

*What is not automatic:* you must name the mode. The tool will not pick between
`payload-bytes` and `payload-digest` for you, because the two answer different
questions and silently switching would let a mode that was never checked look
like one that passed. Naming the wrong mode is reported as *cannot compare*
(exit 3), never as a mismatch — a mode error is not evidence about your artifact.

*What is never fetched:* header 260 (`payload_location`) is displayed by
`inspect` and otherwise ignored. This tool is offline; retrieving the preimage
from a URL the statement itself chose would not establish anything anyway.

Hash algorithms: SHA-256, SHA-384, and SHA-512. Any other value in header 258
is reported as *cannot compare*, never approximated with a different hash.

## Partially implemented

### Certificate chain validation without `--trusted-roots`

*Reported at runtime:* `appraisal.notChecked` code
`CertificateChainNotAnchoredExternally`, or code `NoCertificateChain` when the
statement carries no chain at all. Code `CertificateChainNotValidated` is
reported when the chain could not be examined at all.

The chain is always validated: every certificate is checked to be signed by the
next, and the path must end at a self-issued anchor. Without `--trusted-roots`
that anchor is the root the statement itself carries, so the result establishes
that the chain is *internally consistent* — not that it leads anywhere you
trust.

*Consequence:* an attacker who mints their own root produces a chain that is
equally consistent. The receipt binding still protects you — they cannot get a
ledger receipt for it without registering with the transparency service — but
do not read a validated chain as an identity claim unless you supplied the root.

*What actually protects you today:* registration, and `--trusted-roots`. Pass a
PEM file of the CAs you accept and the anchor must come from that file; the gap
above then disappears and the `certificateChainValidated` and
`requireChainToRootSha256` assertions become meaningful.

*What does not:* `signerSubjectContains` and `signerIssuerContains` substring-match
the leaf certificate embedded in the statement — the same certificate an attacker
in the paragraph above minted. Against that attacker they prove nothing, because
they choose the strings. They are useful for catching an *honest* mistake — a
build signed by the wrong team, or by a legitimate CA you did not intend to
accept — and worthless as a defence against forgery. Do not treat them as a
substitute for supplying roots.

## Not implemented in this release

### ECDSA-signed certificate chains, and RSA-PSS parameters the backend refuses

*Reported at runtime:* `appraisal.notChecked` code `CertificateChainUnsupported`,
naming the signature algorithm OID and the backend's own reason.

The pinned crypto backend verifies RSA certificate signatures only — PKCS#1 v1.5
with SHA-256/384/512, and RSA-PSS. A chain whose certificates are signed with
ECDSA cannot be checked here at all. AMD's hardware bill-of-materials signing
chain is one real example.

RSA-PSS is admitted by OID and then constrained further: the backend requires
MGF1 over the same digest and one specific salt length per digest. A legal
RSA-PSS certificate using a different salt length is reported as unsupported for
the same reason ECDSA is — the question is whether this build can perform the
check, not whether the certificate is well formed.

The check is asked of the backend itself rather than of a list of OIDs kept
alongside it. A list agrees with the backend about the algorithm and not about
its parameters, and the disagreement surfaces as a chain that "failed to
verify" — an accusation against the signer for what is a limit of the tool.

*Consequence:* the chain is **unexamined**, not known-good. This is deliberately
a different code from the gaps above: supplying a root will not fix it, and only
a newer build can. Everything else about such a statement — the leaf signature,
the receipt, the payload — is still verified normally.

### Certificates using extensions the path policy declines to evaluate

*Reported at runtime:* `appraisal.notChecked` code `CertificateChainUnsupported`,
naming the extension OID.

RFC 5280 requires a verifier to refuse a certificate marking an extension
critical that it does not understand. The path validation here processes
`basicConstraints` and `keyUsage`; a certificate marking anything else critical —
extended key usage, for instance — is reported as unsupported rather than
invalid.

The same applies to four extensions the policy refuses **even when they are not
critical**: `policyMappings`, `nameConstraints`, `policyConstraints`, and
`inhibitAnyPolicy`. That is stricter than RFC 5280, which permits a verifier to
ignore a non-critical extension, so a certificate carrying one is legal and
simply beyond this build.

Refusing to process an extension says nothing about whether the chain is
genuine, and reporting it as a failure would accuse a chain that may be
perfectly well formed.

### `did:x509` resolution against the validated chain

*Reported at runtime:* nothing, because nothing claims it. This is a scope
boundary rather than a gap in a check that runs.

The `did:x509` parser and resolver exist as a library primitive and are not
called during verification. The `statementIssuer` assertion compares the CWT
`iss` claim as a **string**, which is what it has always documented; it is
covered by the Issuer's signature and by the receipt, and it is not re-derived
from the certificate chain.

*Consequence:* a validated chain plus a pinned root establishes that the leaf
was issued under a CA you accept. It does **not** establish that the leaf
satisfies the EKU or subject predicates named in the DID the statement claims.
Where the transparency service authenticates `did:x509` at registration —
Microsoft Signing Transparency does — the receipt already carries that
guarantee. Against a service that does not, a different certificate holder under
the same accepted CA could claim the expected DID and obtain a genuine receipt.

### Certificate revocation

*Reported at runtime:* `appraisal.notChecked` code `RevocationNotChecked`.

Not checked. Revocation checking requires network access, and this tool is
offline by design. There is no plan to change that; a gate that stops working
when OCSP is unreachable is not a gate anyone keeps enabled.

### Verifiable data structures other than `CCF_LEDGER_SHA256`

*Reported at runtime:* refusal, exit 3. This one is not in `notChecked`,
because the run does not reach a verdict to caveat.

Any other value in header 395 is refused (exit 3), never interpreted as a
format we do understand.

This includes `RFC9162_SHA256` (vds `1`), which is the only verifiable data
structure RFC 9942 itself registers. Its inclusion proofs use RFC 9162's
domain-separated Merkle construction — a different shape from CCF's — so
supporting it is a second verifier, not a parameter. Until then, receipts from
Sigstore-style logs cannot be verified here.

### Signed trust material

*Reported at runtime:* `trust.limitations`, which names the missing publisher
signature, the absent revocation status, and the lack of anti-rollback
protection.

`--scitt-keys` takes a raw COSE_KeySet. There is no cryptographic binding
between that file and the transparency service it claims to represent — its
authenticity comes from how you obtained and reviewed it.

`tools/scitt-keys.py fetch` establishes that binding *at acquisition time* by
pinning TLS to the service certificate published by the Azure identity service
and requiring the service's own key to appear in the key set it serves. It
records the result in a provenance sidecar. See
[`trust-material.md`](trust-material.md).

That sidecar is a record for reviewers, not a proof: anyone who can edit the key
set can edit the sidecar. The verifier cannot re-check any of it offline.

`--online` moves that binding to verification time: the key set is fetched over
a connection authenticated to the service certificate, and the service's own key
must be present in what it serves. That is a stronger statement about *who
served the bytes* and no statement at all about revocation, freshness, or the
signer. A key withdrawn an hour ago still verifies, and a service replaying an
old key set is indistinguishable from one serving its current one.

*Recommended practice:* commit the key set to your repository so that rotating
it is a reviewed pull request with an audit trail, rather than a file that
appears on a build agent. Where that cadence cannot keep up with rotation, use
`--online` with `--save-trust` so the material a run actually used is still
captured as evidence.

To require a particular transparency service, use the `issuer` assertion in your
policy document. That is a relying-party rule, so it belongs in the artifact you
version and review rather than in a command line, where dropping it leaves no
trace. A receipt from a different service is signed by that service's key and so
fails receipt verification here regardless. Under `--online` the same assertion
does double duty: it is also the allowlist of services the tool may contact.

### Revocation, under `--online` too

*Reported at runtime:* code `AcquisitionServiceKeyMismatch` covers a service
that fails to serve its own key; nothing covers a key that was withdrawn.

Fetching a key set live looks like it should solve revocation and does not.
The key sets these services publish carry no revocation status, so a key removed
from the set simply stops appearing — which a verifier sees as an unknown `kid`,
indistinguishable from a rotation it has not caught up with. There is no
mechanism here for "this key existed and must no longer be honoured".

## Deliberate non-goals

**Fetching statements from a service.** This tool verifies bytes you already
have. `--online` fetches *keys*, never statements or receipts: the evidence
being judged is always input you supplied, so what is being checked cannot be
chosen by the network. Retrieval of statements belongs in whatever already knows
your service topology.

**Deciding what is trustworthy.** The tool reports facts and evaluates *your*
policy. It ships no default policy, because a default would be a trust decision
made on your behalf by a tool that has never seen your threat model.

**Signing or registering.** Verification only. Use `CoseSignTool` or `pyscitt`.

**TPAL and other non-SCITT CCF receipts.** The Merkle core would serve them, but
supporting a second envelope format would blur what "verified" means. Out of
scope.

## Known rough edges

* `--decode` reads claims from the payload only, and only when the statement
  declares that payload to be JSON. Encoded values in protected headers are not
  addressable, and neither is a detached payload, since there are no bytes to
  read. Both are refused by name rather than returning an empty result.
* `--decode` reports a digest; it does not compare one. Gating a deployment on
  "the decoded policy is the one I approved" still means reading `sha256` out
  of the JSON and comparing it yourself. A policy assertion that does the
  comparison in-process, and so cannot be skipped by a pipeline that ignores a
  field, is not yet implemented.
* There is no escape convention for an apostrophe inside a claim name on the
  command line, so such a claim can only be addressed from a policy file.
* `--decode`'s success path has unit coverage and is exercised end-to-end by
  hand, but no acceptance test drives it through the binary: no corpus fixture
  carries a base64-bearing claim, and minting one is a full corpus
  regeneration. The refusal paths are covered.
* Only the first inclusion proof in a receipt is evaluated.
  `receipts.entries[].problems` says so when there is more than one.
* `iat` is read from the receipt's CWT claims and reported as a raw Unix
  timestamp. Time-based policy assertions use the *receipt's* registration time,
  never the statement's own `iat`, because the issuer controls the latter.
* A trusted-roots bundle holding two roots with the same subject and different
  keys — a CA mid-rotation — is handled by trying each candidate until one
  validates, so the answer does not depend on their order in the file. There is
  no fixture for this case: it needs a second real chain, which the corpus does
  not have.
* The CLI surface is unstable before v1.0. Exit codes are the stable contract;
  pin a release tag in pipelines.

## Reporting a gap

If the tool reported success where it should not have, that is a security issue.
See [SECURITY.md](../SECURITY.md) — please do not open a public issue.
