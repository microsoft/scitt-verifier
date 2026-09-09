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

## Not implemented in this release

### Certificate chain validation to a trusted root

*Reported at runtime:* `appraisal.notChecked` code `CertificateChainNotValidated`,
or code `NoCertificateChain` when the statement carries no chain at all.

The statement signature is verified against the public key in the leaf
certificate embedded in the statement itself. That proves the statement is
internally consistent. It does **not** prove the certificate chains to a root
you trust.

*Consequence:* an attacker who can present any self-signed certificate produces
a statement whose signature "verifies". The receipt binding still protects you —
they cannot get a ledger receipt for it without registering with the
transparency service — but do not read `signatureValid: true` as an identity
claim.

*What actually protects you today:* registration. An attacker who self-signs
still has to get that statement admitted to a transparency service whose keys
are in your `--scitt-keys` file, and the receipt is what this tool verifies
cryptographically.

*What does not:* `signerSubjectContains` and `signerIssuerContains` substring-match
the leaf certificate embedded in the statement — the same certificate an attacker
in the paragraph above minted. Against that attacker they prove nothing, because
they choose the strings. They are useful for catching an *honest* mistake — a
build signed by the wrong team, or by a legitimate CA you did not intend to
accept — and worthless as a defence against forgery. Do not treat them as a
substitute for chain validation.

*Planned:* `--trusted-roots`, using the chain validation already available in
the underlying crypto crate.

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

*Recommended practice:* commit the key set to your repository so that rotating
it is a reviewed pull request with an audit trail, rather than a file that
appears on a build agent.

To require a particular transparency service, use the `issuer` assertion in your
policy document. That is a relying-party rule, so it belongs in the artifact you
version and review rather than in a command line, where dropping it leaves no
trace. A receipt from a different service is signed by that service's key and so
fails receipt verification here regardless.

## Deliberate non-goals

**Fetching statements from a service.** This tool verifies bytes you already
have. Retrieval belongs in whatever already knows your service topology, and
keeping it out is what makes the verifier auditable and offline.

**Deciding what is trustworthy.** The tool reports facts and evaluates *your*
policy. It ships no default policy, because a default would be a trust decision
made on your behalf by a tool that has never seen your threat model.

**Signing or registering.** Verification only. Use `CoseSignTool` or `pyscitt`.

**TPAL and other non-SCITT CCF receipts.** The Merkle core would serve them, but
supporting a second envelope format would blur what "verified" means. Out of
scope.

## Known rough edges

* Only the first inclusion proof in a receipt is evaluated.
  `receipts.entries[].problems` says so when there is more than one.
* `iat` is read from the receipt's CWT claims and reported as a raw Unix
  timestamp. Time-based policy assertions use the *receipt's* registration time,
  never the statement's own `iat`, because the issuer controls the latter.
* The CLI surface is unstable before v1.0. Exit codes are the stable contract;
  pin a release tag in pipelines.

## Reporting a gap

If the tool reported success where it should not have, that is a security issue.
See [SECURITY.md](../SECURITY.md) — please do not open a public issue.
