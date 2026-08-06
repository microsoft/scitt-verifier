# Distribution

The tool is only useful if it is already on the machine that needs it. This is
how it gets there.

## Channels

| Channel | Priority | Audience | Notes |
|---|---|---|---|
| GitHub Releases | P0 | Everyone | Static binaries, Linux / macOS / Windows |
| GitHub Action | P0 | GitHub-based CI | `action.yml` in this repository |
| Azure Pipelines script step | P0 | ADO users | See `examples/` |
| ADO Marketplace task | P1 | ADO users who want a task | 1–2 weeks of work |
| MCR container image | P1 | Container pipelines | `mcr.microsoft.com/scitt/verifier` |
| winget / Homebrew | P2 | Developer laptops | Follows a stable release cadence |
| npm + WASM | P3 | Browser and Node | Needs the WebCrypto backend |
| **crates.io** | **Blocked** | Rust consumers | See below |

## Why crates.io is blocked

`scitt-receipt` depends on `tee-attestation-verification-cose`, which depends on
`cborrs` — the formally verified CBOR parser extracted from
[EverParse](https://github.com/project-everest/everparse) — via a **git**
dependency pinned to a commit.

crates.io forbids git dependencies in published crates. That makes the
dependency chain unpublishable, transitively, all the way up to this repository.

Options, in order of preference:

1. **The EverParse team publishes `cborrs` to crates.io.** Everything else
   follows automatically. Worth asking.
2. **The CCF team publishes the `cose` and `crypto` crates**, which requires
   option 1 first.
3. **Vendor `cborrs`.** Fast, but forks a formally verified artifact, which
   forfeits most of the reason for choosing it.

Until then: binaries, containers, and WASM are unaffected. Only `cargo add
scitt-receipt` is unavailable, which affects Rust library consumers and nobody
using the CLI.

## Bootstrapping trust

The tool should be verifiable by the mechanism it implements.

1. Sign each release binary with Artifact Signing.
2. Register the signed statement with Microsoft Signing Transparency.
3. Publish the transparent statement alongside the binary.

Then:

```console
scitt-verifier verify \
  --statement scitt-verifier-x86_64-unknown-linux-musl.cose \
  --artifact  scitt-verifier-x86_64-unknown-linux-musl \
  --binding-mode payload-bytes \
  --scitt-keys mst-scitt-keys.cbor \
  --policy     verify-scitt-verifier.json
```

There is an obvious bootstrap problem — verifying the verifier requires a
verifier — and it is not a fatal one. Anyone who already has a trusted copy can
verify the next release, and anyone starting cold can use `pyscitt` or the Azure
SDK once. What it demonstrates is that we are prepared to be held to the
standard we are asking of others.

## Trust material logistics

The harder distribution problem is not the binary; it is the transparency
service's signing keys.

**Recommendation: commit the key set to the consuming repository.**

* Rotation becomes a reviewed pull request with an audit trail.
* The gate works offline and during a service outage.
* An unexpected change to trust material is visible in a diff.

The cost is that rotation requires a commit in every consuming repository. That
is a real cost, and it is the correct one to pay: the alternative — fetching
keys at verification time — means whoever controls the network at that moment
controls the answer.

## Release checklist

* [ ] Binaries for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
      `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`
* [ ] SHA-256 checksums, published in the release notes
* [ ] SBOM generated and attached
* [ ] Release signed with Artifact Signing and registered with MST
* [ ] The transparent statement attached to the release
* [ ] `action.yml` tested against the published binaries
* [ ] The `v0` moving tag updated

## Positioning

One question needs an answer **before** this appears in Artifact Signing
documentation: is `scitt-verifier` a *reference verifier* or a *supported
product*?

* **Reference verifier** — best effort, community support, breaking changes
  permitted before v1.0.
* **Supported product** — SLA, security response commitments, a compatibility
  guarantee.

Both are defensible. What is not defensible is leaving it ambiguous while
third-party customers start depending on it, because the ambiguity resolves
itself the first time someone files a Sev 2.
