# Policy reference

A policy document turns *facts* into a *decision*. `scitt-receipt` can tell you
a statement was registered by an issuer calling itself
`contoso.confidential-ledger.azure.com`. Only you can say whether that is an
issuer you accept.

`--policy` is mandatory. There is no default, because a default would be this
tool making a trust decision on your behalf.

## Build a policy in four steps

Everything below is runnable against the statement that ships in this
repository, so you can follow it before pointing it at your own.

### 1. Look at what you actually have

A policy pins strings. `inspect` is where you find them — it reads a statement
without needing keys, a policy, or a network:

```console
$ scitt-verifier inspect --statement corpus/fixtures/transparent-statement.cose
```

Five values in that output are the ones you will quote in a policy:

| `inspect` shows | Assertion that pins it |
|---|---|
| `Receipt 1` → `iss` — `musa-mst-july.confidential-ledger.azure.com` | `issuer` |
| `cwt claims` → `iss` — `did:x509:0:sha256:1Unc...` | `statementIssuer` |
| `cwt claims` → `sub` — `unknown.intent` | `statementSubject` |
| `Signing certificate` → `subject` / `issuer` | `signerSubjectContains` / `signerIssuerContains` |
| `Receipt 1` → `registered at` — `1785197841` | `registeredAfter` / `maxAgeDays` |
| any protected header, by the label in brackets | `protectedHeaders` |

Copy the values; do not retype them. `issuer` is an exact match, and a
truncated hostname fails in a way that looks like a rejected artifact.

### 2. Start from the baseline

Two assertions earn their place in almost every policy:

```json
{
  "policyId": "example/baseline",
  "policyVersion": "1",
  "assertions": {
    "issuer": ["musa-mst-july.confidential-ledger.azure.com"],
    "receiptCount": 1
  }
}
```

`issuer` says which transparency service you trust. Without it, a receipt from
a log an attacker stood up satisfies the gate as readily as yours — the
signature checks would all pass, against their key set. `receiptCount` says the
file still carries exactly the one receipt the service returned.

Start here and add, rather than starting from the full list and removing. Every
assertion you cannot explain is one you will eventually disable under time
pressure.

### 3. Add what your threat model needs

| If you need to say | Add |
|---|---|
| "signed by the identity we expect" | `statementIssuer` |
| "about the artifact we expect" | `statementSubject`, or `--artifact` binding |
| "registered recently" | `maxAgeDays` |
| "not an old, rolled-back build" | `minSvn` |
| "carries the vendor header we require" | `protectedHeaders` |
| "the ledger's key genuinely owns its kid" | `requireKidBoundToKey` |

Each has its own section below, including what it does *not* establish.

### 4. Prove it can fail

A policy nobody has seen reject anything is a policy nobody has tested. Run it
twice — once against a statement you trust, once against something it must
refuse:

```console
$ scitt-verifier verify --statement good.cose --scitt-keys keys.cbor --policy p.json
$ echo $?    # expect 0

# Same statement, one character changed in the issuer you pinned.
$ scitt-verifier verify --statement good.cose --scitt-keys keys.cbor --policy misspelled-p.json
$ echo $?    # expect 2
```

Exit 2 is the one to confirm. A gate that has only ever returned 0 cannot be
distinguished from a gate that returns 0 unconditionally.

## Shape

```json
{
  "policyId": "contoso/release-gate",
  "policyVersion": "3",
  "description": "Gate for production deployments.",
  "assertions": {
    "issuer": ["contoso.confidential-ledger.azure.com"],
    "statementIssuer": { "startsWith": "did:x509:0:sha256:<contoso-ca-fingerprint>::" },
    "receiptCount": 1,
    "maxAgeDays": 90,
    "requireKidBoundToKey": true
  }
}
```

`policyId` and `policyVersion` are echoed into the verification record — under
`relyingPartyPolicy`, named in full there because a stored record loses the
command line that produced it, and RFC 9943 §3 gives bare "Registration Policy"
to the transparency service. A decision can be traced back to the exact rules
that produced it. Bump the version when
you change the assertions; an auditor comparing two verification records months
apart has no other way to tell them apart.

`description` is optional and is **not** copied into the record. It is a note
for whoever opens the policy file, so put anything an auditor needs into
`policyId` and `policyVersion` instead.

## How assertions combine

Every assertion in the object must pass. They are ANDed; there is no `anyOf`,
no negation, and no ordering. A policy is a list of things that must all be
true, and the report names each one individually so a failure points at the
rule that produced it rather than at the policy as a whole.

Within a single assertion the story differs, and the difference is deliberate:

* `issuer` and `oneOf` take a list and accept **any** member. They express
  "one of these is fine".
* Everything else takes one value.

A policy is satisfied only when at least one assertion ran and every assertion
that ran passed. That first clause is not redundant — see
`requireKidBoundToKey` below for the policy that parses and asserts nothing.

## Assertions

| Assertion | Type | Meaning |
|---|---|---|
| `issuer` | `string[]` | A **fully verified** receipt's issuer must be in this list (exact match) |
| `signerSubjectContains` | `string` | Substring of the signing certificate's subject |
| `signerIssuerContains` | `string` | Substring of the signing certificate's issuer |
| `receiptCount` | `number` | How many receipts the statement carries; must be `1` |
| `registeredAfter` | `number` | Registration at or after this Unix timestamp |
| `registeredBefore` | `number` | Registration at or before this Unix timestamp |
| `maxAgeDays` | `number` | Registration within N days of now |
| `minSvn` | `number` | Minimum security version number, for anti-rollback |
| `requireKidBoundToKey` | `boolean` | Every receipt's kid must be the digest of its signing key |
| `statementSubject` | `object` | The CWT `sub` claim the statement makes about itself |
| `statementIssuer` | `object` | The CWT `iss` claim naming who signed the statement |
| `protectedHeaders` | `object[]` | Assertions on individual protected header entries, by label path |
| `externalSignatures` | `object[]` | Cryptographically verify a detached signature carried in a protected header |

An empty `assertions` object is rejected: a policy that asserts nothing accepts
everything, which is almost never what someone meant to write.

### `issuer`

The transparency services whose receipts you accept, by the hostname the
receipt declares in its own CWT `iss` claim.

```json
{ "issuer": ["contoso.confidential-ledger.azure.com"] }
{ "issuer": ["contoso-cp.confidential-ledger.azure.com", "contoso-db.confidential-ledger.azure.com"] }
```

**Matching is exact, not substring.** This is the mistake worth warning about,
because the assertion directly below it — `signerIssuerContains` — *is* a
substring rule, and the two names look alike. `"issuer": ["musa-mst-july"]`
does not match a receipt from `musa-mst-july.confidential-ledger.azure.com`; it
fails, and the report reads like a rejected artifact rather than a typo. Paste
the full hostname from `inspect`.

The list is an "any of": a statement passes if any fully verified receipt
declares an issuer in the list. Listing several is how you accept a service
that runs under more than one hostname, such as a primary and a disaster
recovery instance.

Only **fully verified** receipts are considered — one whose key resolved, whose
root signature checked out, and which is bound to this statement. Receipts
travel in the statement's unprotected header, so anyone handling the file can
append one, and an appended receipt's self-declared `iss` is a string the
attacker chose. If it counted here, a statement registered on a ledger this
policy rejects could satisfy the rule anyway.

If no receipt fully verified, the outcome is `cannotEvaluate`, not `fail`.

An empty list is accepted when the policy is parsed and then fails everything,
since no issuer can be a member of it. That is safe but rarely intended; if you
mean "any issuer", omit the assertion and understand what you are giving up.

### `receiptCount`

How many receipts the statement carries. `1` is the only value this build
accepts, and any other is refused when the policy is loaded.

```json
{ "receiptCount": 1 }
```

It counts receipts **present**, not receipts that verified. That is the whole
point: receipts ride in the unprotected header bucket that no signature covers,
so anyone who handled the file can append one, and a transparency service
issues exactly one per registration. A second receipt means the file is not the
one the service returned. Because the verdict disregards receipts that fail to
verify — RFC 9943 §7.1 lets a Relying Party accept one good receipt and ignore
the rest — an inserted receipt is otherwise invisible to the gate. This
assertion is how an operator asks to be told about it.

A value other than `1` is refused rather than evaluated. Receipts are not signed
as a set, so `2` could be satisfied by attaching a copy of the receipt that
already exists: it would count twice while proving once. Requiring genuinely
independent registrations is a different property than counting, and needs
explicit support rather than a larger number here. `0` would accept a statement
carrying no proof of registration at all.

### `statementSubject`

`sub` is the name the issuer gave the thing the statement is about. It lives in
the protected CWT claims, so the issuer's signature covers it — and because the
claim digest covers the signed statement, the receipt the ledger issued covers
it too.

Write it as an object with **exactly one** match mode:

```json
{ "statementSubject": { "equals": "release-manifest-2026.02.12-3" } }
{ "statementSubject": { "startsWith": "release-manifest-" } }
{ "statementSubject": { "oneOf": ["pkg-a", "pkg-b"] } }
```

| Mode | Meaning |
|---|---|
| `equals` | The subject must be exactly this string |
| `startsWith` | The subject must begin with this prefix |
| `oneOf` | The subject must be exactly one of these strings |

There is deliberately no `contains`. A substring rule for `release-manifest-1`
would also accept `not-release-manifest-12`, which is the opposite of what
someone pinning an identity wants. Use `startsWith` when a family of subjects is
meant.

Two policies are refused when the document is parsed rather than allowed to
report a pass:

- `{}`, or more than one mode at once — there is no single rule to apply.
- A mode that cannot reject anything: `startsWith: ""` matches every subject,
  and `oneOf: []` matches none. Either would appear in the report as an
  assertion that ran and passed while having examined nothing.

If the statement carries no `sub` claim the outcome is `cannotEvaluate`, not
`fail` — "makes no claim" and "makes the wrong claim" call for different
responses.

`statementSubject` is most useful when the artifact cannot be hashed. Binding a
physical part to a statement is impossible with `--artifact`, because the
relying party is holding a component, not a file; the serial number in `sub` is
the only join key available.

Note what it does **not** establish: that the *right issuer* said it. Any key
can sign a statement claiming any subject. Pair it with `statementIssuer` to pin
who said it, and with `issuer` and `receiptCount` so the claim is only accepted
from a ledger whose registration policy governs who may claim which subject.

### `statementIssuer`

`iss` is the identity the signer claimed for itself. It is the complement to
`statementSubject`: `sub` names what the statement is about, `iss` names who
said it. Both sit in the protected CWT claims, so the issuer's signature covers
them, and the claim digest carries them into the receipt.

```json
{ "statementIssuer": { "equals": "did:x509:0:sha256:1UncIxT3oW5J...::eku:1.3.6.1.4.1.311.97.1.3.1..." } }
{ "statementIssuer": { "startsWith": "did:x509:0:sha256:1UncIxT3oW5J" } }
{ "statementIssuer": { "oneOf": ["did:x509:0:sha256:aaa", "did:x509:0:sha256:bbb"] } }
```

The match modes, the parse-time refusals, and the absence of a `contains` mode
are the same as `statementSubject`, and for the same reason: a `did:x509` an
attacker controls can embed the string you are pinning, so a substring rule
would accept the impostor it was written to exclude. `startsWith` is the useful
middle ground — a `did:x509` is `did:x509:0:<alg>:<ca-fingerprint>::<policy>`,
so a prefix stopping at the fingerprint pins the issuing CA while tolerating a
change of EKU below it.

If the statement carries no `iss` claim the outcome is `cannotEvaluate`.

**Why this is not `signerIssuerContains` again.** That assertion reads the leaf
certificate the statement carries, which this build does not validate to a
trusted root — whoever signed chose those strings. `iss` is inside the signed
payload that the ledger registered, so forging it means obtaining a receipt for
the forgery.

**What it is worth depends on the ledger's registration policy.** This
assertion checks that the statement claims the issuer you expect; it does not
re-derive that identity from the certificate chain. Where the transparency
service authenticates the issuer at registration — Microsoft Signing
Transparency does, for the `did:x509` form — a receipt means the service already
checked that the signer was entitled to that identity.

That is why this assertion is worth writing rather than assuming. MST
authenticates *which* identity a signer may claim, but it does not restrict
*whose* statements may be registered: any entitled signer can obtain a receipt.
So a receipt alone says "some authenticated issuer", and `statementIssuer` is
what turns that into "the issuer I expect". Against a service that registers
whatever it is handed, the same assertion pins only a string the signer chose
for itself. Know which one you are talking to; that is the assumption this tool
asks you to make deliberately rather than by accident.

### `signerSubjectContains` and `signerIssuerContains`

Substring matches against the subject and issuer distinguished names of the
X.509 certificate embedded in the statement's protected header.

```json
{
  "signerSubjectContains": "CN=Contoso Build Service",
  "signerIssuerContains": "Microsoft Enterprise ID Verification"
}
```

Substring, not exact — a DN is a comma-separated sequence whose ordering and
optional components vary between issuers, so pinning the whole string breaks on
a cosmetic change. Match on the component you actually care about.

Both resolve to `cannotEvaluate` when the statement carries no certificate,
which is legitimate: a statement may name its key by `kid` alone.

**These are the weakest assertions here.** This build does not validate the
certificate to a trusted root, so anyone who can sign a statement chooses both
strings. Read them as a label on the artifact, not as proof of who produced it.
`statementIssuer` is the assertion for that, because a receipt covers it.

### `registeredAfter`, `registeredBefore` and `maxAgeDays`

When the statement was registered, measured as a Unix timestamp.

```json
{ "registeredAfter": 1735689600 }
{ "registeredBefore": 1767225600 }
{ "maxAgeDays": 30 }
```

`registeredAfter` and `registeredBefore` are absolute and inclusive — a
registration exactly on the boundary passes. Use them to scope a gate to a
release window, or to refuse anything registered before a key rotation.

`maxAgeDays` is relative to now: registration must fall within N days of the
current time. It expresses "recent enough", which is the question a deployment
gate usually has. Pass `--now <unix-seconds>` to pin the clock for reproducible
runs — useful when a build agent and a human are arguing about why a gate
failed.

All three read the **receipt's** registration time (`iat` from the receipt's
CWT claims), never the statement's own `iat`. The issuer controls the
statement's claims; the ledger controls the receipt's. Only one of those is
evidence. When several receipts verified, the earliest is used.

If no receipt fully verified there is no trustworthy registration time, and all
three resolve to `cannotEvaluate` rather than falling back to a value the
issuer chose.

### `minSvn`

A minimum security version number, for anti-rollback.

```json
{ "minSvn": 3 }
```

The SVN is read from the statement's CWT claims. A statement declaring a lower
number fails; one declaring the number or higher passes.

**A statement that declares no SVN yields `cannotEvaluate`, and the run exits
3, not 2.** This surprises people, and the distinction is the point: "this
artifact declares SVN 2, which is too low" and "this artifact declares no SVN
at all" call for different responses. The first is a rollback attempt; the
second usually means the producer never emitted the claim, and quietly failing
it would send someone hunting for a rollback that never happened.

Before adding `minSvn`, confirm your producer actually emits the claim — the
statement shipped in this repository does not, so a policy requiring it exits 3
against the walkthrough above.

### `requireKidBoundToKey`

Require that every verified receipt's `kid` is the digest of the key that
signed it.

```json
{ "requireKidBoundToKey": true }
```

A `kid` is a hint for finding a key, and nothing normally forces it to be
honest. When the transparency service derives it from the key itself, the hint
becomes checkable, and this assertion is how you say your service does. It
raises the cost of substituting one of the service's keys for another in a key
set you obtained out of band.

Only verified receipts are examined, deliberately: reading unverified ones
would let anyone append a junk receipt to any statement and turn this assertion
into a denial of the gate.

**`false` does not mean "check that they are not bound".** It pushes no
assertion at all. A policy whose only assertion is `requireKidBoundToKey: false`
parses successfully, evaluates nothing, and exits 3 —
`PolicyProducedNoAssertions`, "policy parsed but evaluated no assertions, so it
made no decision". Omit the field rather than setting it to `false`.

### `protectedHeaders`

The assertions above cover the headers this build understands. This one reaches
**any** protected header — including a vendor label, or a profile that did not
exist when the binary was compiled.

You do not have to look labels up. `inspect` prints each protected header with
its `path` in brackets, ready to paste:

```text
Protected headers
  alg [1]                  ES256 (-7)
  cwt claims [15]
    iss [15, 1]            did:x509:0:sha256:6i0U...
    sub [15, 2]            unknown.intent
  payload hash alg [258]   SHA-256 (-16)
  preimage cty [259]       application/spdx+json
```

An integer label prints bare and a text label quoted, matching the distinction
`path` itself draws. Nested entries show their whole path, so a claim two deep
needs no assembly. Headers marked `(not interpreted)` are the ones this build
has no opinion about, and they are addressed exactly like the rest.

That last point is why an uninterpreted header is not left as a summary. Naming
the shape alone — `array of 1` — proves the header is present and gives an
author nothing to write a rule against, so the next step used to be decoding
the file in a separate CBOR tool. Instead its members are printed, each with
its own path:

```text
Protected headers
  ["external-signature"]   array of 1  (not interpreted)
    ["external-signature", 0]    map of 5
      ["external-signature", 0, 1] -257
      ["external-signature", 0, 4] 23 bytes: 6578616d706c652d65787465726e616c…
      ["external-signature", 0, 34] array of 2
        ["external-signature", 0, 34, 0] -16
        ["external-signature", 0, 34, 1] 32 bytes: 2974419c6147611406284c0aadbc2e7b…
      ["external-signature", 0, 33] array of 1
        ["external-signature", 0, 33, 0] 1054 bytes: 3082041a30820282a003020102021421…
      ["external-signature", 0, -1] 384 bytes: 5fea745e9b67694effb592558f186823…
```

`{"path": ["external-signature", 0, 1], "alg": {"equals": "RS256"}}` follows
directly.
The descent stops at the depth `path` itself stops at, since printing a member
no rule could name would only invite one.

Note what the last line does **not** offer. A byte string has no matcher: `text`
and `int` are the only two, so a signature, a thumbprint, or a nonce can be read
here but not asserted on. That is usually the right outcome — pinning raw bytes
requires the relying party to already hold the value it is trying to learn
about — but it is a real limit, and `cannot-evaluate` is what a rule that tries
will produce.

Where a value is a named constant, the number beside it is what an `int`
matcher compares against: `alg [1]  ES256 (-7)` becomes
`{"path": [1], "int": {"equals": -7}}`. The name is never the match target.

Only the **protected** bucket is addressable, which is why no path is printed
under `Unprotected headers`: those bytes are outside the signature, and a rule
about them would assert nothing.

```json
{
  "protectedHeaders": [
    { "path": [3],    "text": { "equals": "application/cose" } },
    { "path": [15, 2], "text": { "startsWith": "release-manifest-" } },
    { "path": [1],    "alg":  { "oneOf": ["PS256", "RS256"] } }
  ]
}
```

Each entry names **where** the value is and **what type** it must be.

#### Addressing a header

`path` is an array walked from the protected header map downwards.

A JSON **number** addresses an integer CBOR label; a JSON **string** addresses
a text label. COSE permits both, and JSON's own type distinction keeps them
apart with no escaping convention. This is why `protectedHeaders` is a list
rather than an object keyed by label: JSON object keys are always strings, so
`{"15": …}` could not say whether it meant the integer label `15` or the text
label `"15"`.

Later segments descend into nested maps, and into arrays by position. Which one
an integer segment means is decided by the value it lands on, so no extra
syntax is needed:

| `path` | Reaches |
|---|---|
| `[3]` | The content type, an integer label at the top level |
| `["vendor.tier"]` | A text label at the top level |
| `[15, 2]` | The `sub` claim, nested inside the CWT claims header |
| `[34, 0]` | The hash algorithm in `x5t`, which is `[hashAlg, hashValue]` |

Paths are limited to 8 segments.

#### Declaring the type

Exactly one of `text`, `int` or `alg` must be given.

* `text` takes the same `equals` / `startsWith` / `oneOf` object as
  [`statementSubject`](#statementsubject), and requires a CBOR text string.
* `int` takes `equals`, `oneOf`, or a range (`min` and/or `max`, which may be
  combined), and requires a CBOR integer.
* `alg` takes `equals` or `oneOf` over COSE algorithm **names**, and requires a
  CBOR integer. See [Matching an algorithm](#matching-an-algorithm).

**The type is a security boundary, not a convenience.** The report renders a
byte string as `20 bytes: <first 16 in hex>` and a three-element array as
`array of 3`. If a policy matched those renderings, a *text* header whose
content is literally `array of 3` would be indistinguishable from a real array,
and two different byte strings sharing a 16-byte prefix would compare equal.
Naming the type makes both impossible.

A tagged integer is **not** read through its tag. CBOR tag 1 is a date and tag 2
a bignum; unwrapping silently would let a policy match a value whose meaning it
never established. Use the time assertions for registration times.

#### Matching an algorithm

```json
{ "path": [1],                          "alg": { "oneOf": ["ES256", "ES384"] } }
{ "path": ["external-signature", 0, 1], "alg": { "equals": "RS256" } }
```

`alg` accepts exactly what `int` would — these identifiers are integers — and
differs only in what a mistake costs.

COSE algorithm identifiers are adjacent negative integers. `-35`, `-36`, `-37`
and `-38` are ES384, ES512, PS256 and PS384: four unrelated algorithms, one
keystroke apart. A mistyped digit produces a **different, entirely valid
policy** that passes every check for the rest of its life, and a reviewer
reading `oneOf: [-7, -35, -37]` cannot see the error without a registry. If the
intent was to exclude an algorithm, nobody finds out that it was admitted.

A mistyped *name* resolves to nothing and is refused when the policy is read:

```console
$ scitt-verifier verify --policy typo.json ...
STOP usage-error
  protectedHeaders[2].alg names 'RS257', which this build does not know.
  Accepting it would mean a rule that can never match reported as a rule that
  ran. Known names: ES256, ES384, ES512, PS256, PS384, PS512, RS256, RS384,
  RS512, EdDSA, SHA-256, SHA-384, SHA-512. For an algorithm outside this list,
  address it by identifier with int.
```

Exit 4, before any signature is checked. Reports name both sides, so a refusal
is legible without a lookup:

```text
[pass] protectedHeaders — [1]: ES256 (-7) must be one of [ES256, ES384, PS256]
[FAIL] protectedHeaders — [1]: ES512 (-36) does not match: it must be ES384
```

Names are matched **exactly**. `es256` and `ES-256` are refused rather than
repaired: the registry spells these one way, and accepting near-misses teaches
authors that the spelling is free.

There is no `min`/`max`. These are registry codes, not a scale, and a range over
them would admit algorithms by accident of numbering.

`alg` is a matcher rather than an interpretation this build applies to label
`1`, because whether a path addresses an algorithm is the author's claim to
make. `[15, 5]` is `nbf`, an integer that is not an algorithm; and at a
private-use label inside a vendor structure — `["external-signature", 0, 1]` —
this build has no basis to know that key `1` means `alg`. It does, by that
vendor's convention, and writing `alg` is how the author says so.

Use `int` for an algorithm this build has no name for. That keeps a new registry
entry usable without waiting for a release, at the cost of the safety above.

#### Outcomes

| Situation | Outcome |
|---|---|
| Header present, right type, criteria met | `pass` |
| Header present, right type, criteria not met | `fail` |
| Header present but a different CBOR type | `fail`, naming both types |
| Header absent | `cannotEvaluate` |
| The label appears more than once | `fail` |

A wrong type is a `fail` rather than a `cannotEvaluate` because the tool did
reach an answer: the statement says something, and it is not the shape the
policy described. The detail names what was expected and what was found, so an
author who addressed the wrong label sees it immediately.

A **duplicated label** fails. CBOR permits the same key twice, and taking the
first would let a producer show this tool one value and another parser a
different one from the same signed bytes. There is no safe choice between them.

#### Not in this build

* **Byte-string matching.** A `bstr` header can be addressed, but any matcher
  applied to it fails on the type. Certificate thumbprints and key identifiers
  are therefore not yet pinnable.
* **Matching across an array.** You can address one element by position, but
  there is no way to say "every element" or "any element". `*` in a path is
  reserved for this and is **refused** when the policy is parsed — a policy
  written for a later build must not quietly become "look for a label named
  `*`", find nothing, and report `cannotEvaluate`.

#### What it does not establish

The same caveat as `statementIssuer`, and one more.

A protected header is inside the signature and inside the receipt, so pinning
one proves the issuer said it and the ledger registered it saying so. It does
**not** interpret the value. If a header carries signature material of its own,
this assertion can pin the identifiers beside it, but nothing here verifies
that signature — so a policy that matches such a header proves what the
statement *claims*, not that the claim was independently checked.

To check it, use [`externalSignatures`](#externalsignatures).

### `externalSignatures`

Some producers carry a *second party's* signature inside the statement's
protected header — a component supplier signing a manifest that a build service
later registers. `protectedHeaders` can describe such a header. This assertion
computes it.

```json
"externalSignatures": [
  {
    "path": ["external-statement"],
    "signedOver": "coseSign1",
    "signerSubjectContains": "Example Component Supplier"
  },
  {
    "path": ["external-signature", 0],
    "signedOver": "payload",
    "signerSubjectContains": "Example Component Supplier"
  }
]
```

`path` addresses the **whole signature structure**, not any field inside it.
With `signedOver: "payload"` that is a descriptor map, and the verifier reads
the COSE labels within:

| Label | Meaning |
|---|---|
| `1` | The signature algorithm. `ES256/384/512`, `PS256/384/512` and `RS256/384/512` are supported |
| `33` | `x5chain` — the signer's certificate, as a DER byte string or an array of them |
| `-1` | The signature bytes |

With `signedOver: "coseSign1"` it is a COSE_Sign1, and the same three come from
its own protected header and signature field.

Naming the structure once, rather than writing three coordinated paths, is
deliberate: separate paths could drift apart and end up checking one signature
against a different signature's algorithm.

`signedOver` is **required**, and names how to read the value at `path`:

| Value | Shape at `path` | What the signature covers |
|---|---|---|
| `"payload"` | A map of COSE labels — a hand-rolled descriptor | The payload bytes directly |
| `"coseSign1"` | A COSE_Sign1 (tag 18 or bare array) | A `Sig_structure` binding the protected header and the payload |

There is no default. A detached signature carries no statement of what it
signed, so a verifier that guessed would report a forgery every time it guessed
wrong, which is the worst error a gate can make: it teaches operators to
disregard the result. An unrecognised value is refused when the policy is read,
not evaluated into a failure. Naming the *wrong* convention for the value
present gives `cannotEvaluate`, never `fail` — the two shapes are different
structures, and "this is not a COSE_Sign1" is the only honest answer.

#### `coseSign1`, and why it is the better shape

If you control the producer, put a COSE_Sign1 in the header rather than a
descriptor map. It costs essentially nothing and removes an ambiguity:

| | bytes |
|---|---|
| descriptor map | 1,517 |
| COSE_Sign1, payload detached (`nil`) | **1,522** |
| COSE_Sign1, payload embedded | 1,679 |

Five bytes. The certificate chain dominates either way. In exchange, the
question `signedOver` exists to answer stops being a convention: `Sig_structure`
names the protected header and the payload, so any COSE library can check it
without being told what the producer meant.

**Detach the nested payload.** Embedding it duplicates the payload inside the
statement — for a 42 KB manifest, that roughly doubles the file — but the real
problem is not size. Two copies of the payload inside one signed statement, with
nothing forcing them to agree, would let a producer embed what the supplier
endorsed and register something else, with both signatures verifying. This build
therefore **fails** an embedded payload that differs from the statement's, and
says so in the detail. An embedded payload that matches exactly is accepted.

`signerSubjectContains` and `signerIssuerContains` are optional substring pins
on the signer's certificate. They behave exactly like the top-level assertions
of the same name, and carry the same caveat — see below.

#### Why this is worth more than matching the header

Every byte `protectedHeaders` can read was chosen by whoever assembled the
statement. A descriptor holding 512 random bytes matches a shape rule exactly as
well as a real one does. This assertion converts a claim anyone could fabricate
with a random-number generator into one that requires a private key.

It also binds the signature to *these* bytes. Moving a genuine supplier
signature onto a statement about something else fails, because the payload it
covers is no longer the payload present.

#### What it does not establish

**Not whose key it is.** This build does not validate the external certificate
chain to a trusted root, so a signer who mints their own certificate passes.
`signerSubjectContains` raises the bar from "someone" to "someone who wrote this
string into a certificate they issued themselves" — useful against mistakes,
not against forgery. A run that uses this assertion says so explicitly under
**Not checked**, as `ExternalSignerChainNotValidated`.

What it *does* give you, even unpinned, is that the descriptor sits in the
protected bucket: the statement's issuer signed over it and the ledger witnessed
it at registration. So a supplier signature that verifies is one the registering
party committed to, on the record, at a time the receipt fixes.

#### Outcomes

| Situation | Outcome |
|---|---|
| Signature verifies and the signer pins match | `pass` |
| Signature does not verify over the payload | `fail` |
| Signature verifies but a signer pin does not match | `fail` — real cryptography, wrong party, which is the shape a substitution attack takes |
| A nested COSE_Sign1 embeds a payload that differs from the statement's | `fail` — its signature may be valid over those bytes; they are not the bytes being deployed |
| The path leads to no such header | `cannotEvaluate` |
| The value is not the shape `signedOver` names | `cannotEvaluate` |
| The descriptor lacks an algorithm, certificate or signature | `cannotEvaluate` |
| The algorithm is one this build cannot compute | `cannotEvaluate` |
| The payload is detached, so there are no bytes to check against | `cannotEvaluate` |

An absent signature is never a failure. A pipeline has to be able to tell "this
supplier did not sign" from "this supplier's signature is fake".

### These assertions are not equally strong

`issuer`, `registeredAfter`, `registeredBefore`, `maxAgeDays` and
`minSvn` read facts that a transparency service signed, or that this tool
verified. They are load-bearing.

`receiptCount` reads the envelope rather than anything signed: it counts what
arrived in an unprotected header. That is precisely what makes it useful — it
sees an insertion the signed material cannot describe — but it detects tampering
with the file, not a property the service attested.

`statementSubject` reads a claim the issuer signed and the ledger's receipt
covers. It is stronger than the certificate assertions below, but it identifies
the *subject*, not the *signer*.

`statementIssuer` reads the same kind of claim and identifies the *signer*. Its
strength is inherited rather than intrinsic: it is only as good as the
registration policy of the service whose receipt covers it. Against Microsoft
Signing Transparency, which authenticates `did:x509` at registration, it is
load-bearing; against a service that registers anything, it pins a self-asserted
string. It is never weaker than the certificate assertions below, because the
receipt covers it and does not cover them.

`protectedHeaders` reads whatever you point it at inside the same signed,
receipt-covered bucket, so its strength matches `statementSubject` and
`statementIssuer` — with the caveat that the tool assigns the value no meaning.
It reports that the issuer signed this label with this value; what that is
worth depends entirely on what the label means to you.

`externalSignatures` is the one assertion that performs cryptography of its own
rather than reading a fact established elsewhere. A pass means a private key was
used over these exact payload bytes — which no amount of `protectedHeaders`
matching can establish. Its ceiling is the same one the certificate assertions
hit: the external chain is not validated to a root, so it identifies a key, not
a party.

`signerSubjectContains` and `signerIssuerContains` read the leaf certificate,
which is **not validated to a trusted root** — see
[limitations](limitations.md#certificate-chain-validation-to-a-trusted-root).
Anyone who can sign a statement chooses those strings. Use them to catch an
honest mistake, never as a defence against forgery.

## Three outcomes, not two

| Outcome | Meaning |
|---|---|
| `pass` | The assertion ran and was satisfied |
| `fail` | The assertion ran and was not satisfied |
| `cannotEvaluate` | The input needed to answer was absent |

`cannotEvaluate` is never a pass. A policy asking for `minSvn: 3` against a
statement that declares no SVN yields `cannotEvaluate`, and the run exits 3.

The distinction matters operationally: "this artifact declares SVN 2, which is
too low" and "this artifact declares no SVN at all" call for completely
different responses, and collapsing them into `fail` loses the information
needed to choose.

## What the exit code tells you

| Code | Meaning |
|---|---|
| 0 | Transparent, and the policy is satisfied |
| 1 | Cryptographic or binding failure — do not trust this artifact |
| 2 | Transparent, but the policy was not satisfied |
| 3 | Could not be evaluated — missing trust material, or an assertion that could not run |
| 4 | Usage or input error, including a malformed or unimplementable policy |

Three of these are policy-authoring codes and they mean different things:

* **2** is your policy working. The statement is genuine and something you
  required was not true of it.
* **3** is your policy not getting an answer — a `cannotEvaluate` outcome, or a
  policy that asserted nothing. Exit 3 is *not* a pass; a gate treating
  anything non-1 as success has no policy.
* **4** is the policy file itself: an unknown assertion, `receiptCount` other
  than `1`, an empty `oneOf`, an empty `startsWith`. These are caught when the
  policy is loaded, before any artifact is read, so a broken policy fails on
  the first run rather than on the first unusual artifact.

`docs/output.md` describes the full record each run emits.

## Unknown assertions are refused

A policy naming an assertion this build does not implement is rejected outright
(exit 4).

The alternative — ignoring it — means a policy written for a newer version
appears to pass on an older binary, reporting success for a rule that was never
evaluated. That is the single most dangerous thing a policy engine can do, so
the failure is loud and early.

The practical consequence: **upgrade the verifier before rolling out a policy
that uses new assertions.**

## Worked examples

**Minimal.** Registered somewhere, on some ledger:

```json
{
  "policyId": "example/minimal",
  "policyVersion": "1",
  "assertions": { "receiptCount": 1 }
}
```

Almost too weak to be useful: it accepts a receipt from *any* transparency
service, including one an attacker stood up. Add `issuer`.

**A production gate.** Registered on our ledger, recently, by our signing
identity:

```json
{
  "policyId": "contoso/production",
  "policyVersion": "7",
  "assertions": {
    "issuer": ["contoso.confidential-ledger.azure.com"],
    "statementIssuer": {
      "startsWith": "did:x509:0:sha256:1UncIxT3oW5JalFUkbJzvJwJjkCgcNYe8WAocPDEAtg::"
    },
    "receiptCount": 1,
    "maxAgeDays": 30,
    "requireKidBoundToKey": true
  }
}
```

The identity pin is `statementIssuer` rather than `signerIssuerContains`
because the receipt covers the former and does not cover the latter. Add
`signerIssuerContains` alongside it if you want the certificate DN in the
report, but do not let it stand in for the identity check.

**Runnable against this repository.** The statement in `corpus/fixtures` is a
real Microsoft Signing Transparency artifact, so this policy exercises every
value the walkthrough discovered:

```json
{
  "policyId": "example/walkthrough",
  "policyVersion": "1",
  "assertions": {
    "issuer": ["musa-mst-july.confidential-ledger.azure.com"],
    "statementSubject": { "equals": "unknown.intent" },
    "receiptCount": 1,
    "requireKidBoundToKey": true
  }
}
```

```console
$ scitt-verifier verify \
    --statement corpus/fixtures/transparent-statement.cose \
    --scitt-keys corpus/fixtures/musa-mst-july-scitt-keys.cbor \
    --policy walkthrough.json
```

`corpus/policies/` holds several more, each written against an artifact that
exists.

## Testing your policy

Treat a policy as code that can be wrong, because it is the only part of this
tool you write yourself.

**Confirm it rejects.** Copy the policy, change one pinned string, and run it
against the same statement. Expect exit 2. A policy that has only ever returned
0 is indistinguishable from one that returns 0 unconditionally, and the
difference is invisible until the day it matters.

**Confirm it is not silently skipping.** Read the `relyingPartyPolicy`
`assertions` array in the JSON record and count the entries. Every assertion
you wrote should appear with an outcome. An assertion missing from that array
did not run.

```console
$ scitt-verifier verify ... --format json --result out.json
```

**Distinguish 2 from 3.** Exit 3 means an assertion could not be answered —
usually `minSvn` against a producer that emits no SVN, or a time assertion when
no receipt verified. It is not a weaker failure; it means the gate did not
reach a verdict. Fail closed on it.

**Pin the clock when the result must be reproducible.** `--now <unix-seconds>`
makes `maxAgeDays` deterministic, so a policy that passes in CI and fails on a
developer's machine an hour later can be compared directly.
