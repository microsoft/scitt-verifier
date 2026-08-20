# Policy reference

A policy document turns *facts* into a *decision*. `scitt-receipt` can tell you
a statement was registered by an issuer calling itself
`contoso.confidential-ledger.azure.com`. Only you can say whether that is an
issuer you accept.

`--policy` is mandatory. There is no default, because a default would be this
tool making a trust decision on your behalf.

## Shape

```json
{
  "policyId": "contoso/release-gate",
  "policyVersion": "3",
  "description": "Gate for production deployments.",
  "assertions": {
    "issuer": ["contoso.confidential-ledger.azure.com"],
    "signerIssuerContains": "Contoso Corporation",
    "minReceipts": 1,
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

## Assertions

| Assertion | Type | Meaning |
|---|---|---|
| `issuer` | `string[]` | A **fully verified** receipt's issuer must be in this list |
| `signerSubjectContains` | `string` | Substring of the signing certificate's subject |
| `signerIssuerContains` | `string` | Substring of the signing certificate's issuer |
| `minReceipts` | `number` | How many receipts must *fully* verify |
| `registeredAfter` | `number` | Registration at or after this Unix timestamp |
| `registeredBefore` | `number` | Registration at or before this Unix timestamp |
| `maxAgeDays` | `number` | Registration within N days of now |
| `minSvn` | `number` | Minimum security version number, for anti-rollback |
| `requireKidBoundToKey` | `boolean` | Every receipt's kid must be the digest of its signing key |
| `statementSubject` | `object` | The CWT `sub` claim the statement makes about itself |

An empty `assertions` object is rejected: a policy that asserts nothing accepts
everything, which is almost never what someone meant to write.

### `statementSubject`

`sub` is the name the issuer gave the thing the statement is about. It lives in
the protected CWT claims, so the issuer's signature covers it — and because the
claim digest covers the signed statement, the receipt the ledger issued covers
it too.

Write it as an object with **exactly one** match mode:

```json
{ "statementSubject": { "equals": "amd-hbom-F434386R50002-100-000001527" } }
{ "statementSubject": { "startsWith": "amd-hbom-" } }
{ "statementSubject": { "oneOf": ["pkg-a", "pkg-b"] } }
```

| Mode | Meaning |
|---|---|
| `equals` | The subject must be exactly this string |
| `startsWith` | The subject must begin with this prefix |
| `oneOf` | The subject must be exactly one of these strings |

There is deliberately no `contains`. A substring rule for `amd-hbom-1` would
also accept `not-amd-hbom-12`, which is the opposite of what someone pinning an
identity wants. Use `startsWith` when a family of subjects is meant.

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
can sign a statement claiming any subject. Pair it with `issuer` and
`minReceipts` so the claim is only accepted from a ledger whose registration
policy governs who may claim which subject.

### These assertions are not equally strong

`issuer`, `minReceipts`, `registeredAfter`, `registeredBefore`, `maxAgeDays` and
`minSvn` read facts that a transparency service signed, or that this tool
verified. They are load-bearing.

`statementSubject` reads a claim the issuer signed and the ledger's receipt
covers. It is stronger than the certificate assertions below, but it identifies
the *subject*, not the *signer*.

`signerSubjectContains` and `signerIssuerContains` read the leaf certificate
embedded in the statement, which is **not validated to a trusted root** — see
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

## Unknown assertions are refused

A policy naming an assertion this build does not implement is rejected outright
(exit 4).

The alternative — ignoring it — means a policy written for a newer version
appears to pass on an older binary, reporting success for a rule that was never
evaluated. That is the single most dangerous thing a policy engine can do, so
the failure is loud and early.

The practical consequence: **upgrade the verifier before rolling out a policy
that uses new assertions.**

## Time

Time-based assertions use the *receipt's* registration time (`iat` from the
receipt's CWT claims), never the statement's own `iat`. The issuer controls the
statement's claims; the ledger controls the receipt's. Only one of those is
evidence.

If no receipt fully verified, there is no trustworthy registration time and
time-based assertions resolve to `cannotEvaluate` rather than falling back to a
value the issuer chose.

Pass `--now <unix-seconds>` to pin the clock for reproducible runs — useful when
a build agent and a human are arguing about why a gate failed.

## Worked examples

**Minimal.** Registered somewhere, on some ledger:

```json
{
  "policyId": "example/minimal",
  "policyVersion": "1",
  "assertions": { "minReceipts": 1 }
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
    "signerIssuerContains": "Contoso Corporation",
    "minReceipts": 1,
    "maxAgeDays": 30,
    "requireKidBoundToKey": true
  }
}
```

**Two independent services.** For artifacts where a single transparency service
is itself a single point of failure:

```json
{
  "policyId": "contoso/dual-attested",
  "policyVersion": "2",
  "assertions": {
    "issuer": [
      "contoso.confidential-ledger.azure.com",
      "contoso-eu.confidential-ledger.azure.com"
    ],
    "minReceipts": 2
  }
}
```

Note that `minReceipts` counts receipts that *fully* verified — inclusion proof,
root signature, and binding to this statement. A receipt that merely parsed does
not count.
