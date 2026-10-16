# Synthetic external-signer chains

These are **synthetic regression fixtures**, not transparency-service
conformance evidence. `generate.py` creates every key, certificate, signature,
statement and CCF-shaped receipt locally. No partner material is used, and no
private keys are written. The real-service corpus in `corpus/` is unchanged.

Regenerate with Python, `cryptography >= 42` and `cbor2`:

```console
python crates/scitt-verifier/tests/fixtures/external-chain/generate.py
```

The baseline external path is a 2048-bit RSA leaf, intermediate and self-signed
root, every certificate signed with RSA-PSS SHA-384, MGF1 SHA-384, and a 48-byte
salt. The detached signature also uses PS384. A second statement carries it in
a detached-payload COSE_Sign1. Independent throwaway EC keys sign the envelope
and synthetic receipt, so changing the external path does not break either.

Negative fixtures are signed and receipted again after damaging the external
path. They isolate tampered certificate signatures, missing certificates,
truncated DER, malformed entries, unsupported PSS parameters, ECDSA certificate
signatures, and an unhandled critical extension. The signature key remains
usable even in unsupported-chain cases. Registration-time fixtures establish
that validity uses verified receipt times, not the envelope's out-of-window
`iat`. `expected.json` records generated anchor/path hashes and validity bounds;
these are synthetic values, not independently authenticated manufacturer pins.
`roots.pem` contains the same synthetic root for HTTPS bundle parsing and
acquisition tests. It is extracted from the baseline fixture; the generator
also writes it on regeneration. It contains no private key.

Review regressions also cover a malformed first chain entry, empty or
wrong-typed chains, missing chains, rejected nested signatures, and a nested
signature over a different embedded payload. The latter fails payload binding
before its signature is checked, so its signature result must remain `null`.
