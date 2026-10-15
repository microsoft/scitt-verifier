# Synthetic critical-EKU chains

These are synthetic regression fixtures, not real-service conformance evidence.
The generator reuses encoding and receipt helpers from `external-chain/generate.py`.
It mints throwaway RSA keys, an RSA SHA-384 certificate path, a PS384 statement,
and an ES256 CCF-shaped receipt. No partner input or private key is written.
The leaf has invented EKU OIDs and a three-day validity window in January 2024;
the verified receipt witnesses registration within that window. The statement's
own `iat` is deliberately outside it.

Regenerate with Python, `cryptography >= 42`, and `cbor2`:

```console
python crates/scitt-verifier/tests/fixtures/critical-eku/generate.py
```

Variants cover absent, malformed, duplicate, empty, noncritical and any-purpose leaf EKUs;
critical CA EKU; unknown critical and skipped extensions; invalid CA constraints,
key usage and path length; damaged signatures; incomplete paths; and missing or
late registration times. The malformed EKU places a wanted OID before truncated
DER, so tolerant decoding would falsely accept it.

`expected.json` contains only synthetic expected values. These fixtures were
not registered with a transparency service and do not replace the real corpus.
