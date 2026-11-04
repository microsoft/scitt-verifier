# Fixtures

Copied unchanged from
[microsoft/TEE-Attestation-Verification](https://github.com/microsoft/TEE-Attestation-Verification)
`attestation/tests/test_data/` at revision
`a52c499f64aeb5014c94c1faf5ac33c38a195280`, the revision the workspace pins:

| File | What it is |
|---|---|
| `turin_attestation_report.bin` | A version 5 SEV-SNP report from a Turin part, made without a nonce (`REPORT_DATA` is all zeros) |
| `turin_vcek.pem` | The VCEK AMD's KDS issued for that chip at that TCB |
| `turin_kds_ask.pem`, `turin_kds_ark.pem` | AMD's Turin ASK and ARK, as KDS serves them |

The hardware BOM payloads in `src/tests.rs` are invented. The only real
value they carry, the serial, is read from the report at test time.
