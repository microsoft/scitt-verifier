"""Re-register the committed statements without replacing the offline corpus.

Requires the same dependencies as generate_fixtures.py and a ledger whose
registration policy accepts the corpus signers. Output must be a new or empty
directory outside corpus/fixtures. No signing keys are needed: only the
unsigned receipt bucket changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

import cbor2
from cryptography import x509
from pyscitt.client import Client
from pyscitt.verify import StaticTrustStore, verify_transparent_statement

import generate_fixtures as fixtures


SOURCE = Path(__file__).resolve().parents[1] / "fixtures"
STATEMENTS = (
    "transparent-statement.cose",
    "cbor-header.cose",
    "nested-sign1.cose",
    "image-reproduction/statement.cose",
    "amd-snp-device/statement.cose",
)


def signed_bytes(statement: bytes) -> bytes:
    protected, _, payload, signature = cbor2.loads(statement).value
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, help="transparency service hostname")
    parser.add_argument("--out", required=True, type=Path, help="new live-fixture directory")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.is_relative_to(SOURCE) or SOURCE.is_relative_to(out):
        parser.error("--out must be outside the committed fixtures and their ancestors")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        parser.error("--out must be a new or empty directory")

    statements = {name: signed_bytes((SOURCE / name).read_bytes()) for name in STATEMENTS}
    files = {
        name: (SOURCE / name).read_bytes()
        for name in (
            "artifact.bin",
            "bad-artifact.bin",
            "image-reproduction/published-reproduce.json",
            "image-reproduction/rebuilt-reproduce.json",
        )
    }
    certificate = fixtures.service_cert(args.ledger)
    cert = x509.load_pem_x509_certificate(certificate.encode("ascii"))
    service_trust = StaticTrustStore(certificates=[fixtures.der(cert)])
    entries = {}
    with tempfile.TemporaryDirectory(prefix="scitt-seed-") as directory:
        bundle = Path(directory) / "service-cert.pem"
        bundle.write_text(certificate, encoding="ascii")
        client = Client(f"https://{args.ledger}", cacert=str(bundle))
        keys = client.get("/.well-known/scitt-keys").read()
        key_trust = StaticTrustStore(cose_keys=cbor2.loads(keys))
        for name, signed in statements.items():
            submission = client.submit_signed_statement_and_wait_for_receipt(signed)
            transparent = (
                submission.response_bytes
                if submission.is_receipt_embedded
                else client.get_transparent_statement(submission.tx)
            )
            if signed_bytes(transparent) != signed:
                raise ValueError(f"{name}: registration changed the signed statement")
            verify_transparent_statement(transparent, key_trust, signed)
            verify_transparent_statement(transparent, service_trust, signed)
            files[name] = transparent
            entries[name] = {
                "transactionId": submission.tx,
                "claimDigest": hashlib.sha256(signed).hexdigest(),
            }
            print(f"{name}: registered and verified at {submission.tx}", flush=True)

    transparent = files["transparent-statement.cose"]
    files.update(
        {
            "tampered-statement.cose": fixtures.tampered_receipt(transparent),
            "payload-tampered.cose": fixtures.tampered_payload(transparent),
            "appended-receipt.cose": fixtures.appended_receipt(transparent),
            "hostile-subject.cose": fixtures.hostile_subject(transparent),
            fixtures.KEY_SET_NAME: keys,
            fixtures.SERVICE_CERT_NAME: certificate.replace("\r\n", "\n").encode("ascii"),
            "registrations.json": json.dumps(
                {"ledger": args.ledger, "entries": entries}, indent=2
            ).encode("ascii"),
        }
    )
    for name, data in files.items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(f"Live fixtures saved to {out}; committed fixtures unchanged.")


if __name__ == "__main__":
    main()
