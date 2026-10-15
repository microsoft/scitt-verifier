"""Generate SYNTHETIC external-chain regression fixtures, never partner data.

Requires cryptography >= 42 and cbor2. Run with:
    python crates/scitt-verifier/tests/fixtures/external-chain/generate.py

All keys are generated in memory and discarded. Neither the statements nor
their synthetic CCF receipts have ever been registered with a real service.
The real-service conformance corpus is separate and is not modified here.
"""

import datetime
import hashlib
import json
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent
BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
AFTER = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
REGISTERED_AT = 1792000000
PAYLOAD = b'{"component":"invented-component","serial":"synthetic-0001"}'
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)


def cert(key, name, issuer=None, issuer_key=None, *, ca=False, salt=48, critical=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(BEFORE)
        .not_valid_after(AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if critical:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.3")]),
            critical=True,
        )
    signer = issuer_key if issuer_key is not None else key
    if isinstance(signer, rsa.RSAPrivateKey):
        return builder.sign(
            signer,
            hashes.SHA384(),
            rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=salt),
        )
    return builder.sign(signer, hashes.SHA256())


def der(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)


def digest(data):
    return hashlib.sha256(data).digest()


def sig_structure(protected, payload):
    return cbor2.dumps(["Signature1", protected, b"", payload])


def ec_sign(key, protected, payload):
    encoded = key.sign(sig_structure(protected, payload), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(encoded)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def corrupt_signature(certificate):
    return certificate[:-1] + bytes([certificate[-1] ^ 1])


def main():
    root_key, intermediate_key, leaf_key = [
        rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)
    ]
    root = cert(root_key, "Synthetic Supplier Root", ca=True)
    intermediate = cert(
        intermediate_key, "Synthetic Supplier Intermediate", root, root_key, ca=True
    )
    leaf = cert(leaf_key, "Synthetic Supplier Signer", intermediate, intermediate_key)
    chain = [der(leaf), der(intermediate), der(root)]
    unsupported = cert(
        leaf_key, "Synthetic Supplier Signer", intermediate, intermediate_key, salt=32
    )
    critical = cert(
        leaf_key, "Synthetic Supplier Signer", intermediate, intermediate_key, critical=True
    )
    # ECDSA-signed RSA leaf: its detached RSA signature remains supported while
    # the certificate signature algorithm is beyond the pinned path backend.
    ec_ca_key = ec.generate_private_key(ec.SECP256R1())
    ec_ca = cert(ec_ca_key, "Synthetic ECDSA Root", ca=True)
    ec_leaf = cert(leaf_key, "Synthetic Supplier Signer", ec_ca, ec_ca_key)

    envelope_key = ec.generate_private_key(ec.SECP256R1())
    envelope_cert = cert(envelope_key, "Synthetic Statement Signer")
    ledger_key = ec.generate_private_key(ec.SECP256R1())
    ledger_spki = ledger_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kid = hashlib.sha256(ledger_spki).hexdigest().encode("ascii")
    point = ledger_key.public_key().public_numbers()
    (OUT / "keys.cbor").write_bytes(
        cbor2.dumps([{1: 2, 2: kid, -1: 1, -2: point.x.to_bytes(32, "big"),
                      -3: point.y.to_bytes(32, "big")}])
    )
    signature = leaf_key.sign(PAYLOAD, PSS, hashes.SHA384())

    def statement(name, external_chain, *, nested=False, bad_signature=False,
                  registered_at=REGISTERED_AT):
        detached_signature = signature
        if bad_signature:
            detached_signature = bytes(len(signature))
        if nested:
            protected = cbor2.dumps({1: -38, 33: external_chain})
            inner_signature = leaf_key.sign(
                sig_structure(protected, PAYLOAD), PSS, hashes.SHA384()
            )
            descriptor = cbor2.CBORTag(18, [protected, {}, None, inner_signature])
        else:
            descriptor = {1: -38, 33: external_chain, -1: detached_signature}
        # Deliberately outside the certificate window. Time assertions must
        # use independently attested receipt times, not this signer's claim.
        protected = cbor2.dumps({
            1: -7, 3: "application/json", 33: [der(envelope_cert)],
            15: {6: 0}, "external-signature": [descriptor],
        })
        signed = cbor2.CBORTag(
            18, [protected, {}, PAYLOAD, ec_sign(envelope_key, protected, PAYLOAD)]
        )
        claims = digest(cbor2.dumps(signed))
        write_set = digest(b"synthetic write set")
        commit = "ce:1.1:00"
        merkle_root = digest(write_set + digest(commit.encode()) + claims)
        receipt_claims = {1: "synthetic-ledger.example"}
        if registered_at is not None:
            receipt_claims[6] = registered_at
        receipt_protected = cbor2.dumps({1: -7, 4: kid, 15: receipt_claims, 395: 2})
        proof = cbor2.dumps({1: [write_set, commit, claims], 2: []})
        receipt = cbor2.dumps(cbor2.CBORTag(18, [
            receipt_protected, {396: {-1: [proof]}}, None,
            ec_sign(ledger_key, receipt_protected, merkle_root),
        ]))
        signed.value[1][394] = [receipt]
        (OUT / f"{name}.cose").write_bytes(cbor2.dumps(signed))

    statement("valid", chain)
    statement("nested", chain, nested=True)
    statement("bad-signature", chain, bad_signature=True)
    statement("tampered-leaf", [corrupt_signature(chain[0]), *chain[1:]])
    statement("tampered-intermediate", [chain[0], corrupt_signature(chain[1]), chain[2]])
    statement("missing-root", chain[:-1])
    statement("missing-intermediate", [chain[0], chain[2]])
    statement("leaf-only", chain[0])
    statement("truncated-der", [chain[0], chain[1][:-16], chain[2]])
    statement("truncated-leaf-der", [chain[0][:-16], *chain[1:]])
    statement("nested-truncated-leaf-der", [chain[0][:-16], *chain[1:]], nested=True)
    statement("malformed-entry", [chain[0], 7, chain[1], chain[2]])
    statement("nested-malformed-entry", [chain[0], 7, chain[1], chain[2]], nested=True)
    statement("unsupported-pss", [der(unsupported), *chain[1:]])
    statement("unsupported-ecdsa", [der(ec_leaf), der(ec_ca)])
    statement("unsupported-critical", [der(critical), *chain[1:]])
    statement("late-registration", chain, registered_at=2240611200)
    statement("no-registration-time", chain, registered_at=None)
    (OUT / "expected.json").write_text(json.dumps({
        "rootSha256": hashlib.sha256(chain[2]).hexdigest(),
        "certificateSha256": [hashlib.sha256(c).hexdigest() for c in chain],
        "pathNotBefore": int(BEFORE.timestamp()),
        "pathNotAfter": int(AFTER.timestamp()),
    }, indent=2) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
