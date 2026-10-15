"""Mint synthetic critical-EKU statements and CCF-shaped receipts, not corpus evidence.

Requires cryptography >= 42 and cbor2. No private keys are written.
"""

import datetime
import hashlib
import importlib.util
import json
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "external_chain", OUT.parent / "external-chain" / "generate.py"
)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
OIDS = ["1.3.6.1.4.1.55555.1", "1.3.6.1.4.1.55555.2"]
BEFORE = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
AFTER = BEFORE + datetime.timedelta(days=3)
REGISTERED_AT = int((BEFORE + datetime.timedelta(days=1)).timestamp())
PAYLOAD = b'{"component":"synthetic-purpose-check"}'


def certificate(key, name, issuer=None, issuer_key=None, *, ca=False,
                eku=None, critical=True, basic=True, ca_flag=None,
                basic_critical=True, key_cert_sign=None, path_length=None,
                extra=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(shared.BEFORE if ca else BEFORE)
        .not_valid_after(shared.AFTER if ca else AFTER)
    )
    if basic:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca if ca_flag is None else ca_flag,
                                  path_length=path_length),
            critical=basic_critical,
        )
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False,
                      key_cert_sign=ca if key_cert_sign is None else key_cert_sign,
                      crl_sign=ca, encipher_only=False, decipher_only=False),
        critical=True,
    )
    if eku is not None:
        value = (
            x509.UnrecognizedExtension(x509.ExtensionOID.EXTENDED_KEY_USAGE, eku)
            if isinstance(eku, bytes)
            else x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid) for oid in eku])
        )
        builder = builder.add_extension(value, critical=critical)
    if extra is not None:
        builder = builder.add_extension(extra[0], critical=extra[1])
    return builder.sign(issuer_key if issuer_key is not None else key,
                        hashes.SHA384(), rsa_padding=padding.PKCS1v15())


def main():
    root_key, intermediate_key, leaf_key = [
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for _ in range(3)
    ]
    root = certificate(root_key, "Synthetic Purpose Root", ca=True)
    intermediate = certificate(intermediate_key, "Synthetic Purpose CA",
                               root, root_key, ca=True)
    leaf = certificate(leaf_key, "Synthetic Purpose Signer",
                       intermediate, intermediate_key, eku=OIDS)
    chain = [shared.der(leaf), shared.der(intermediate), shared.der(root)]
    ledger_key = ec.generate_private_key(ec.SECP256R1())
    spki = ledger_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kid = hashlib.sha256(spki).hexdigest().encode("ascii")
    point = ledger_key.public_key().public_numbers()
    (OUT / "keys.cbor").write_bytes(cbor2.dumps([
        {1: 2, 2: kid, -1: 1, -2: point.x.to_bytes(32, "big"),
         -3: point.y.to_bytes(32, "big")}
    ]))

    def statement(name, path, *, registered_at=REGISTERED_AT):
        protected = cbor2.dumps({
            1: -38, 3: "application/json", 33: path,
            15: {6: 0, 1: "synthetic-signer.example"},
        })
        signature = leaf_key.sign(shared.sig_structure(protected, PAYLOAD),
                                  shared.PSS, hashes.SHA384())
        signed = cbor2.CBORTag(18, [protected, {}, PAYLOAD, signature])
        claims = shared.digest(cbor2.dumps(signed))
        write_set = shared.digest(b"synthetic purpose write set")
        commit = "ce:1.1:00"
        merkle_root = shared.digest(write_set + shared.digest(commit.encode()) + claims)
        receipt_claims = {1: "synthetic-purpose-ledger.example"}
        if registered_at is not None:
            receipt_claims[6] = registered_at
        receipt_protected = cbor2.dumps({1: -7, 4: kid, 15: receipt_claims, 395: 2})
        proof = cbor2.dumps({1: [write_set, commit, claims], 2: []})
        receipt = cbor2.dumps(cbor2.CBORTag(18, [
            receipt_protected, {396: {-1: [proof]}}, None,
            shared.ec_sign(ledger_key, receipt_protected, merkle_root),
        ]))
        signed.value[1][394] = [receipt]
        (OUT / f"{name}.cose").write_bytes(cbor2.dumps(signed))

    statement("valid", chain)
    statement("duplicate-eku", [duplicate_eku(leaf, intermediate_key), *chain[1:]])
    statement("tampered-leaf", [shared.corrupt_signature(chain[0]), *chain[1:]])
    statement("tampered-intermediate",
              [chain[0], shared.corrupt_signature(chain[1]), chain[2]])
    statement("leaf-only", chain[:1])
    statement("late-registration", chain, registered_at=int(AFTER.timestamp()) + 1)
    statement("no-registration-time", chain, registered_at=None)
    for name, kwargs in [
        ("noncritical", {"eku": OIDS, "critical": False}),
        ("absent-eku", {}),
        # The tolerant parser returns a wanted OID before the truncated TLV.
        ("malformed-eku", {"eku": b"\x30\x0f\x06\x09\x2b\x06\x01\x04\x01\x83\xb2\x03\x01\x06\x05\x2a\x03"}),
        ("empty-eku", {"eku": b"\x30\x00"}),
        ("any-eku", {"eku": ["2.5.29.37.0"]}),
        ("unknown-critical", {"eku": OIDS, "extra": (
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55555.99"),
                                       b"\x05\x00"), True)}),
        ("skipped-extension", {"eku": OIDS, "extra": (
            x509.UnrecognizedExtension(x509.ExtensionOID.POLICY_CONSTRAINTS,
                                       b"\x30\x00"), False)}),
    ]:
        alternate = certificate(leaf_key, "Synthetic Purpose Signer",
                                intermediate, intermediate_key, **kwargs)
        statement(name, [shared.der(alternate), *chain[1:]])

    for name, kwargs in [
        ("ca-critical-eku", {"eku": OIDS}),
        ("ca-not-ca", {"ca_flag": False}),
        ("ca-missing-basic", {"basic": False}),
        ("ca-noncritical-basic", {"basic_critical": False}),
        ("ca-no-key-cert-sign", {"key_cert_sign": False}),
    ]:
        alternate = certificate(intermediate_key, "Synthetic Purpose CA",
                                root, root_key, ca=True, **kwargs)
        statement(name, [chain[0], shared.der(alternate), chain[2]])

    constrained_root = certificate(root_key, "Synthetic Purpose Root",
                                   ca=True, path_length=0)
    statement("path-length", [*chain[:2], shared.der(constrained_root)])
    (OUT / "expected.json").write_text(json.dumps({
        "rootSha256": hashlib.sha256(chain[2]).hexdigest(),
        "leafEkuOids": OIDS,
        "registeredAt": REGISTERED_AT,
    }, indent=2) + "\n", encoding="ascii")


def duplicate_eku(cert, issuer_key):
    # The certificate builder correctly refuses duplicate extensions. Encode
    # this invalid signed certificate explicitly to exercise verifier refusal.
    def tlv(tag, body):
        size = len(body)
        length = bytes([size]) if size < 128 else (
            bytes([0x80 | ((size.bit_length() + 7) // 8)])
            + size.to_bytes((size.bit_length() + 7) // 8, "big")
        )
        return bytes([tag]) + length + body

    def items(data):
        while data:
            first_length = data[1]
            count = first_length & 0x7f if first_length >= 128 else 0
            start = 2 + count
            length = int.from_bytes(data[2:start], "big") if count else first_length
            end = start + length
            yield data[0], data[start:end]
            data = data[end:]

    _, certificate_body = next(items(shared.der(cert)))
    (_, tbs), (_, algorithm), _ = list(items(certificate_body))
    fields = []
    for tag, value in items(tbs):
        if tag == 0xA3:
            _, extensions = next(items(value))
            eku = next(tlv(t, v) for t, v in items(extensions)
                       if next(items(v)) == (0x06, b"\x55\x1d\x25"))
            value = tlv(0x30, extensions + eku)
        fields.append(tlv(tag, value))
    encoded_tbs = tlv(0x30, b"".join(fields))
    signature = issuer_key.sign(encoded_tbs, padding.PKCS1v15(), hashes.SHA384())
    return tlv(0x30, encoded_tbs + tlv(0x30, algorithm)
               + tlv(0x03, b"\x00" + signature))


if __name__ == "__main__":
    main()
