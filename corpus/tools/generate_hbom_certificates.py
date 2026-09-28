"""Generate synthetic certificate-only test evidence (never vendor hardware data).

Requires Python cryptography and cbor2. The existing real SCITT corpus statement
provides accepted signed bytes; its arbitrary payload is a stand-in for HBOM
bytes in this isolated certificate-binding test, not an HBOM document.
"""

import base64
import datetime as dt
import hashlib
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures" / "synthetic-hbom"
OUT.mkdir(exist_ok=True)
OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
EKU = ObjectIdentifier("1.3.6.1.4.1.55555.1.2")
payload = cbor2.loads((ROOT / "fixtures" / "transparent-statement.cose").read_bytes())
hbom_stand_in = payload.value[2] if isinstance(payload, cbor2.CBORTag) else payload[2]
digest = hashlib.sha384(hbom_stand_in).digest()
synthetic_hbom = (
    b'{"documentType":"synthetic-hbom","components":[{"id":"TEST-ONLY-PART"}]}\n'
)
(OUT / "hbom.json").write_bytes(synthetic_hbom)
start = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
end = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)


def name(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
root_name = name("Synthetic HBOM Test Root")
root = (
    x509.CertificateBuilder()
    .subject_name(root_name)
    .issuer_name(root_name)
    .public_key(root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(start)
    .not_valid_after(end)
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    .sign(root_key, hashes.SHA256())
)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


(OUT / "root.pem").write_bytes(pem(root))
other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
other_name = name("Unrelated Synthetic Root")
other_root = (
    x509.CertificateBuilder()
    .subject_name(other_name)
    .issuer_name(other_name)
    .public_key(other_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(start)
    .not_valid_after(end)
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    .sign(other_key, hashes.SHA256())
)
(OUT / "untrusted-root.pem").write_bytes(pem(other_root))


def leaf(label, commitment=digest, valid_from=start, valid_to=end, with_extension=True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(label))
        .issuer_name(root_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([EKU]), critical=False)
    )
    if with_extension:
        builder = builder.add_extension(x509.UnrecognizedExtension(OID, commitment), critical=False)
    return builder.sign(root_key, hashes.SHA256())


good = leaf("Synthetic HBOM Binding")
for filename, certificate in [
    ("good.pem", good),
    ("mismatch.pem", leaf("Synthetic Other Bytes", b"\x00" * 48)),
    ("malformed.pem", leaf("Synthetic Malformed Extension", b"\x04\x02\x01\x02")),
    ("missing.pem", leaf("Synthetic Missing Extension", with_extension=False)),
    ("expired.pem", leaf("Synthetic Expired", valid_to=dt.datetime(2025, 2, 1, tzinfo=dt.timezone.utc))),
    ("der-octet.pem", leaf("Synthetic DER OCTET", b"\x04\x30" + digest)),
    ("hbom.pem", leaf("Synthetic HBOM Document", hashlib.sha384(synthetic_hbom).digest())),
]:
    (OUT / filename).write_bytes(pem(certificate))

broken = bytearray(good.public_bytes(serialization.Encoding.DER))
broken[-1] ^= 1
(OUT / "broken.pem").write_bytes(
    b"-----BEGIN CERTIFICATE-----\n"
    + base64.encodebytes(broken)
    + b"-----END CERTIFICATE-----\n"
)
(OUT / "ambiguous.pem").write_bytes(pem(good) + pem(leaf("Synthetic Second Leaf")))
print("Synthetic root SHA-256:", hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).hexdigest())
