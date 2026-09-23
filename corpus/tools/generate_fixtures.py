"""Regenerate the conformance corpus against a transparency service.

The corpus is real bytes from a real service, so it cannot be repaired by hand:
the receipt covers the ledger hostname in its own protected header, and the
Issuer's signature covers the payload. When the service a fixture was
registered against is decommissioned, the only honest repair is to register
equivalent statements somewhere else and recapture the results.

Committing this script is the point of issue #19. The previous corpus was
produced by hand, so nobody could reproduce it, and a dead ledger became a
problem with no bounded fix. Running this against a live service reproduces the
whole corpus in one pass.

Every signing identity is minted here and thrown away. No part number, serial,
subject, or organisation in the output refers to anything that exists. The
receipts, inclusion proofs, and root signatures are genuine, because each
statement really is registered.

Requires `pyscitt` (from the scitt-ccf-ledger repository) plus `cbor2`,
`httpx`, and `cryptography`. Registration needs a service whose policy accepts
the statement; an unauthenticated `return true` policy is enough.

    python corpus/tools/generate_fixtures.py \
        --ledger mst-test-scitt-verifier.confidential-ledger.azure.com \
        --out corpus/fixtures

It prints the pinned claim digest, signed length, and `did:x509` issuer at the
end. All three move with a freshly minted CA and have to be pasted into
`crates/scitt-receipt/tests/conformance.rs`,
`crates/scitt-wasm/tests/corpus.node.mjs`, and
`crates/scitt-verifier/tests/acceptance.rs`.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import cbor2
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from pyscitt import crypto
from pyscitt.client import Client

IDENTITY_SERVICE = "https://identity.confidential-ledger.core.azure.com/ledgerIdentity"

# COSE header labels used below. 394 is SCITT's receipts label; the rest are
# RFC 9052's.
ALG, KID, CONTENT_TYPE, X5T, X5CHAIN, RECEIPTS = 1, 4, 3, 34, 33, 394
SIGNATURE = -1
ALG_RS256, ALG_ES256, ALG_PS256 = -257, -7, -37
HASH_SHA256 = -16
CWT, CWT_ISS = 15, 1
CCF_PROOF = 396

# The payload of the base statement is the artifact itself, so the binding
# check has something to compare against. The trailing CRLF is load bearing: it
# is what makes `artifact.bin` a file git will silently corrupt unless
# `.gitattributes` marks it binary, which is the regression
# `fixtures_are_byte_exact` guards.
ARTIFACT = b"Hello from MST Team\r\n"

# A different artifact, for the negative binding case. Its only requirement is
# that it is not `ARTIFACT`; it is pinned here so that regenerating the corpus
# does not churn a file whose bytes carry no other meaning.
NOT_THE_ARTIFACT = b"Hello from MST Team!"

# The corpus refers to the key set by a stable name rather than by the
# hostname it came from. The hostname is recorded in `corpus/README.md` and is
# signed into every receipt, so nothing is lost -- but naming the file after a
# particular service is what made the last regeneration touch the test suite,
# the workflows and the demo. Replacing the ledger should not rename a file.
KEY_SET_NAME = "mst-test-scitt-keys.cbor"

# The CWT subject of the base statement. Several policy tests match on it
# exactly, so it is part of the corpus's contract rather than a free choice.
BASE_SUBJECT = "unknown.intent"

# The same field, filled with the characters a terminal acts on rather than
# prints. Exactly as long as `BASE_SUBJECT`, so it can be substituted into a
# finished statement without re-encoding anything around it.
#
# A statement is untrusted input, and `inspect` displays it without verifying
# anything. Unescaped, this value ends the line it is printed on and starts one
# that reads like a verdict, in the colour the real ones use.
HOSTILE_SUBJECT = "a\r\n PASS \x1b[32m"

# Certificates outlive the fixtures deliberately. A short-lived certificate
# would make `inspect` report an expired chain years before anything was
# actually wrong with the corpus, which trains readers to ignore the field.
CERT_LIFETIME_DAYS = 365 * 20

# RFC 9052 makes text labels private use, so a supplier may carry anything
# here. These are the two shapes seen in practice: a hand-rolled descriptor
# map, and COSE's own nested COSE_Sign1.
EXTERNAL_SIGNATURE = "external-signature"
EXTERNAL_STATEMENT = "external-statement"

# An arc reserved for documentation. Pinning a real product's EKU would make
# this corpus refer to something that exists.
SUPPLIER_EKU = "2.999"
SIGNING_EKU = "1.3.6.1.4.1.311.97.1.3.1"


# --------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org is not None:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def make_cert(
    key,
    cn: str,
    *,
    org: str | None = None,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: Any | None = None,
    ca: bool = False,
    eku: str | None = None,
) -> x509.Certificate:
    """Build one certificate, self-signed when no issuer is given."""
    now = datetime.datetime.now(datetime.UTC)
    pub = key.public_key()
    subject = _name(cn, org)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_LIFETIME_DAYS))
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    )
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(eku)]), critical=False
        )
    return builder.sign(issuer_key if issuer_key is not None else key, hashes.SHA256())


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def did_x509(ca_cert: x509.Certificate, eku: str) -> str:
    """The did:x509 an MST issuer is expected to present.

    The fingerprint names the certificate that issued the leaf -- `x5chain[1]`
    -- and the service refuses a statement whose did does not resolve against
    the chain it carries. Base64url here is unpadded; a padded value is
    rejected as an invalid fingerprint.
    """
    fp = crypto.b64url(hashlib.sha256(der(ca_cert)).digest()).rstrip("=")
    return f"did:x509:0:sha256:{fp}::eku:{eku}"


# --------------------------------------------------------------------------
# service
# --------------------------------------------------------------------------


def service_cert(ledger: str) -> str:
    """Fetch the ledger's service certificate from the identity service.

    A CCF node serves a certificate no public root signs, so TLS verification
    against the system bundle fails. The identity service *is* publicly
    trusted, which is how the service certificate is bootstrapped -- using it
    as the CA bundle means this script never disables verification.
    """
    resp = httpx.get(f"{IDENTITY_SERVICE}/{ledger.split('.')[0]}", timeout=30)
    resp.raise_for_status()
    return resp.json()["ledgerTlsCertificate"]


def register(client: Client, signed: bytes) -> bytes:
    """Register a signed statement, returning the transparent statement."""
    submission = client.submit_signed_statement_and_wait_for_receipt(signed)
    if submission.is_receipt_embedded:
        return submission.response_bytes
    return client.get_transparent_statement(submission.tx)


# --------------------------------------------------------------------------
# statements
# --------------------------------------------------------------------------


def base_statement() -> bytes:
    """PS256 over the artifact bytes, under a four-certificate chain.

    The shape is pinned by the acceptance suite, not chosen for convenience:
    `x5chain` must hold four certificates and `x5t` must be present, because
    tests address `[33]` and `[34, 0]` to prove that a policy path can reach
    into an array and that `inspect` renders a hash algorithm's numeric value.
    """
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    policy_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    root = make_cert(root_key, "Example Corpus Root CA", ca=True)
    policy_ca = make_cert(
        policy_key,
        "Example Corpus Policy CA",
        issuer_cert=root,
        issuer_key=root_key,
        ca=True,
    )
    issuing = make_cert(
        issuing_key,
        "Example Corpus Issuing CA",
        issuer_cert=policy_ca,
        issuer_key=policy_key,
        ca=True,
    )
    leaf = make_cert(
        leaf_key,
        "example-signer",
        issuer_cert=issuing,
        issuer_key=issuing_key,
        eku=SIGNING_EKU,
    )

    signer = crypto.Signer(
        private_key=key_pem(leaf_key),
        issuer=did_x509(issuing, SIGNING_EKU),
        algorithm="PS256",
        x5c=[pem(leaf), pem(issuing), pem(policy_ca), pem(root)],
    )
    return crypto.sign_statement(
        signer,
        ARTIFACT,
        content_type="application/cose",
        feed=BASE_SUBJECT,
        cwt=True,
        additional_phdr={X5T: [HASH_SHA256, hashlib.sha256(der(leaf)).digest()]},
    )


def supplier_identity() -> tuple[Any, x509.Certificate]:
    """A self-signed RSA identity standing in for a component supplier.

    Self-signed on purpose. It is what makes the fixture an honest
    demonstration of the assertion's ceiling: `externalSignatures` can prove
    the signature was made by the key in this certificate, and nothing at all
    about whose key that is.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    # Both name parts are load-bearing: acceptance policies assert on the
    # organisation and the receipt suite asserts on the common name.
    cert = make_cert(
        key,
        "Example External Signer",
        org="Example Component Supplier",
        eku=SUPPLIER_EKU,
    )
    return key, cert


def envelope_identity() -> tuple[Any, list[x509.Certificate]]:
    """An ES256 leaf under a throwaway CA, for the outer statement."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca = make_cert(ca_key, "Example Corpus Test CA", ca=True)
    leaf = make_cert(
        leaf_key,
        "example-envelope-signer",
        issuer_cert=ca,
        issuer_key=ca_key,
        eku=SUPPLIER_EKU,
    )
    return leaf_key, [leaf, ca]


def manifest(build_id: str, version: str, digest: str) -> bytes:
    """A small, obviously invented component manifest."""
    return json.dumps(
        {
            "artifact": "example-component",
            "buildId": build_id,
            "digest": f"sha256:{digest}",
            "version": version,
        }
    ).encode("ascii")


def cbor_header_statement() -> bytes:
    """A supplier signature carried as a hand-rolled descriptor map.

    The descriptor is the shape CoseSignTool's `--cbph` produces: algorithm,
    key id, thumbprint, certificate chain and signature, under a text label.
    The signature is a raw RS256 signature over the payload bytes, because the
    descriptor has no `Sig_structure` to say anything else.
    """
    payload = manifest(
        "20260212.3",
        "1.4.0",
        "9f2c1d0a7b5e4318c6a90d2f8e17b40539ac6e2d1f8b03c47a5e69d81b2f4c07",
    )
    supplier_key, supplier_cert = supplier_identity()
    signature = supplier_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    descriptor = {
        ALG: ALG_RS256,
        KID: b"example-external-key-1",
        X5T: [HASH_SHA256, hashlib.sha256(der(supplier_cert)).digest()],
        X5CHAIN: [der(supplier_cert)],
        SIGNATURE: signature,
    }

    leaf_key, chain = envelope_identity()
    signer = crypto.Signer(
        private_key=key_pem(leaf_key),
        issuer=did_x509(chain[1], SUPPLIER_EKU),
        algorithm="ES256",
        x5c=[pem(c) for c in chain],
    )
    return crypto.sign_statement(
        signer,
        payload,
        content_type="application/json",
        feed="example-artifact-0001",
        cwt=True,
        additional_phdr={EXTERNAL_SIGNATURE: [descriptor]},
    )


def nested_sign1_statement() -> bytes:
    """The same claim in COSE's own shape: a nested, detached COSE_Sign1.

    The payload is detached (`nil`) so the outer statement's bytes are not
    duplicated. `Sig_structure` then names exactly which bytes are covered,
    instead of leaving it to the convention the descriptor relies on.
    """
    payload = manifest(
        "20260904.1",
        "2.0.0",
        "41d0e6b8c3927fa5e14b8d0762a9c35801fe4d6b29307ca5148e6f03b7d29a4e",
    )
    supplier_key, supplier_cert = supplier_identity()

    inner_protected = cbor2.dumps(
        {ALG: ALG_RS256, X5CHAIN: [der(supplier_cert)]}, canonical=True
    )
    tbs = cbor2.dumps(["Signature1", inner_protected, b"", payload], canonical=True)
    signature = supplier_key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    nested = cbor2.CBORTag(18, [inner_protected, {}, None, signature])

    leaf_key, chain = envelope_identity()
    signer = crypto.Signer(
        private_key=key_pem(leaf_key),
        issuer=did_x509(chain[1], SUPPLIER_EKU),
        algorithm="ES256",
        x5c=[pem(c) for c in chain],
    )
    return crypto.sign_statement(
        signer,
        payload,
        content_type="application/json",
        feed="example-artifact-0002",
        cwt=True,
        additional_phdr={EXTERNAL_STATEMENT: nested},
    )


# --------------------------------------------------------------------------
# derived fixtures
# --------------------------------------------------------------------------


def receipts_of(statement: bytes) -> list[bytes]:
    tag = cbor2.loads(statement)
    return list(tag.value[1][RECEIPTS])


def flip_byte_in(statement: bytes, needle: bytes, offset_in_needle: int) -> bytes:
    """Flip one bit of `needle` where it appears in `statement`.

    Operating on the raw bytes rather than re-encoding keeps every other byte
    of the file identical, so a diff against the genuine fixture shows exactly
    one changed offset and nothing else.
    """
    at = statement.find(needle)
    if at < 0:
        raise SystemExit("could not locate the region to mutate")
    if statement.find(needle, at + 1) >= 0:
        raise SystemExit("region to mutate is ambiguous")
    index = at + offset_in_needle
    out = bytearray(statement)
    out[index] ^= 0x01
    return bytes(out)


def tampered_receipt(statement: bytes) -> bytes:
    """Flip a byte inside the receipt.

    The Issuer's signature still verifies -- the statement's own bytes are
    untouched -- but the transparency service's signature over the Merkle root
    does not. That is `cannot-evaluate`, not `untrusted`: an unproven claim is
    not a disproven one.
    """
    receipt = receipts_of(statement)[0]
    return flip_byte_in(statement, receipt, len(receipt) - 1)


def tampered_payload(statement: bytes) -> bytes:
    """Change the payload, leaving the receipt untouched.

    The most instructive fixture in the corpus. The receipt is genuine, its
    inclusion proof is valid, and its root signature verifies -- it is simply
    not evidence about *these* bytes, because the claims digest no longer
    matches. Any implementation that skips the binding check accepts this.
    """
    return flip_byte_in(statement, ARTIFACT, 1)


def appended_receipt(statement: bytes) -> bytes:
    """Append a second, corrupted receipt to the unprotected header.

    Receipts travel in the unprotected bucket, which no signature covers, so
    anyone handling the file can add one without holding a key. If that could
    flip a verdict, every mirror and CI cache would hold a veto over the gate.
    The genuine receipt is still present, and RFC 9943 s7.1 asks for at least
    one, so this must still pass.
    """
    tag = cbor2.loads(statement)
    genuine = tag.value[1][RECEIPTS][0]
    corrupted = bytearray(genuine)
    corrupted[-1] ^= 0x01
    tag.value[1][RECEIPTS] = [genuine, bytes(corrupted)]
    return cbor2.dumps(tag)


def hostile_subject(statement: bytes) -> bytes:
    """Overwrite the CWT subject with terminal control characters.

    Substituted into the finished bytes rather than signed, for the same
    reason as the other derived fixtures: every other byte of the file stays
    identical, so a diff shows exactly the region that changed. The issuer's
    signature no longer verifies over it, which costs nothing here -- this
    fixture exists for `inspect`, which authenticates nothing and displays
    the field regardless.

    Nobody needs a key to produce this. A statement is a file, and a file
    arrives from wherever it arrived from.
    """
    needle = cbor2.dumps(BASE_SUBJECT)
    replacement = cbor2.dumps(HOSTILE_SUBJECT)
    if len(needle) != len(replacement):
        raise SystemExit("hostile subject must encode to the same length")
    at = statement.find(needle)
    if at < 0:
        raise SystemExit("could not locate the subject to overwrite")
    if statement.find(needle, at + 1) >= 0:
        raise SystemExit("subject to overwrite is ambiguous")
    return statement[:at] + replacement + statement[at + len(needle) :]


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------


def merkle_root(transparent: bytes) -> str:
    """Recompute the CCF Merkle root the receipt's signature covers.

    Derived from the inclusion proof rather than read from the receipt, which
    does not carry the root: the leaf is
    `sha256(write_set_digest || sha256(commit_evidence) || claims_digest)`,
    folded through the proof's `[is_left, sibling]` pairs. Computing it here
    keeps the pinned value independent of the Rust implementation that also
    asserts it.
    """
    receipt = cbor2.loads(cbor2.loads(transparent).value[1][RECEIPTS][0])
    proof = receipt.value[1][CCF_PROOF][-1][0]
    proof = cbor2.loads(proof) if isinstance(proof, (bytes, bytearray)) else proof
    write_set, commit_evidence, claims = proof[1]
    if isinstance(commit_evidence, str):
        commit_evidence = commit_evidence.encode()
    node = hashlib.sha256(
        write_set + hashlib.sha256(commit_evidence).digest() + claims
    ).digest()
    for is_left, sibling in proof[2]:
        pair = (sibling + node) if is_left else (node + sibling)
        node = hashlib.sha256(pair).digest()
    return node.hex()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True, help="transparency service hostname")
    ap.add_argument("--out", required=True, type=Path, help="fixture directory")
    args = ap.parse_args()

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    bundle = Path(__file__).resolve().parent / "service-cert.pem"
    bundle.write_text(service_cert(args.ledger))
    client = Client(f"https://{args.ledger}", cacert=str(bundle))

    def emit(name: str, data: bytes) -> None:
        (out / name).write_bytes(data)
        print(f"  {name:34} {len(data):>6} bytes", file=sys.stderr)

    print(f"registering on {args.ledger}", file=sys.stderr)

    transparent = register(client, base_statement())
    emit("transparent-statement.cose", transparent)
    emit("tampered-statement.cose", tampered_receipt(transparent))
    emit("payload-tampered.cose", tampered_payload(transparent))
    emit("appended-receipt.cose", appended_receipt(transparent))
    emit("hostile-subject.cose", hostile_subject(transparent))

    emit("cbor-header.cose", register(client, cbor_header_statement()))
    emit("nested-sign1.cose", register(client, nested_sign1_statement()))

    keys = client.get("/.well-known/scitt-keys").read()
    emit(KEY_SET_NAME, keys)

    emit("artifact.bin", ARTIFACT)
    emit("bad-artifact.bin", NOT_THE_ARTIFACT)

    # Pinned values, computed here rather than copied from the tool under test.
    # The whole point of the constants in `conformance.rs` is that a second
    # implementation agrees with the first.
    tag = cbor2.loads(transparent)
    protected, _, payload, _ = tag.value
    stripped = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, tag.value[3]]))
    print("\npinned values for conformance.rs:", file=sys.stderr)
    print(f"  EXPECTED_SIGNED_LEN     {len(stripped)}", file=sys.stderr)
    print(
        f"  EXPECTED_CLAIM_DIGEST   {hashlib.sha256(stripped).hexdigest()}",
        file=sys.stderr,
    )
    # The issuer is a did:x509 over a freshly minted CA, so it moves with every
    # run. `acceptance.rs` pins it, so print it here rather than leaving the
    # next person to dig it out of the CBOR by hand.
    print("\nFIXTURE_ISSUER for acceptance.rs:", file=sys.stderr)
    print(f"  {cbor2.loads(protected)[CWT][CWT_ISS]}", file=sys.stderr)
    print("\npinned values for corpus.node.mjs and corpus/README.md:", file=sys.stderr)
    print(f"  merkleRoot              {merkle_root(transparent)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
