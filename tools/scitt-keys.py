#!/usr/bin/env python3
"""Obtain and review the trust material that scitt-verifier needs.

This is a prototype of the planned `scitt-keys` binary. It is deliberately
separate from the verifier: `scitt-verifier verify` never touches the network,
and nothing here should ever run in a deployment gate.

    scitt-keys.py fetch --issuer <host> --out <file> [--service-cert <pem>]
    scitt-keys.py show  <file>
    scitt-keys.py diff  <old> <new>

Requires: cryptography, cbor2   (pip install cryptography cbor2)
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError as exc:  # pragma: no cover - environment problem, not logic
    sys.exit(f"missing dependency: {exc.name}\n  pip install cryptography cbor2")

TOOL_VERSION = "0.1.0-prototype"

# Azure-managed Confidential Ledger instances bootstrap trust here. This host is
# certified by the public Azure PKI; it is the one thing we take on faith.
AZURE_LEDGER_SUFFIX = ".confidential-ledger.azure.com"
AZURE_IDENTITY_URL = (
    "https://identity.confidential-ledger.core.azure.com/ledgerIdentity/{name}"
)

KEYSET_PATH = "/.well-known/scitt-keys"
COSE_KEY_KID = 2  # COSE_Key label for the key identifier
HTTP_TIMEOUT = 30

# Exit codes. `fetch` and `diff` share the change-reporting codes so a caller can
# branch the same way on either.
EXIT_UNCHANGED = 0
EXIT_UNTRUSTED = 1  # could not establish trust in the material
EXIT_USAGE = 2
EXIT_KEYS_ADDED = 3  # normal rotation - commit it
EXIT_KEYS_REMOVED = 4  # unusual - a human should look


class Untrusted(Exception):
    """Trust in the fetched material could not be established."""


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------
# COSE_Key_Set inspection
# --------------------------------------------------------------------------


def normalise_kid(kid: object) -> str:
    """Render a COSE_Key `kid` as the lowercase hex string used for comparison.

    MST stores the kid as 64 ASCII hex characters inside a byte string, and that
    value equals hex(SHA-256(SubjectPublicKeyInfo DER)). Other services may store
    the 32 raw digest bytes instead, so accept both and normalise to hex text.
    """
    if isinstance(kid, str):
        return kid.strip().lower()
    if not isinstance(kid, (bytes, bytearray)):
        raise Untrusted(f"key identifier has unexpected CBOR type {type(kid).__name__}")

    raw = bytes(kid)
    if len(raw) == 64:
        try:
            text = raw.decode("ascii").lower()
        except UnicodeDecodeError:
            pass
        else:
            if all(c in "0123456789abcdef" for c in text):
                return text
    return binascii.hexlify(raw).decode("ascii")


def read_keyset(data: bytes) -> list[str]:
    """Return the key identifiers in a COSE_Key_Set, in file order."""
    try:
        keyset = cbor2.loads(data)
    except Exception as exc:
        raise Untrusted(f"not decodable as CBOR: {exc}") from exc

    if not isinstance(keyset, list):
        raise Untrusted(
            f"expected a COSE_Key_Set (CBOR array), found {type(keyset).__name__}"
        )
    if not keyset:
        raise Untrusted("key set is empty; no receipt could ever be verified with it")

    kids: list[str] = []
    for index, key in enumerate(keyset):
        if not isinstance(key, dict):
            raise Untrusted(f"key {index} is not a COSE_Key map")
        if COSE_KEY_KID not in key:
            raise Untrusted(f"key {index} has no kid (label 2); it cannot be selected")
        kids.append(normalise_kid(key[COSE_KEY_KID]))

    duplicates = {k for k in kids if kids.count(k) > 1}
    if duplicates:
        raise Untrusted(f"duplicate key identifiers: {', '.join(sorted(duplicates))}")
    return kids


def spki_kid(cert_pem: str) -> tuple[str, str, str]:
    """Return (kid, subject, sha256-of-certificate) for a PEM certificate."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as exc:
        raise Untrusted(f"service certificate is not valid PEM: {exc}") from exc

    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return (
        hashlib.sha256(spki).hexdigest(),
        cert.subject.rfc4514_string(),
        hashlib.sha256(cert_der).hexdigest(),
    )


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------


def ledger_name(issuer: str) -> str:
    host = issuer.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
    if not host:
        raise Untrusted("--issuer is empty")
    return host


def fetch_service_certificate(host: str) -> tuple[str, str]:
    """Fetch the CCF service certificate from the Azure identity service.

    Returns (pem, identity_url). This is the only step that relies on the public
    certificate authorities, and it is the root of the whole trust chain.
    """
    if not host.endswith(AZURE_LEDGER_SUFFIX):
        raise Untrusted(
            f"{host} is not an Azure-managed Confidential Ledger, so its service\n"
            "  certificate cannot be looked up automatically. Obtain the CCF service\n"
            "  certificate from the ledger operator and pass --service-cert <file>."
        )

    name = host[: -len(AZURE_LEDGER_SUFFIX)]
    url = AZURE_IDENTITY_URL.format(name=name)
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as response:
            identity = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise Untrusted(
            f"identity service returned HTTP {exc.code} for {name}. Check the "
            "ledger name in --issuer."
        ) from exc
    except Exception as exc:
        raise Untrusted(f"could not reach the identity service at {url}: {exc}") from exc

    pem = identity.get("ledgerTlsCertificate")
    if not pem:
        raise Untrusted(
            f"identity service response for {name} has no ledgerTlsCertificate"
        )
    return pem, url


def pinned_context(cert_pem: str) -> ssl.SSLContext:
    """Build an SSL context that trusts the given certificate and nothing else.

    Deliberately does not call load_default_certs(): a CCF ledger is not certified
    by any public authority, so falling back to the system trust store would mean
    accepting a completely different service.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cadata=cert_pem)
    except ssl.SSLError as exc:
        raise Untrusted(f"service certificate could not be loaded: {exc}") from exc
    return context


def fetch_keyset(host: str, context: ssl.SSLContext) -> bytes:
    url = f"https://{host}{KEYSET_PATH}"
    try:
        with urllib.request.urlopen(
            url, context=context, timeout=HTTP_TIMEOUT
        ) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Untrusted(
                f"{url} returned 404.\n"
                "  This ledger predates the SCITT key set endpoint. Upgrade it.\n"
                "  The /jwks endpoint is deliberately not used as a fallback: its key\n"
                "  identifiers must be re-derived by hand, and getting that wrong looks\n"
                "  identical to a stale trust store."
            ) from exc
        raise Untrusted(f"{url} returned HTTP {exc.code}") from exc
    except Exception as exc:
        # urllib wraps TLS failures in URLError, so unwrap before reporting: a
        # pinning failure and an unreachable host need very different responses.
        cause = getattr(exc, "reason", None)
        if isinstance(exc, ssl.SSLError) or isinstance(cause, ssl.SSLError):
            raise Untrusted(
                f"TLS verification against the pinned service certificate failed.\n"
                f"  {cause or exc}\n"
                f"  {host} did not present a certificate issued by the expected CCF\n"
                "  service. Either the certificate is stale, or this is not the service\n"
                "  it claims to be."
            ) from exc
        raise Untrusted(f"could not reach {url}: {exc}") from exc

    if not body:
        raise Untrusted(f"{url} returned an empty body")
    return body


def assert_self_binding(kids: list[str], tls_kid: str, host: str) -> None:
    """Require the pinned service key to appear in the key set it served.

    Without this the fetch only proves that some host holding this certificate
    served us some bytes. With it, the key set is bound to the identity that the
    Azure identity service attested to.
    """
    if tls_kid not in kids:
        raise Untrusted(
            f"the key set served by {host} does not contain the service's own key.\n"
            f"  expected kid {tls_kid}\n"
            f"  found        {', '.join(kids) if kids else '(none)'}\n"
            "  Refusing to write trust material that is not bound to the service\n"
            "  certificate the identity service published."
        )


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def describe_change(old: list[str] | None, new: list[str]) -> tuple[int, list[str]]:
    """Compare key sets and return (exit code, human-readable lines)."""
    if old is None:
        return EXIT_UNCHANGED, [f"new trust material: {len(new)} key(s)"]

    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]

    lines = [f"  + {kid}" for kid in added]
    lines += [f"  - {kid}" for kid in removed]

    if not added and not removed:
        return EXIT_UNCHANGED, [f"unchanged: {len(new)} key(s)"]
    if removed:
        lines.append("")
        lines.append(
            "Keys were REMOVED. Disaster recovery and routine rotation both retain\n"
            "old keys, so a healthy change only ever adds them. Find out why before\n"
            "committing this: receipts issued under a removed key can no longer be\n"
            "verified."
        )
        return EXIT_KEYS_REMOVED, lines
    return EXIT_KEYS_ADDED, lines


def provenance_path(out: Path) -> Path:
    return out.with_suffix(out.suffix + ".provenance.json")


def cmd_fetch(args: argparse.Namespace) -> int:
    if os.environ.get("CI") and not args.refresh:
        print(
            "refusing to fetch trust material inside CI.\n"
            "\n"
            "  Fetching keys during a build means whoever controls the network at that\n"
            "  moment controls what the gate trusts. Commit the key set instead and\n"
            "  point scitt-verifier at the committed file.\n"
            "\n"
            "  If this is a scheduled job that opens a pull request when keys rotate,\n"
            "  say so explicitly with --refresh.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    host = ledger_name(args.issuer)
    out = Path(args.out)

    if args.service_cert:
        cert_pem = Path(args.service_cert).read_text(encoding="utf-8")
        identity_url = None
        print(f"service certificate: {args.service_cert} (supplied out of band)")
    else:
        cert_pem, identity_url = fetch_service_certificate(host)
        print(f"service certificate: {identity_url}")

    tls_kid, subject, cert_sha256 = spki_kid(cert_pem)
    print(f"  subject {subject}")
    print(f"  sha-256 {cert_sha256}")

    body = fetch_keyset(host, pinned_context(cert_pem))
    kids = read_keyset(body)
    assert_self_binding(kids, tls_kid, host)

    keyset_sha256 = hashlib.sha256(body).hexdigest()
    print(f"key set: https://{host}{KEYSET_PATH}")
    print(f"  {len(body)} bytes, sha-256 {keyset_sha256}")
    print(f"  {len(kids)} key(s), service key present and bound")

    previous = None
    if out.exists():
        try:
            previous = read_keyset(out.read_bytes())
        except Untrusted as exc:
            warn(f"existing {out} could not be read ({exc}); treating as new")

    code, lines = describe_change(previous, kids)
    print()
    for line in lines:
        print(line)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(body)

    provenance = {
        "issuer": host,
        "identity_endpoint": identity_url,
        "service_cert_source": (
            "identity-service" if identity_url else "operator-supplied"
        ),
        "service_cert_subject": subject,
        "service_cert_sha256": cert_sha256,
        "service_key_kid": tls_kid,
        "self_binding_verified": True,
        "keyset_sha256": keyset_sha256,
        "keyset_bytes": len(body),
        "kids": kids,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_version": TOOL_VERSION,
    }
    sidecar = provenance_path(out)
    sidecar.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    print()
    print(f"wrote {out}")
    print(f"wrote {sidecar}")
    print()
    print("Commit both files. The sidecar is what makes the key set reviewable.")
    return code


def cmd_show(args: argparse.Namespace) -> int:
    path = Path(args.file)
    body = path.read_bytes()
    kids = read_keyset(body)

    print(f"{path}")
    print(f"  {len(body)} bytes, sha-256 {hashlib.sha256(body).hexdigest()}")
    print(f"  {len(kids)} key(s):")
    for kid in kids:
        print(f"    {kid}")

    sidecar = provenance_path(path)
    if not sidecar.exists():
        print()
        print(
            "No provenance sidecar. This key set's authenticity rests entirely on how\n"
            "it was obtained, which is not recorded anywhere."
        )
        return EXIT_UNCHANGED

    provenance = json.loads(sidecar.read_text(encoding="utf-8"))
    print()
    print(f"provenance ({sidecar.name}):")
    for field in (
        "issuer",
        "service_cert_source",
        "service_cert_subject",
        "service_key_kid",
        "fetched_at",
        "tool_version",
    ):
        if provenance.get(field) is not None:
            print(f"  {field}: {provenance[field]}")

    if provenance.get("keyset_sha256") != hashlib.sha256(body).hexdigest():
        print()
        print(
            "MISMATCH: the sidecar records a different digest than this file.\n"
            "The key set has been modified since it was fetched.",
            file=sys.stderr,
        )
        return EXIT_UNTRUSTED
    return EXIT_UNCHANGED


def cmd_diff(args: argparse.Namespace) -> int:
    old = read_keyset(Path(args.old).read_bytes())
    new = read_keyset(Path(args.new).read_bytes())
    code, lines = describe_change(old, new)
    for line in lines:
        print(line)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scitt-keys.py",
        description=(
            "Obtain and review the transparency service keys that scitt-verifier "
            "needs. Never run this in a deployment gate."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    fetch = sub.add_parser("fetch", help="fetch a key set and record its provenance")
    fetch.add_argument(
        "--issuer",
        required=True,
        help="transparency service host, e.g. example.confidential-ledger.azure.com",
    )
    fetch.add_argument("--out", required=True, help="file to write the COSE_Key_Set to")
    fetch.add_argument(
        "--service-cert",
        help=(
            "PEM CCF service certificate, for ledgers not managed by Azure. "
            "Required when --issuer is not an Azure Confidential Ledger."
        ),
    )
    fetch.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "declare that this is a scheduled rotation job, permitting it to run in CI"
        ),
    )
    fetch.set_defaults(func=cmd_fetch)

    show = sub.add_parser("show", help="describe a key set and its provenance, offline")
    show.add_argument("file")
    show.set_defaults(func=cmd_show)

    diff = sub.add_parser("diff", help="compare two key sets, offline")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except Untrusted as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNTRUSTED
    except FileNotFoundError as exc:
        print(f"error: {exc.filename}: no such file", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
