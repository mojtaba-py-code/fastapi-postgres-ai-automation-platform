"""Create a local development CA and a TLS certificate for the demo stack.

    uv run python scripts/dev_certs.py [--domain localhost] [--out deploy/certs]

Writes, into the output directory (git-ignored):

* ``dev-ca.pem``     - the CA certificate (import it into a browser or pass it to
                       curl/httpx as the trust anchor; the platform trusts it for
                       the demo mail server);
* ``fullchain.pem``  - leaf certificate + CA, used by nginx and Mailpit;
* ``privkey.pem``    - the leaf key.

The CA key is never written to disk: re-running the script creates a new CA.
FOR LOCAL DEVELOPMENT AND DEMOS ONLY - production uses certificates from a real
CA. The script refuses to overwrite certificates it did not create.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import re
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MARKER = "NexusFlow development CA"
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
# Names the demo stack uses internally, in addition to the public domain.
_INTERNAL_NAMES = ("localhost", "mailpit")


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, MARKER),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def build(domain: str, now: dt.datetime) -> tuple[bytes, bytes, bytes]:
    """Return (ca_pem, fullchain_pem, leaf_key_pem)."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name(MARKER))
        .issuer_name(_name(MARKER))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    names = list(dict.fromkeys([domain, *_INTERNAL_NAMES]))
    san: list[x509.GeneralName] = [x509.DNSName(n) for n in names]
    san.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(_name(domain))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    fullchain = leaf_cert.public_bytes(serialization.Encoding.PEM) + ca_pem
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return ca_pem, fullchain, key_pem


def _created_by_us(path: Path) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return False
    return MARKER in cert.issuer.rfc4514_string()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--domain", default=os.environ.get("NEXUSFLOW_DOMAIN", "localhost"))
    parser.add_argument("--out", type=Path, default=Path("deploy/certs"))
    args = parser.parse_args(argv)

    domain = args.domain.strip().lower().rstrip(".")
    if not _HOSTNAME.fullmatch(domain):
        print(f"refusing: {domain!r} is not a valid host name", file=sys.stderr)
        return 2
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    existing = out / "fullchain.pem"
    if existing.exists() and not _created_by_us(existing):
        print(
            f"refusing to overwrite {existing}: it was not created by this script "
            "(it may be a real certificate)",
            file=sys.stderr,
        )
        return 1

    ca_pem, fullchain, key_pem = build(domain, dt.datetime.now(dt.UTC))
    written = []
    for name, data in (
        ("dev-ca.pem", ca_pem),
        ("fullchain.pem", fullchain),
        ("privkey.pem", key_pem),
    ):
        path = out / name
        path.write_bytes(data)
        written.append(path)
    # Readable by the unprivileged nginx and Mailpit users inside their
    # containers whatever the umask. Acceptable for a throwaway development
    # key only.
    for path in written:
        path.chmod(0o644)
    print(f"development certificate for {domain} (+ {', '.join(_INTERNAL_NAMES)}) in {out}")
    print(f"trust {out / 'dev-ca.pem'} to avoid browser warnings; never use it in production")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
