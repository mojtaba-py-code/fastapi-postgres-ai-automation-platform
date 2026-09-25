#!/usr/bin/env python3
"""Issue the private CA and the server certificates for TLS inside the stack.

PostgreSQL, both Redis instances and RabbitMQ accept TLS connections only, and
every client verifies the server's certificate and host name against this CA.
Writes into the secrets directory (``./secrets``, mode 0700):

* ``internal_ca.pem``  - the CA certificate, mounted into every client;
* ``internal_ca.key``  - the CA's private key (0600): stays on the host and is
  never mounted into a container - it is only needed to renew certificates;
* ``tls_<service>.pem`` / ``tls_<service>.key`` - each server's certificate
  and key, mounted only into that server.

    python scripts/internal_pki.py              # create whatever is missing
    python scripts/internal_pki.py --check      # exit 1 within 30 days of an expiry
    python scripts/internal_pki.py --renew      # new server certificates, same CA
    python scripts/internal_pki.py --rotate-ca  # new CA and server certificates

Server certificates are valid for two years and the CA for ten; the script
prints the expiry dates. Renew before they expire, then restart the stack
(docs/DEPLOYMENT.md, "Internal TLS").
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ORGANIZATION = "NexusFlow internal PKI"
CA_NAME = "NexusFlow internal CA"
CA_DAYS = 3650
SERVER_DAYS = 730
# Service (file stem) -> the host names its clients connect to. Every server
# certificate also names localhost and 127.0.0.1, for the container's own
# health check.
SERVICES: dict[str, tuple[str, ...]] = {
    "postgres": ("postgres",),
    "redis": ("redis",),
    "redis_sandbox": ("redis-sandbox",),
    "rabbitmq": ("rabbitmq",),
}
_PUBLIC = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH  # 0644, see generate_secrets
_PRIVATE = stat.S_IRUSR | stat.S_IWUSR  # 0600: the CA key is read by nobody but its owner


@dataclass(frozen=True)
class Authority:
    certificate: x509.Certificate
    key: ec.EllipticCurvePrivateKey


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def new_authority(now: dt.datetime) -> Authority:
    key = ec.generate_private_key(ec.SECP384R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(CA_NAME))
        .issuer_name(_name(CA_NAME))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(ca=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA384())
    )
    return Authority(certificate, key)


def issue(
    authority: Authority, hosts: tuple[str, ...], now: dt.datetime
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A server certificate for ``hosts`` (plus localhost and 127.0.0.1)."""
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [x509.DNSName(h) for h in dict.fromkeys([*hosts, "localhost"])]
    names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(hosts[0]))
        .issuer_name(authority.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=SERVER_DAYS))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(ca=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.key.public_key()), False
        )
        .sign(authority.key, hashes.SHA384())
    )
    return certificate, key


def _cert_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _write(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    path.chmod(mode)


def _load_authority(directory: Path) -> Authority | None:
    cert_path, key_path = directory / "internal_ca.pem", directory / "internal_ca.key"
    if not cert_path.exists() and not key_path.exists():
        return None
    if not (cert_path.exists() and key_path.exists()):
        raise SystemExit(
            "internal_ca.pem and internal_ca.key must exist together; "
            "restore the missing one or use --rotate-ca"
        )
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or (
        key.public_key().public_numbers() != certificate.public_key().public_numbers()  # type: ignore[union-attr]
    ):
        raise SystemExit("internal_ca.key does not belong to internal_ca.pem")
    return Authority(certificate, key)


def _issued_by(path: Path, authority: Authority) -> bool:
    try:
        x509.load_pem_x509_certificate(path.read_bytes()).verify_directly_issued_by(
            authority.certificate
        )
    except (OSError, ValueError, TypeError, InvalidSignature):
        return False
    return True


def run(directory: Path, *, renew: bool = False, rotate_ca: bool = False) -> list[str]:
    """Create or renew the internal PKI in ``directory``; returns a summary."""
    now = dt.datetime.now(dt.UTC)
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    summary: list[str] = []
    authority = None if rotate_ca else _load_authority(directory)
    if authority is None:
        authority = new_authority(now)
        _write(directory / "internal_ca.key", _key_pem(authority.key), _PRIVATE)
        _write(directory / "internal_ca.pem", _cert_pem(authority.certificate), _PUBLIC)
        summary.append(f"new CA, valid until {authority.certificate.not_valid_after_utc:%Y-%m-%d}")
        renew = True  # every server certificate must come from the new CA
    for service, hosts in SERVICES.items():
        cert_path, key_path = directory / f"tls_{service}.pem", directory / f"tls_{service}.key"
        present = cert_path.exists() and key_path.exists()
        if present and not renew:
            if not _issued_by(cert_path, authority):
                raise SystemExit(
                    f"{cert_path.name} was not issued by internal_ca.pem; run with --renew"
                )
            continue
        certificate, key = issue(authority, hosts, now)
        _write(key_path, _key_pem(key), _PUBLIC)
        _write(cert_path, _cert_pem(certificate), _PUBLIC)
        summary.append(
            f"{cert_path.name} for {', '.join(hosts)}, "
            f"valid until {certificate.not_valid_after_utc:%Y-%m-%d}"
        )
    return summary


def check(directory: Path, *, warn_days: int = 30) -> list[str]:
    """Problems with the issued certificates: missing, foreign, expiring or expired."""
    authority = _load_authority(directory)
    if authority is None:
        return ["no internal CA - run scripts/internal_pki.py"]
    now = dt.datetime.now(dt.UTC)
    problems: list[str] = []
    named = {"internal_ca.pem": authority.certificate}
    for service in SERVICES:
        path = directory / f"tls_{service}.pem"
        if not path.exists():
            problems.append(f"{path.name} is missing")
        elif not _issued_by(path, authority):
            problems.append(f"{path.name} was not issued by internal_ca.pem")
        else:
            named[path.name] = x509.load_pem_x509_certificate(path.read_bytes())
    for name, certificate in named.items():
        days = (certificate.not_valid_after_utc - now).days
        if days < warn_days:
            problems.append(f"{name} expires in {days} days" if days >= 0 else f"{name} expired")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=Path("secrets"))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="report expiring certificates")
    group.add_argument("--renew", action="store_true", help="re-issue the server certificates")
    group.add_argument("--rotate-ca", action="store_true", help="new CA and server certificates")
    args = parser.parse_args(argv)
    if args.check:
        problems = check(args.dir)
        for line in problems or ["internal certificates valid for at least 30 more days"]:
            print(line)
        return 1 if problems else 0
    summary = run(args.dir, renew=args.renew, rotate_ca=args.rotate_ca)
    for line in summary or ["internal PKI complete - nothing to do"]:
        print(line)
    if summary:
        print("restart the stack to load new certificates: docker compose up -d --force-recreate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
