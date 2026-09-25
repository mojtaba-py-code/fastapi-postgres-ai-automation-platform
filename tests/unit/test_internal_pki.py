"""The internal PKI: a private CA and one server certificate per internal service.

Every certificate is checked the way the clients use it - a real TLS handshake
against the CA with the service's host name - and a wrong host name fails.
"""

from __future__ import annotations

import importlib.util
import ssl
import sys
from pathlib import Path
from types import ModuleType

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def pki() -> ModuleType:
    path = ROOT / "scripts" / "internal_pki.py"
    spec = importlib.util.spec_from_file_location("internal_pki", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _handshake(directory: Path, service: str, server_hostname: str) -> None:
    """A TLS 1.2+ handshake between an in-memory server and a verifying client."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(directory / f"tls_{service}.pem", directory / f"tls_{service}.key")
    client = ssl.create_default_context(cafile=str(directory / "internal_ca.pem"))
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    tls_client = client.wrap_bio(c_in, c_out, server_hostname=server_hostname)
    tls_server = server.wrap_bio(s_in, s_out, server_side=True)
    done = {"client": False, "server": False}
    for _ in range(10):
        for name, end in (("client", tls_client), ("server", tls_server)):
            if not done[name]:
                try:
                    end.do_handshake()
                    done[name] = True
                except ssl.SSLWantReadError:
                    pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if all(done.values()):
            return
    raise AssertionError("handshake did not complete")


def _certificate(directory: Path, name: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate((directory / name).read_bytes())


def test_every_internal_server_gets_a_certificate_its_clients_accept(
    pki: ModuleType, tmp_path: Path
) -> None:
    pki.run(tmp_path)
    for service, hosts in pki.SERVICES.items():
        for host in (*hosts, "localhost", "127.0.0.1"):
            _handshake(tmp_path, service, host)
        with pytest.raises(ssl.SSLCertVerificationError):
            _handshake(tmp_path, service, "attacker.example")


def test_server_certificates_are_leaf_server_certificates(pki: ModuleType, tmp_path: Path) -> None:
    pki.run(tmp_path)
    ca = _certificate(tmp_path, "internal_ca.pem")
    for service in pki.SERVICES:
        leaf = _certificate(tmp_path, f"tls_{service}.pem")
        leaf.verify_directly_issued_by(ca)
        assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(usage) == [ExtendedKeyUsageOID.SERVER_AUTH]
        days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
        assert days <= pki.SERVER_DAYS
    constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is True and constraints.path_length == 0


def test_running_again_changes_nothing_and_renewing_keeps_the_ca(
    pki: ModuleType, tmp_path: Path
) -> None:
    pki.run(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}

    assert pki.run(tmp_path) == []
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before

    renewed = pki.run(tmp_path, renew=True)
    assert len(renewed) == len(pki.SERVICES)
    assert (tmp_path / "internal_ca.pem").read_bytes() == before["internal_ca.pem"]
    assert (tmp_path / "tls_redis.pem").read_bytes() != before["tls_redis.pem"]
    _handshake(tmp_path, "redis", "redis")


def test_rotating_the_ca_reissues_every_server_certificate(pki: ModuleType, tmp_path: Path) -> None:
    pki.run(tmp_path)
    old_ca = (tmp_path / "internal_ca.pem").read_bytes()

    pki.run(tmp_path, rotate_ca=True)

    assert (tmp_path / "internal_ca.pem").read_bytes() != old_ca
    for service, hosts in pki.SERVICES.items():
        _handshake(tmp_path, service, hosts[0])


def test_a_certificate_from_another_ca_is_refused_not_silently_kept(
    pki: ModuleType, tmp_path: Path
) -> None:
    pki.run(tmp_path)
    foreign = tmp_path / "foreign"
    pki.run(foreign)
    (tmp_path / "tls_postgres.pem").write_bytes((foreign / "tls_postgres.pem").read_bytes())

    with pytest.raises(SystemExit, match="--renew"):
        pki.run(tmp_path)


def test_half_a_ca_is_refused(pki: ModuleType, tmp_path: Path) -> None:
    pki.run(tmp_path)
    (tmp_path / "internal_ca.key").unlink()

    with pytest.raises(SystemExit, match="must exist together"):
        pki.run(tmp_path)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_ca_key_is_private_and_the_directory_closed(pki: ModuleType, tmp_path: Path) -> None:
    directory = tmp_path / "secrets"
    pki.run(directory)

    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "internal_ca.key").stat().st_mode & 0o777 == 0o600
    assert (directory / "tls_postgres.key").stat().st_mode & 0o777 == 0o644
