"""Key-encryption keys wrapped by Vault's transit engine.

The secrets file used to hold the keys themselves: anyone who copied it (or a
backup of it) could decrypt every sealed value. With Vault it holds
ciphertexts that only a Vault identity allowed to use the transit key can
unwrap - at start-up, after which encryption stays local.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest

from nexusflow.apps.cli import main as cli
from nexusflow.bootstrap import container as bootstrap
from nexusflow.core.config import VaultSettings
from nexusflow.infrastructure.security.crypto import EnvelopeCipher
from nexusflow.infrastructure.security.vault import VaultError, VaultTransit
from tests.conftest import make_settings

KEK = bytes(range(32))


class FakeVault:
    """Transit decrypt/encrypt/rewrap and AppRole login over a MockTransport."""

    def __init__(self, *, token: str = "hvs.test-token") -> None:  # noqa: S107 - a fake
        self.token = token
        self.requests: list[httpx2.Request] = []
        self.failures: list[int] = []  # statuses to answer before succeeding
        self.version = 1

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self.failures:
            return httpx2.Response(self.failures.pop(0), json={"errors": ["busy"]})
        body = json.loads(request.content or b"{}")
        path = request.url.path
        if path == "/v1/auth/approle/login":
            if body == {"role_id": "role", "secret_id": "secret"}:
                return httpx2.Response(200, json={"auth": {"client_token": self.token}})
            return httpx2.Response(400, json={"errors": ["invalid role or secret id"]})
        if request.headers.get("x-vault-token") != self.token:
            return httpx2.Response(403, json={"errors": ["permission denied"]})
        items = body["batch_input"]
        if path == "/v1/transit/encrypt/nexusflow":
            results = [{"ciphertext": f"vault:v{self.version}:" + i["plaintext"]} for i in items]
        elif path == "/v1/transit/decrypt/nexusflow":
            results = [{"plaintext": i["ciphertext"].split(":", 2)[2]} for i in items]
        elif path == "/v1/transit/rewrap/nexusflow":
            results = [
                {"ciphertext": f"vault:v{self.version}:" + i["ciphertext"].split(":", 2)[2]}
                for i in items
            ]
        else:
            return httpx2.Response(404, json={"errors": []})
        return httpx2.Response(200, json={"data": {"batch_results": results}})


def _settings(**overrides: Any) -> VaultSettings:
    values: dict[str, Any] = {
        "address": "https://vault.example.com:8200",
        "token": "hvs.test-token",
    }
    return VaultSettings(**{**values, **overrides})


def _transit(fake: FakeVault, **overrides: Any) -> VaultTransit:
    client = httpx2.Client(transport=httpx2.MockTransport(fake.handler))
    return VaultTransit(_settings(**overrides), client=client, sleep=lambda _: None)


def _wrapped(key: bytes = KEK, version: int = 1) -> str:
    return f"vault:v{version}:" + base64.b64encode(key).decode()


def test_the_keyring_is_unwrapped_in_one_authenticated_request() -> None:
    fake = FakeVault()
    keys = _transit(fake, namespace="team/platform").decrypt_keyring(
        {"kek-1": _wrapped(), "kek-2": _wrapped(bytes(32))}
    )
    assert keys == {"kek-1": KEK, "kek-2": bytes(32)}
    [request] = fake.requests
    assert request.method == "POST"
    assert str(request.url) == "https://vault.example.com:8200/v1/transit/decrypt/nexusflow"
    assert request.headers["x-vault-token"] == "hvs.test-token"
    assert request.headers["x-vault-namespace"] == "team/platform"


def test_an_approle_logs_in_first_and_its_token_is_used() -> None:
    fake = FakeVault(token="hvs.from-approle")
    transit = _transit(fake, token=None, role_id="role", secret_id="secret")
    assert transit.decrypt_keyring({"kek-1": _wrapped()}) == {"kek-1": KEK}
    login, decrypt = fake.requests
    assert login.url.path == "/v1/auth/approle/login"
    assert "x-vault-token" not in login.headers
    assert decrypt.headers["x-vault-token"] == "hvs.from-approle"


def test_a_refusal_is_final_and_says_nothing_secret() -> None:
    fake = FakeVault(token="hvs.another-token")
    with pytest.raises(VaultError) as refused:
        _transit(fake).decrypt_keyring({"kek-1": _wrapped()})
    assert len(fake.requests) == 1  # 403 is not retried
    assert "hvs." not in str(refused.value) and "hvs." not in str(refused.value.internal_detail)


def test_unavailability_is_retried_then_reported() -> None:
    fake = FakeVault()
    fake.failures = [503, 502]
    assert _transit(fake, retries=3).decrypt_keyring({"kek-1": _wrapped()}) == {"kek-1": KEK}
    assert len(fake.requests) == 3
    fake = FakeVault()
    fake.failures = [503] * 5
    with pytest.raises(VaultError):
        _transit(fake, retries=2).decrypt_keyring({"kek-1": _wrapped()})
    assert len(fake.requests) == 3


@pytest.mark.parametrize(
    ("keyring", "why"),
    [
        ({}, "empty"),
        ({"kek-1": base64.b64encode(KEK).decode()}, "a local key, not a ciphertext"),
        ({"kek-1": _wrapped(bytes(16))}, "not 32 bytes"),
    ],
)
def test_what_is_not_a_wrapped_32_byte_key_is_refused(keyring: dict[str, str], why: str) -> None:
    with pytest.raises(VaultError):
        _transit(FakeVault()).decrypt_keyring(keyring)


def test_plain_http_is_refused_unless_explicitly_allowed_outside_production() -> None:
    with pytest.raises(VaultError):
        VaultTransit(_settings(address="http://vault:8200"))
    VaultTransit(_settings(address="http://127.0.0.1:8200", allow_insecure_http=True)).close()
    with pytest.raises(ValueError, match=r"vault\.address must use https"):
        make_settings(
            app={"environment": "production", "public_base_url": "https://nexusflow.example"},
            security={"kek_provider": "vault-transit"},
            vault={"address": "http://vault:8200", "token": "t", "allow_insecure_http": True},
        )


def test_the_vault_provider_needs_an_address_and_an_identity() -> None:
    with pytest.raises(ValueError, match=r"vault\.address is required"):
        make_settings(security={"kek_provider": "vault-transit"}, vault={"token": "t"})
    with pytest.raises(ValueError, match=r"vault\.token or vault\.role_id"):
        make_settings(
            security={"kek_provider": "vault-transit"},
            vault={"address": "https://vault.example.com", "role_id": "role"},
        )


def test_the_platform_decrypts_with_the_unwrapped_keyring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Data sealed under a local key opens once the same key is unwrapped from Vault.
    sealed = EnvelopeCipher({"kek-1": KEK}, "kek-1").encrypt("secret", context="ctx")
    seen: list[str] = []

    def unwrap(vault: VaultSettings, keys_json: str) -> dict[str, bytes]:
        seen.append(keys_json)
        return _transit(FakeVault()).decrypt_keyring(json.loads(keys_json))

    monkeypatch.setattr(bootstrap, "unwrap_keyring", unwrap)
    settings = make_settings(
        security={
            "kek_provider": "vault-transit",
            "encryption_keys": json.dumps({"kek-1": _wrapped()}),
            "encryption_active_key_id": "kek-1",
        },
        vault={"address": "https://vault.example.com", "token": "hvs.test-token"},
    )
    cipher, _, _ = bootstrap.build_security(settings)
    assert seen and cipher.decrypt(sealed, context="ctx") == "secret"


def test_a_keyring_is_unwrapped_once_per_process(monkeypatch: pytest.MonkeyPatch) -> None:
    # Worker children inherit their parent's keys: a child recycled while Vault
    # is down still starts, and Vault is not asked again for every child.
    from nexusflow.infrastructure.security import vault

    fake = FakeVault()
    monkeypatch.setattr(vault, "_UNWRAPPED", {})
    monkeypatch.setattr(
        vault,
        "VaultTransit",
        lambda settings: VaultTransit(
            settings, client=httpx2.Client(transport=httpx2.MockTransport(fake.handler))
        ),
    )
    keyring = json.dumps({"kek-1": _wrapped()})
    first = vault.unwrap_keyring(_settings(), keyring)
    fake.failures = [503] * 100  # Vault gone
    assert vault.unwrap_keyring(_settings(), keyring) == first == {"kek-1": KEK}
    assert len(fake.requests) == 1


def _run_cli(
    monkeypatch: pytest.MonkeyPatch, fake: FakeVault, settings: Any, *argv: str
) -> dict[str, Any]:
    factory: Callable[[VaultSettings], VaultTransit] = lambda vault: VaultTransit(  # noqa: E731
        vault, client=httpx2.Client(transport=httpx2.MockTransport(fake.handler))
    )
    monkeypatch.setattr(cli, "VaultTransit", factory)
    args = cli.build_parser().parse_args(argv)
    result: dict[str, Any] = args.sync_handler(settings, args)
    return result


def test_a_local_keyring_moves_into_vault_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    local = base64.b64encode(KEK).decode()
    settings = make_settings(
        security={"encryption_keys": json.dumps({"kek-1": local})},
        vault={"address": "https://vault.example.com", "token": "hvs.test-token"},
    )
    result = _run_cli(monkeypatch, FakeVault(), settings, "keys", "vault-wrap")
    assert result == {"encryption_keys": {"kek-1": _wrapped()}}  # ciphertexts only


def test_new_keys_and_rewraps_are_printed_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    vault = {"address": "https://vault.example.com", "token": "hvs.test-token"}
    fake = FakeVault()
    new = _run_cli(
        monkeypatch, fake, make_settings(vault=vault), "keys", "vault-new", "--key-id", "kek-2"
    )
    assert new["key_id"] == "kek-2" and new["wrapped"].startswith("vault:v1:")
    fake.version = 2
    wrapped_settings = make_settings(
        security={
            "kek_provider": "vault-transit",
            "encryption_keys": json.dumps({"kek-1": _wrapped()}),
        },
        vault=vault,
    )
    rewrapped = _run_cli(monkeypatch, fake, wrapped_settings, "keys", "vault-rewrap")
    assert rewrapped == {"encryption_keys": {"kek-1": _wrapped(version=2)}}
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["keys", "vault-new", "--key-id", "../evil"])
