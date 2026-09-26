from __future__ import annotations

import pytest

from nexusflow.domain.identity.api_keys import CredentialKind, generate_credential
from nexusflow.infrastructure.observability.logging import REDACTED, redact, redact_text

pytestmark = pytest.mark.security


def test_sensitive_keys_are_redacted_recursively() -> None:
    event = {
        "event": "login",
        "password": "hunter2",
        "nested": {"Authorization": "Bearer abc.def.ghi", "items": [{"api_key": "k"}]},
        "input_tokens": 1200,
    }
    out = redact(event)
    assert out["password"] == REDACTED
    assert out["nested"]["Authorization"] == REDACTED
    assert out["nested"]["items"][0]["api_key"] == REDACTED
    assert out["input_tokens"] == 1200  # numeric metrics are not secrets
    assert out["event"] == "login"


@pytest.mark.parametrize(
    "secret",
    [
        "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlc2lnbmF0dXJl",
        "Bearer abcdefghijklmnop",
        "sk-ant-api03-abcdefghijklmnop",
        "https://hooks.slack.com/services/T000/B000/XXXXXXXX",
        "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ",
        "postgresql+asyncpg://app:SuperSecret@db:5432/nexus",
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA\n-----END PRIVATE KEY-----",
    ],
)
def test_secret_patterns_scrubbed_in_free_text(secret: str) -> None:
    text = f"request failed while using {secret} for upstream"
    assert secret not in redact_text(text)


@pytest.mark.parametrize("kind", list(CredentialKind))
def test_machine_credentials_scrubbed(kind: CredentialKind) -> None:
    # API keys, n8n service tokens and SCIM provisioning tokens alike.
    token = generate_credential(kind).token
    assert token not in redact_text(f"key={token}")


def test_long_values_truncated() -> None:
    assert len(redact_text("a" * 10_000)) < 5000
