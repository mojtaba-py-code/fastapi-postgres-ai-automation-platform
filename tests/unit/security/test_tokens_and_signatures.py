from __future__ import annotations

import os

import pytest

from nexusflow.core.errors import AuthenticationError
from nexusflow.domain.identity.api_keys import (
    CredentialKind,
    generate_credential,
    parse_credential,
)
from nexusflow.domain.webhooks.signatures import (
    build_signature_header,
    compute_signature,
    verify_signature,
)

pytestmark = pytest.mark.security

NOW = 1_780_000_000
DELIVERY = "8b1f3c2e-0000-4000-8000-000000000001"


class TestApiKeyFormat:
    def test_generated_credentials_parse(self) -> None:
        for kind in CredentialKind:
            generated = generate_credential(kind)
            parsed = parse_credential(generated.token)
            assert parsed is not None
            assert parsed.kind is kind
            assert parsed.prefix == generated.prefix

    def test_checksum_detects_modification(self) -> None:
        token = generate_credential(CredentialKind.API_KEY).token
        index = 20
        flipped = token[:index] + ("A" if token[index] != "A" else "B") + token[index + 1 :]
        assert parse_credential(flipped) is None

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "nxf_",
            "Bearer abc",
            "nxx_abcdefghijkl_" + "a" * 49,
            "nxf_ABCDEFGHIJKL_" + "a" * 49,
            "nxf_abcdefghijkl_" + "a" * 500,
        ],
    )
    def test_malformed_tokens_rejected(self, value: str) -> None:
        assert parse_credential(value) is None


class TestWebhookSignatures:
    secret = b"whsec-test-secret-value-0123456789"

    def _header(self, body: bytes, *, timestamp: int = NOW, secret: bytes | None = None) -> str:
        return build_signature_header(
            secret or self.secret, timestamp=timestamp, delivery_id=DELIVERY, body=body
        )

    def test_valid_signature(self) -> None:
        body = b'{"items": []}'
        parsed = verify_signature(
            secrets=[self.secret],
            header=self._header(body),
            delivery_id=DELIVERY,
            body=body,
            now_timestamp=NOW + 10,
            tolerance_seconds=300,
        )
        assert parsed.timestamp == NOW

    def test_body_tampering_rejected(self) -> None:
        header = self._header(b'{"amount": 1}')
        with pytest.raises(AuthenticationError) as exc:
            verify_signature(
                secrets=[self.secret],
                header=header,
                delivery_id=DELIVERY,
                body=b'{"amount": 1000}',
                now_timestamp=NOW,
                tolerance_seconds=300,
            )
        assert exc.value.code == "invalid_signature"  # generic for the client
        assert exc.value.internal_detail == "signature_mismatch"  # specific in logs only

    def test_delivery_id_is_bound_into_mac(self) -> None:
        body = b"{}"
        header = self._header(body)
        with pytest.raises(AuthenticationError):
            verify_signature(
                secrets=[self.secret],
                header=header,
                delivery_id=DELIVERY.replace("1", "2"),
                body=body,
                now_timestamp=NOW,
                tolerance_seconds=300,
            )

    @pytest.mark.parametrize("skew", [-301, 301, 86_400])
    def test_stale_or_future_timestamps_rejected(self, skew: int) -> None:
        body = b"{}"
        with pytest.raises(AuthenticationError) as exc:
            verify_signature(
                secrets=[self.secret],
                header=self._header(body),
                delivery_id=DELIVERY,
                body=body,
                now_timestamp=NOW + skew,
                tolerance_seconds=300,
            )
        assert exc.value.code == "invalid_signature"
        assert exc.value.internal_detail == "timestamp_out_of_tolerance"

    def test_secret_rotation_accepts_either_secret(self) -> None:
        body = b"{}"
        new_secret = os.urandom(32)
        header = self._header(body, secret=new_secret)
        verify_signature(
            secrets=[self.secret, new_secret],
            header=header,
            delivery_id=DELIVERY,
            body=body,
            now_timestamp=NOW,
            tolerance_seconds=300,
        )

    @pytest.mark.parametrize(
        "header",
        [
            None,
            "",
            "garbage",
            "t=abc,v1=00",
            "v1=" + "0" * 64,
            f"t={NOW}",
            f"t={NOW},v1=" + "z" * 64,
            f"t={NOW},t={NOW},v1=" + "0" * 64,
            "x" * 2000,
        ],
    )
    def test_malformed_headers_rejected(self, header: str | None) -> None:
        with pytest.raises(AuthenticationError):
            verify_signature(
                secrets=[self.secret],
                header=header,
                delivery_id=DELIVERY,
                body=b"{}",
                now_timestamp=NOW,
                tolerance_seconds=300,
            )

    @pytest.mark.parametrize("delivery_id", [None, "", "short", "has space in it", "a" * 200])
    def test_invalid_delivery_ids_rejected(self, delivery_id: str | None) -> None:
        signature = compute_signature(self.secret, timestamp=NOW, delivery_id="x", body=b"{}")
        with pytest.raises(AuthenticationError):
            verify_signature(
                secrets=[self.secret],
                header=f"t={NOW},v1={signature}",
                delivery_id=delivery_id,
                body=b"{}",
                now_timestamp=NOW,
                tolerance_seconds=300,
            )
