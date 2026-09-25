from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nexusflow.core.config import Environment, Settings
from nexusflow.core.errors import InvalidInputError, PayloadTooLargeError
from nexusflow.core.ids import parse_uuid, uuid7
from nexusflow.core.jsonutil import canonical_json, content_hash, loads_limited, max_nesting_depth
from nexusflow.core.pagination import (
    MAX_CURSOR_LENGTH,
    PageRequest,
    SortSpec,
    decode_cursor,
    encode_cursor,
    parse_sort,
)
from nexusflow.core.text import (
    clean_text,
    content_disposition,
    mask_email,
    mask_secret,
    slugify,
    spreadsheet_safe,
)
from tests.conftest import make_settings


class TestIds:
    def test_uuid7_is_version_7_and_time_ordered(self) -> None:
        first, second = uuid7(1_000), uuid7(2_000)
        assert first.version == 7
        assert first < second

    def test_parse_uuid_is_strict(self) -> None:
        value = uuid4()
        assert parse_uuid(str(value)) == value
        assert parse_uuid("not-a-uuid") is None
        assert parse_uuid(value.hex) is None  # only canonical form


class TestText:
    def test_clean_text_strips_controls_and_bidi(self) -> None:
        dirty = "  Hello\x00\u202eWorld\u200b \t\n next  "
        assert clean_text(dirty, max_length=100) == "Hello World next"

    def test_clean_text_multiline_keeps_paragraphs(self) -> None:
        assert clean_text("a\r\n\r\n\r\n\r\nb", max_length=10, multiline=True) == "a\n\nb"

    def test_clean_text_truncates(self) -> None:
        assert len(clean_text("x" * 50, max_length=10)) == 10

    @pytest.mark.parametrize(
        "value", ["=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\uff1d1"]
    )
    def test_spreadsheet_formula_injection_neutralized(self, value: str) -> None:
        assert spreadsheet_safe(value).startswith("'")

    def test_spreadsheet_safe_keeps_plain_values(self) -> None:
        assert spreadsheet_safe("Widget 3000") == "Widget 3000"

    def test_content_disposition_cannot_inject_headers(self) -> None:
        header = content_disposition('evil"\r\nSet-Cookie: x=1.csv')
        assert "\r" not in header and "\n" not in header
        assert header.count('"') == 2

    def test_masking(self) -> None:
        assert mask_email("jane.doe@example.com") == "j***@example.com"
        assert mask_secret("abcdefghijklmnop").endswith("mnop")
        assert "abc" not in mask_secret("abcdefgh")

    def test_slugify(self) -> None:
        assert slugify("Acme Corp — EU Pricing!") == "acme-corp-eu-pricing"

    @given(st.text(max_size=300))
    def test_clean_text_never_emits_control_characters(self, value: str) -> None:
        cleaned = clean_text(value, max_length=200)
        assert all(ch == " " or ord(ch) >= 0x20 for ch in cleaned)
        assert len(cleaned) <= 200


class TestJson:
    def test_canonical_json_is_stable(self) -> None:
        a = {"b": 1, "a": [1, 2], "id": UUID(int=1), "at": datetime(2026, 1, 1, tzinfo=UTC)}
        b = dict(reversed(list(a.items())))
        assert canonical_json(a) == canonical_json(b)
        assert content_hash(a) == content_hash(b)

    def test_depth_scanner_ignores_brackets_in_strings(self) -> None:
        assert max_nesting_depth(b'{"a": "[[[[[[", "b": [1, {"c": 2}]}') == 3

    def test_loads_limited_rejects_deep_documents(self) -> None:
        with pytest.raises(InvalidInputError):
            loads_limited(b"[" * 100 + b"]" * 100, max_bytes=10_000, max_depth=32)

    def test_loads_limited_rejects_large_documents(self) -> None:
        with pytest.raises(PayloadTooLargeError):
            loads_limited(b"[" + b"1," * 1000 + b"1]", max_bytes=100)

    def test_loads_limited_rejects_nan(self) -> None:
        with pytest.raises(InvalidInputError):
            loads_limited(b'{"a": NaN}', max_bytes=100)

    def test_loads_limited_parses_valid_json(self) -> None:
        assert loads_limited(json.dumps({"a": [1, 2]}).encode(), max_bytes=100) == {"a": [1, 2]}


class TestPagination:
    def test_cursor_round_trip(self) -> None:
        last = uuid4()
        cursor = decode_cursor(encode_cursor(datetime(2026, 1, 1, tzinfo=UTC), last))
        assert cursor.last_id == last
        assert cursor.sort_value == "2026-01-01T00:00:00+00:00"

    @pytest.mark.parametrize(
        "token",
        ["", "!!!", "e30", "a" * 600, "eyJ2IjpbMV0sImkiOiJ4In0", "e" * (MAX_CURSOR_LENGTH + 1)],
    )
    def test_invalid_cursors_rejected(self, token: str) -> None:
        with pytest.raises(InvalidInputError):
            decode_cursor(token)

    @pytest.mark.parametrize(
        "name",
        [
            "\U0001f600" * 120,  # the longest name (120 characters), 4 bytes each in UTF-8
            "数据" * 60,
            '"' * 120,  # escaped by JSON
            "\\" * 120,
            "Zürich " * 17,
        ],
    )
    def test_the_cursor_after_any_name_is_accepted_back(self, name: str) -> None:
        token = encode_cursor(name, uuid4())
        assert len(token) <= MAX_CURSOR_LENGTH
        assert decode_cursor(token).sort_value == name

    @pytest.mark.parametrize(
        "value",
        ["NaN", "Infinity", "-Infinity", str(2**63), str(-(2**63) - 1), '"a\\u0000b"', '"\\ud800"'],
    )
    def test_cursor_values_the_database_cannot_bind_are_rejected(self, value: str) -> None:
        document = '{"v":%s,"i":"%s"}' % (value, uuid4())  # noqa: UP031 - raw JSON on purpose
        token = base64.urlsafe_b64encode(document.encode()).rstrip(b"=").decode()
        with pytest.raises(InvalidInputError):
            decode_cursor(token)

    @pytest.mark.parametrize("value", [2**63 - 1, -(2**63), 1.5, "Zürich", None])
    def test_bindable_cursor_values_round_trip(self, value: str | int | float | None) -> None:
        assert decode_cursor(encode_cursor(value, uuid4())).sort_value == value

    def test_limit_bounds(self) -> None:
        with pytest.raises(InvalidInputError):
            PageRequest(limit=0)
        with pytest.raises(InvalidInputError):
            PageRequest(limit=10_000)

    def test_sort_allowlist(self) -> None:
        allowed = frozenset({"created_at", "name"})
        default = SortSpec("created_at")
        assert parse_sort("-name", allowed=allowed, default=default) == SortSpec("name", True)
        with pytest.raises(InvalidInputError):
            parse_sort("password_hash", allowed=allowed, default=default)


class TestSettings:
    def test_missing_key_material_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="jwt_private_key"):
            Settings()

    def test_production_rejects_insecure_options(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_settings(
                app={
                    "environment": Environment.PRODUCTION,
                    "debug": True,
                    "public_base_url": "http://nexusflow.example.com",
                    "allowed_hosts": ["*"],
                    "cors_allowed_origins": ["*"],
                },
            )
        message = str(exc.value)
        for fragment in ("debug", "https", "allowed_hosts", "CORS", "webhook_jwt_secret"):
            assert fragment in message

    def test_docs_disabled_by_default_in_production(self) -> None:
        settings = make_settings(
            app={
                "environment": Environment.PRODUCTION,
                "public_base_url": "https://nexusflow.example.com",
                "allowed_hosts": ["nexusflow.example.com"],
            },
            n8n={"webhook_jwt_secret": "x" * 40},
        )
        assert not settings.app.api_docs_enabled
        assert settings.security_warnings()

    def test_secrets_are_not_in_repr(self) -> None:
        settings = make_settings()
        assert "PRIVATE KEY" not in repr(settings)

    def test_file_secrets(self, tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
        from pathlib import Path

        secret_file = Path(str(tmp_path)) / "pepper"
        secret_file.write_text("f" * 64 + "\n")
        monkeypatch.setenv("NEXUSFLOW_SECURITY__HMAC_PEPPER_FILE", str(secret_file))
        settings = make_settings()
        # init kwargs win over files; remove it to check the file source
        base = settings.model_dump()
        base["security"].pop("hmac_pepper")
        reloaded = Settings(**base)
        assert reloaded.security.hmac_pepper is not None
        assert reloaded.security.hmac_pepper.get_secret_value() == "f" * 64

    def test_an_empty_secret_file_means_not_configured(
        self, tmp_path: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pathlib import Path

        placeholder = Path(str(tmp_path)) / "n8n_api_key"
        placeholder.write_text("\n")  # created by generate_secrets.py, not filled in yet
        monkeypatch.setenv("NEXUSFLOW_N8N__API_KEY_FILE", str(placeholder))
        assert make_settings().n8n.api_key is None

    def test_rate_limit_overrides_merge_with_defaults(self) -> None:
        settings = make_settings(
            rate_limits={"rules": {"api.read": {"limit": 5, "period_seconds": 60}}}
        )
        assert settings.rate_limits.rules["api.read"].limit == 5
        assert "auth.login.ip" in settings.rate_limits.rules
