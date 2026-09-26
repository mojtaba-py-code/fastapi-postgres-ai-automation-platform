"""The passkey relying party derived from the settings (``core.config``).

Its ID is the host of ``app.public_base_url`` unless ``security.webauthn_rp_id``
names that host or a parent domain of it; answers are accepted from the public
URL's origin plus ``security.webauthn_origins``, https only (``http://localhost``
outside staging and production). A setting that cannot work refuses startup;
a public host that is an IP address only leaves passkeys unavailable (warned).
"""

from __future__ import annotations

from typing import Any

import pytest

from nexusflow.core.config import Environment, WebAuthnRelyingParty, webauthn_relying_party
from tests.conftest import make_settings

pytestmark = pytest.mark.security

_PRODUCTION: dict[str, Any] = {
    "environment": Environment.PRODUCTION,
    "allowed_hosts": ["app.example.com"],
}


def _resolve(
    public_base_url: str, *, production: bool = False, **security: Any
) -> tuple[WebAuthnRelyingParty | None, list[str]]:
    app = {**(_PRODUCTION if production else {}), "public_base_url": public_base_url}
    overrides: dict[str, Any] = {"app": app, "security": security}
    if production:
        overrides["n8n"] = {"webhook_jwt_secret": "x" * 40}
    try:
        settings = make_settings(**overrides)
    except ValueError as exc:
        return None, [str(exc)]
    return webauthn_relying_party(settings.app, settings.security)


class TestTheRelyingParty:
    def test_the_public_host_by_default(self) -> None:
        assert _resolve("https://app.example.com") == (
            WebAuthnRelyingParty(rp_id="app.example.com", origins=("https://app.example.com",)),
            [],
        )

    def test_a_path_and_a_non_default_port_are_handled_like_a_browser(self) -> None:
        resolved, problems = _resolve("https://App.Example.com:8443/nexusflow/")
        assert problems == []
        assert resolved == WebAuthnRelyingParty(
            rp_id="app.example.com", origins=("https://app.example.com:8443",)
        )
        default_port, _ = _resolve("https://app.example.com:443")
        assert default_port is not None
        assert default_port.origins == ("https://app.example.com",)

    def test_local_development_works_out_of_the_box(self) -> None:
        resolved, problems = _resolve("http://localhost:8000")
        assert problems == []
        assert resolved == WebAuthnRelyingParty(
            rp_id="localhost", origins=("http://localhost:8000",)
        )

    def test_a_parent_domain_may_be_the_relying_party(self) -> None:
        resolved, problems = _resolve(
            "https://app.example.com",
            webauthn_rp_id="Example.com",
            webauthn_origins=["https://admin.example.com", "https://example.com/"],
        )
        assert problems == []
        assert resolved == WebAuthnRelyingParty(
            rp_id="example.com",
            origins=(
                "https://app.example.com",
                "https://admin.example.com",
                "https://example.com",
            ),
        )

    @pytest.mark.parametrize(
        "rp_id",
        [
            "other.example",  # unrelated
            "pp.example.com",  # a suffix, but not at a label boundary
            "sub.app.example.com",  # a subdomain of the host, not a parent
            "com",  # a single label that is not the host itself
            "203.0.113.5",
            "exa mple.com",
            "-bad.example.com",
            "",
        ],
    )
    def test_a_relying_party_id_outside_the_public_host_refuses_startup(self, rp_id: str) -> None:
        resolved, problems = _resolve("https://app.example.com", webauthn_rp_id=rp_id)
        assert resolved is None
        assert problems and "webauthn_rp_id" in problems[0]

    @pytest.mark.parametrize(
        "origin",
        [
            "https://evil.example",  # outside the relying party
            "https://example.com.evil.example",
            "https://app.example.com/path",  # not just an origin
            "https://app.example.com?query",
            "https://user@app.example.com",
            "ftp://app.example.com",
            "http://app.example.com",  # plain http outside localhost
            "app.example.com",
            "https://app.example.com:99999",
        ],
    )
    def test_an_origin_that_cannot_be_used_refuses_startup(self, origin: str) -> None:
        resolved, problems = _resolve("https://app.example.com", webauthn_origins=[origin])
        assert resolved is None
        assert problems and "webauthn_origins" in problems[0]

    def test_http_localhost_is_for_development_only(self) -> None:
        development, problems = _resolve(
            "http://localhost:8000", webauthn_origins=["http://localhost:5173"]
        )
        assert problems == []
        assert development is not None
        assert development.origins == ("http://localhost:8000", "http://localhost:5173")

        resolved, problems = _resolve(
            "https://localhost", production=True, webauthn_origins=["http://localhost:5173"]
        )
        assert resolved is None
        assert "must use https" in problems[0]

    @pytest.mark.parametrize(
        "public_base_url", ["http://127.0.0.1:8000", "https://[2001:db8::1]", "https://203.0.113.9"]
    )
    def test_an_ip_address_leaves_passkeys_unavailable_with_a_warning(
        self, public_base_url: str
    ) -> None:
        assert _resolve(public_base_url) == (None, [])
        settings = make_settings(app={"public_base_url": public_base_url})
        assert any("passkeys are unavailable" in w for w in settings.security_warnings())

    def test_plain_http_outside_localhost_leaves_passkeys_unavailable(self) -> None:
        assert _resolve("http://nexusflow.internal:8000") == (None, [])

    def test_a_working_configuration_warns_about_nothing_passkey_related(self) -> None:
        settings = make_settings(app={"public_base_url": "https://app.example.com"})
        assert not any("passkeys" in warning for warning in settings.security_warnings())
