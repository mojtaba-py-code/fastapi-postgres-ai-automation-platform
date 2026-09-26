"""The pure rules of single sign-on: issuers, domains, roles, MFA evidence and
which sessions reach an organization that requires single sign-on."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from nexusflow.core.errors import InvalidInputError
from nexusflow.domain.authorization.roles import Role
from nexusflow.domain.identity.directory import normalize_user_name
from nexusflow.domain.identity.model import UserSession
from nexusflow.domain.identity.sso import (
    GOOGLE_ISSUER,
    IdTokenClaims,
    SsoConnection,
    email_domain,
    ensure_jit_role,
    idp_reported_mfa,
    managed_by_organization,
    normalize_client_value,
    normalize_domain,
    normalize_domains,
    normalize_issuer,
    satisfies_sso,
    verification_record_name,
)

pytestmark = pytest.mark.security


class TestIssuers:
    @pytest.mark.parametrize(
        "issuer",
        [
            "https://accounts.google.com",
            "https://login.microsoftonline.com/0f1e2d3c-aaaa-bbbb-cccc-000000000000/v2.0",
            "https://dev-123456.okta.com/oauth2/default",
            "https://idp.example.com/",  # kept as typed: issuers compare as exact strings
        ],
    )
    def test_public_https_issuers_are_kept_exactly(self, issuer: str) -> None:
        assert normalize_issuer(f"  {issuer} ") == issuer

    @pytest.mark.parametrize(
        "issuer",
        [
            "http://idp.example.com",
            "https://10.0.0.1",
            "https://169.254.169.254/latest",
            "https://localhost",
            "https://idp.internal",
            "https://idp.example.com:8443",
            "https://idp.example.com/?tenant=1",
            "https://idp.example.com/#frag",
            "https://user:pass@idp.example.com",
            "https://" + "a" * 510 + ".com",
            "",
        ],
    )
    def test_anything_else_is_refused(self, issuer: str) -> None:
        with pytest.raises(InvalidInputError) as exc:
            normalize_issuer(issuer)
        assert exc.value.code == "invalid_issuer"


class TestDomains:
    @pytest.mark.parametrize(
        ("raw", "normalized"),
        [
            ("Example.COM", "example.com"),
            (" corp.example.co.uk. ", "corp.example.co.uk"),
            ("bücher.example", "xn--bcher-kva.example"),
        ],
    )
    def test_domains_are_compared_in_one_form(self, raw: str, normalized: str) -> None:
        assert normalize_domain(raw) == normalized

    @pytest.mark.parametrize(
        "raw",
        [
            "com",
            "*.example.com",
            "10.0.0.1",
            "example..com",
            "-bad.example.com",
            "a.123",
            "a b.com",
        ],
    )
    def test_anything_but_a_plain_domain_is_refused(self, raw: str) -> None:
        with pytest.raises(InvalidInputError):
            normalize_domain(raw)

    def test_a_list_is_required_bounded_and_deduplicated(self) -> None:
        assert normalize_domains(["B.example.com", "a.example.com", "b.example.com"]) == [
            "a.example.com",
            "b.example.com",
        ]
        with pytest.raises(InvalidInputError):
            normalize_domains([])
        with pytest.raises(InvalidInputError):
            normalize_domains([f"d{i}.example.com" for i in range(21)])

    @pytest.mark.parametrize(
        ("email", "domain"),
        [
            ("alice@corp.example.com", "corp.example.com"),
            ("alice@@corp.example.com", None),
            ("alice@evil.example.com@corp.example.com", None),
            ("no-at-all", None),
            ("al ice@corp.example.com", None),
            ("@corp.example.com", None),
            ("alice@", None),
        ],
    )
    def test_the_domain_of_an_address(self, email: str, domain: str | None) -> None:
        assert email_domain(email) == domain

    def test_user_names_are_addresses(self) -> None:
        assert normalize_user_name("Alice@Corp.Example.com") == "alice@corp.example.com"
        with pytest.raises(InvalidInputError):
            normalize_user_name("alice")

    def test_the_proof_lives_under_its_own_name(self) -> None:
        assert verification_record_name("example.com") == "_nexusflow-verification.example.com"


class TestPolicy:
    @pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST])
    def test_an_identity_provider_grants_viewer_or_analyst(self, role: Role) -> None:
        assert ensure_jit_role(role) is role

    @pytest.mark.parametrize("role", [Role.OWNER, Role.ADMIN, Role.OPERATOR])
    def test_never_more(self, role: Role) -> None:
        with pytest.raises(InvalidInputError) as exc:
            ensure_jit_role(role)
        assert exc.value.code == "invalid_default_role"

    @pytest.mark.parametrize(
        ("amr", "mfa"),
        [
            ((), False),
            (("pwd",), False),
            (("pwd", "kba"), False),
            (("face",), False),
            (("pin",), False),
            (("pwd", "mfa"), True),
            (("otp",), True),
            (("hwk",), True),
            (("swk", "pin"), True),
            (("sc",), True),
            (("mca",), True),
        ],
    )
    def test_mfa_evidence_from_the_provider(self, amr: tuple[str, ...], mfa: bool) -> None:
        assert idp_reported_mfa(amr) is mfa

    def test_client_values_are_printable_and_bounded(self) -> None:
        assert normalize_client_value(" abc ", what="client id", max_length=10) == "abc"
        for bad in ("", "a b", "x" * 11, "tab\there"):
            with pytest.raises(InvalidInputError):
                normalize_client_value(bad, what="client id", max_length=10)


def _session(*, sso_org: object = None, mfa: bool = False) -> UserSession:
    now = datetime.now(UTC)
    return UserSession(
        id=uuid4(),
        user_id=uuid4(),
        org_id=None,
        created_at=now,
        last_used_at=now,
        expires_at=now + timedelta(hours=1),
        mfa_verified=mfa,
        sso_org_id=sso_org,  # type: ignore[arg-type]
    )


class TestWhoReachesAnOrganizationThatRequiresSso:
    def test_a_session_its_identity_provider_opened(self) -> None:
        org = uuid4()
        assert satisfies_sso(_session(sso_org=org), org, Role.VIEWER)
        assert not satisfies_sso(_session(sso_org=uuid4()), org, Role.VIEWER)

    def test_owners_with_the_platforms_mfa_break_the_glass(self) -> None:
        org = uuid4()
        assert satisfies_sso(_session(mfa=True), org, Role.OWNER)
        assert not satisfies_sso(_session(mfa=False), org, Role.OWNER)
        assert not satisfies_sso(_session(mfa=True), org, Role.ADMIN)


def _connection(issuer: str) -> SsoConnection:
    now = datetime.now(UTC)
    return SsoConnection(
        id=uuid4(),
        org_id=uuid4(),
        issuer=issuer,
        client_id="client",
        client_secret_ciphertext=b"",
        secret_key_id="k1",
        allowed_domains=["example.com", "pending.example"],
        verified_domains=["example.com"],
        created_at=now,
        updated_at=now,
    )


def _signed_in(hosted_domain: str | None) -> IdTokenClaims:
    return IdTokenClaims(
        issuer="https://idp.example",
        subject="subject",
        nonce="nonce",
        email="person@example.com",
        email_verified=True,
        hosted_domain=hosted_domain,
    )


class TestManagedAccounts:
    """Review R14-1: Google's issuer serves personal accounts too."""

    @pytest.mark.parametrize(
        ("hosted_domain", "managed"),
        [
            ("example.com", True),
            ("Example.COM", True),
            (None, False),  # a personal Google account
            ("pending.example", False),  # allowed, but not verified
            ("gmail.com", False),
            ("not a domain", False),
        ],
    )
    def test_from_google_the_hosted_domain_must_be_a_verified_one(
        self, hosted_domain: str | None, managed: bool
    ) -> None:
        connection = _connection(GOOGLE_ISSUER)
        assert managed_by_organization(connection, _signed_in(hosted_domain)) is managed

    @pytest.mark.parametrize("hosted_domain", [None, "gmail.com"])
    def test_an_organizations_own_tenant_vouches_for_its_accounts(
        self, hosted_domain: str | None
    ) -> None:
        connection = _connection("https://dev-123456.okta.com/oauth2/default")
        assert managed_by_organization(connection, _signed_in(hosted_domain))
