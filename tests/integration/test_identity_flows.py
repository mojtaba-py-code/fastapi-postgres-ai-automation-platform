"""Authentication, session and tenancy flows against a real database."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import asyncpg
import pyotp
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import (
    AuthenticationError,
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
)
from nexusflow.core.pagination import PageRequest
from nexusflow.domain.authorization.principal import Principal, PrincipalType
from nexusflow.domain.authorization.roles import Permission, Role
from nexusflow.domain.identity.auth_service import TokenPair
from tests.support.fixtures import META, PASSWORD, register, unique_email

pytestmark = pytest.mark.security


async def _principal(container: Container, tokens: TokenPair) -> Principal:
    return await container.authenticator.authenticate(tokens.access_token)


class TestLoginAndSessions:
    async def test_register_login_and_authenticate(self, container: Container) -> None:
        email, tokens = await register(container)
        principal = await _principal(container, tokens)
        assert principal.type is PrincipalType.USER
        assert principal.role is Role.OWNER
        result = await container.auth.login(
            email=email.upper(), password=PASSWORD, org_id=None, meta=META
        )
        assert result.tokens is not None
        assert (await _principal(container, result.tokens)).user_id == principal.user_id

    async def test_duplicate_registration_rejected(self, container: Container) -> None:
        email, _ = await register(container)
        with pytest.raises(ConflictError):
            await register(container, email=email)

    async def test_weak_password_rejected(self, container: Container) -> None:
        with pytest.raises(InvalidInputError) as exc:
            await container.auth.register(
                email=unique_email(),
                password="password1234",
                full_name="Weak",
                organization_name="Weak Org",
                invitation_token=None,
                meta=META,
            )
        assert exc.value.code == "weak_password"

    async def test_login_failures_are_indistinguishable(self, container: Container) -> None:
        email, _ = await register(container)
        errors = []
        for candidate_email, password in (
            (email, "wrong-password-123"),
            (unique_email(), PASSWORD),
        ):
            with pytest.raises(AuthenticationError) as exc:
                await container.auth.login(
                    email=candidate_email, password=password, org_id=None, meta=META
                )
            errors.append((exc.value.code, exc.value.message))
        assert errors[0] == errors[1]

    async def test_account_lockout_after_repeated_failures(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, _ = await register(container)
        threshold = container.settings.security.lockout_threshold
        for _ in range(threshold):
            with pytest.raises(AuthenticationError):
                await container.auth.login(
                    email=email, password="bad-password-000", org_id=None, meta=META
                )
        # The correct password is now refused too, with the same generic error.
        with pytest.raises(AuthenticationError):
            await container.auth.login(email=email, password=PASSWORD, org_id=None, meta=META)
        locked_until = await admin_conn.fetchval(
            "SELECT locked_until FROM users WHERE email = $1", email
        )
        assert locked_until is not None
        actions = await admin_conn.fetch(
            "SELECT action FROM audit_logs "
            "WHERE actor_id = (SELECT id FROM users WHERE email = $1)",
            email,
        )
        assert "auth.login.locked" in {r["action"] for r in actions}

    async def test_refresh_rotation_and_reuse_detection(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        _, tokens = await register(container)
        rotated = await container.auth.refresh(refresh_token=tokens.refresh_token, meta=META)
        assert rotated.refresh_token != tokens.refresh_token
        # Replaying the already-used token revokes the whole session family ...
        with pytest.raises(AuthenticationError):
            await container.auth.refresh(refresh_token=tokens.refresh_token, meta=META)
        # ... so even the legitimately rotated token and access token stop working.
        with pytest.raises(AuthenticationError):
            await container.auth.refresh(refresh_token=rotated.refresh_token, meta=META)
        with pytest.raises(AuthenticationError):
            await container.authenticator.authenticate(rotated.access_token)
        assert (
            await admin_conn.fetchval(
                "SELECT count(*) FROM audit_logs WHERE action = 'auth.refresh.reuse_detected'"
            )
            >= 1
        )

    async def test_logout_revokes_access_immediately(self, container: Container) -> None:
        _, tokens = await register(container)
        principal = await _principal(container, tokens)
        await container.auth.logout(principal, META)
        with pytest.raises(AuthenticationError):
            await container.authenticator.authenticate(tokens.access_token)

    async def test_password_change_invalidates_other_sessions(self, container: Container) -> None:
        email, first = await register(container)
        second_login = await container.auth.login(
            email=email, password=PASSWORD, org_id=None, meta=META
        )
        assert second_login.tokens is not None
        principal = await _principal(container, first)
        new_tokens = await container.auth.change_password(
            principal,
            current_password=PASSWORD,
            new_password="An0ther-very-good-passphrase",
            meta=META,
        )
        with pytest.raises(AuthenticationError):
            await container.authenticator.authenticate(second_login.tokens.access_token)
        with pytest.raises(AuthenticationError):
            await container.auth.refresh(refresh_token=second_login.tokens.refresh_token, meta=META)
        assert (await _principal(container, new_tokens)).user_id == principal.user_id

    async def test_password_reset_flow(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        email, tokens = await register(container)
        await container.auth.request_password_reset(email=email, meta=META)
        await container.auth.request_password_reset(email=unique_email(), meta=META)  # no error
        reset_id = await admin_conn.fetchval(
            "SELECT id FROM password_reset_tokens "
            "WHERE user_id = (SELECT id FROM users WHERE email = $1) AND used_at IS NULL",
            email,
        )
        # Simulate the mail worker: it generates the token and stores only its hash.
        raw_token = "reset-token-" + uuid4().hex
        await admin_conn.execute(
            "UPDATE password_reset_tokens SET token_hash = $1 WHERE id = $2",
            container.token_hasher.hash(raw_token),
            reset_id,
        )
        new_password = "Brand-new-passphrase-42!"
        await container.auth.reset_password(token=raw_token, new_password=new_password, meta=META)
        with pytest.raises(InvalidInputError):
            await container.auth.reset_password(
                token=raw_token, new_password=new_password + "x", meta=META
            )
        with pytest.raises(AuthenticationError):
            await container.authenticator.authenticate(tokens.access_token)
        result = await container.auth.login(
            email=email, password=new_password, org_id=None, meta=META
        )
        assert result.tokens is not None


class TestMfa:
    async def test_enrollment_login_and_replay_protection(self, container: Container) -> None:
        email, tokens = await register(container)
        principal = await _principal(container, tokens)
        enrollment = await container.auth.begin_mfa_enrollment(
            principal, password=PASSWORD, meta=META
        )
        totp = pyotp.TOTP(enrollment.secret)
        now = container.clock.now()
        recovery_codes = await container.auth.confirm_mfa_enrollment(
            principal, code=totp.at(now - timedelta(seconds=30)), meta=META
        )
        assert len(recovery_codes) == 10
        result = await container.auth.login(email=email, password=PASSWORD, org_id=None, meta=META)
        assert result.tokens is None and result.mfa_challenge is not None
        code = totp.at(container.clock.now())
        pair = await container.auth.verify_mfa(
            challenge_token=result.mfa_challenge, code=code, meta=META
        )
        assert (await _principal(container, pair)).user_id == principal.user_id
        # The same TOTP code cannot be replayed with a fresh challenge.
        again = await container.auth.login(email=email, password=PASSWORD, org_id=None, meta=META)
        assert again.mfa_challenge is not None
        with pytest.raises(AuthenticationError):
            await container.auth.verify_mfa(
                challenge_token=again.mfa_challenge, code=code, meta=META
            )
        # A recovery code works exactly once.
        pair = await container.auth.verify_mfa(
            challenge_token=again.mfa_challenge, code=recovery_codes[0], meta=META
        )
        third = await container.auth.login(email=email, password=PASSWORD, org_id=None, meta=META)
        assert third.mfa_challenge is not None
        with pytest.raises(AuthenticationError):
            await container.auth.verify_mfa(
                challenge_token=third.mfa_challenge, code=recovery_codes[0], meta=META
            )

    async def test_organization_mfa_policy_is_enforced(self, container: Container) -> None:
        _, tokens = await register(container)
        owner = await _principal(container, tokens)
        await container.organizations.update(
            owner, name=None, settings={"require_mfa": True}, meta=META
        )
        with pytest.raises(PermissionDeniedError) as exc:
            await container.authenticator.authenticate(tokens.access_token)
        assert exc.value.code == "mfa_required"


class TestTenancyAndRoles:
    async def test_invitation_and_role_escalation_rules(
        self, container: Container, admin_conn: asyncpg.Connection
    ) -> None:
        _, owner_tokens = await register(container)
        owner = await _principal(container, owner_tokens)
        analyst_email = unique_email("analyst")
        invitation = await container.organizations.invite(
            owner, email=analyst_email, role=Role.ANALYST, meta=META
        )
        raw = "invite-" + uuid4().hex
        await admin_conn.execute(
            "UPDATE invitations SET token_hash = $1 WHERE id = $2",
            container.token_hasher.hash(raw),
            invitation.id,
        )
        analyst_tokens = await container.auth.register(
            email=analyst_email,
            password=PASSWORD,
            full_name="Ana Lyst",
            organization_name=None,
            invitation_token=raw,
            meta=META,
        )
        analyst = await _principal(container, analyst_tokens)
        assert analyst.org_id == owner.org_id
        assert analyst.role is Role.ANALYST
        assert not analyst.has(Permission.MEMBERS_MANAGE)
        # Analysts cannot invite, change roles or read the audit log.
        with pytest.raises(PermissionDeniedError):
            await container.organizations.invite(
                analyst, email=unique_email(), role=Role.VIEWER, meta=META
            )
        members = await container.organizations.list_members(owner, PageRequest())
        analyst_membership = next(m for m in members.items if m.user_id == analyst.user_id)
        # Owners can promote; the change applies to the very next request (no stale token role).
        await container.organizations.change_role(
            owner, membership_id=analyst_membership.membership_id, role=Role.ADMIN, meta=META
        )
        promoted = await _principal(container, analyst_tokens)
        assert promoted.role is Role.ADMIN
        # Admins cannot grant or modify the owner role, nor change their own role.
        with pytest.raises(PermissionDeniedError):
            await container.organizations.invite(
                promoted, email=unique_email(), role=Role.OWNER, meta=META
            )
        owner_membership = next(m for m in members.items if m.user_id == owner.user_id)
        with pytest.raises(PermissionDeniedError):
            await container.organizations.change_role(
                promoted, membership_id=owner_membership.membership_id, role=Role.VIEWER, meta=META
            )
        with pytest.raises(PermissionDeniedError):
            await container.organizations.change_role(
                promoted, membership_id=analyst_membership.membership_id, role=Role.OWNER, meta=META
            )

    async def test_last_owner_cannot_leave(self, container: Container) -> None:
        _, tokens = await register(container)
        owner = await _principal(container, tokens)
        members = await container.organizations.list_members(owner, PageRequest())
        with pytest.raises(ConflictError):
            await container.organizations.remove_member(
                owner, membership_id=members.items[0].membership_id, meta=META
            )

    async def test_cross_tenant_membership_ids_are_not_found(self, container: Container) -> None:
        _, a_tokens = await register(container)
        _, b_tokens = await register(container)
        owner_a = await _principal(container, a_tokens)
        owner_b = await _principal(container, b_tokens)
        b_members = await container.organizations.list_members(owner_b, PageRequest())
        with pytest.raises(NotFoundError):
            await container.organizations.change_role(
                owner_a, membership_id=b_members.items[0].membership_id, role=Role.VIEWER, meta=META
            )

    async def test_api_keys_are_least_privilege_and_revocable(self, container: Container) -> None:
        _, tokens = await register(container)
        owner = await _principal(container, tokens)
        created = await container.accounts.create_api_key(
            owner,
            name="ci",
            role=Role.VIEWER,
            scopes=[Permission.SOURCES_READ.value],
            expires_in_days=30,
            meta=META,
        )
        machine = await container.authenticator.authenticate(created.token)
        assert machine.type is PrincipalType.API_KEY
        assert machine.permissions == frozenset({Permission.SOURCES_READ})
        with pytest.raises(InvalidInputError):
            await container.accounts.create_api_key(
                owner,
                name="bad",
                role=Role.VIEWER,
                scopes=[Permission.SOURCES_WRITE.value],
                expires_in_days=30,
                meta=META,
            )
        await container.accounts.revoke_api_key(owner, key_id=created.key.id, meta=META)
        with pytest.raises(AuthenticationError):
            await container.authenticator.authenticate(created.token)

    async def test_switch_organization_requires_membership(self, container: Container) -> None:
        _, a_tokens = await register(container)
        _, b_tokens = await register(container)
        owner_a = await _principal(container, a_tokens)
        owner_b = await _principal(container, b_tokens)
        assert owner_b.org_id is not None
        with pytest.raises(NotFoundError):
            await container.auth.switch_organization(owner_a, owner_b.org_id, META)
