"""R10 - sign-in risk: the "success after failures" signal on the MFA path.

R9-5 added the ``after_failures`` sign-in-risk signal: a successful sign-in that
follows several wrong passwords (or a lockout) is notable, and combined with a
network/device novelty it is *suspicious* - audited as such, counted for the
``SuspiciousSignIns`` operator alert, and e-mailed to the user as an unusual
sign-in.

For accounts **with MFA enabled** the signal was lost (fixed; now a
regression test). ``AuthService.login``
zeroes ``user.failed_login_attempts`` when it issues the MFA challenge
(``auth_service.py`` ~line 321, ``if user.mfa_enabled: user.failed_login_attempts = 0``)
and commits. ``verify_mfa`` then loads the user afresh and runs the risk
assessment inside ``_complete_login`` - by which point the pre-success failures
are gone. A password-correct + valid-TOTP sign-in from a new network, right
after repeated wrong passwords, is therefore classified only ``unfamiliar``
instead of ``suspicious``: the operator alert never counts it and the user is
told merely of a "new device" instead of an unusual sign-in.

``TestControlNonMfa`` shows the intended behaviour on the non-MFA path (the same
scenario is correctly ``suspicious``); ``TestMfaPath`` pins the defect.
"""

from __future__ import annotations

from datetime import timedelta

import pyotp
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.identity.auth_service import TokenPair
from nexusflow.domain.identity.login_risk import FAILURES_BEFORE_SUCCESS, LoginRisk
from nexusflow.domain.shared.context import RequestMeta
from tests.support.fixtures import META, PASSWORD, register

pytestmark = [pytest.mark.security, pytest.mark.integration]

AGENT = "pytest"  # the user agent of the registration session (tests.support META)
HOME_IP = "203.0.113.10"  # same /24 as the registration session: a familiar network
NEW_IP = "192.0.2.44"  # a different /24: a new network


def _meta(ip: str) -> RequestMeta:
    return RequestMeta(request_id="req-r10-risk", ip=ip, user_agent=AGENT)


async def _principal(container: Container, tokens: TokenPair) -> Principal:
    return await container.authenticator.authenticate(tokens.access_token)


async def _fail_logins(container: Container, email: str, times: int, *, ip: str) -> None:
    for _ in range(times):
        with pytest.raises(AuthenticationError):
            await container.auth.login(
                email=email, password="wrong-password-000", org_id=None, meta=_meta(ip)
            )


class TestControlNonMfa:
    async def test_success_from_a_new_network_after_failures_is_suspicious(
        self, container: Container
    ) -> None:
        """Baseline (no MFA): the very scenario the MFA path mishandles."""
        email, _ = await register(container)
        await _fail_logins(container, email, FAILURES_BEFORE_SUCCESS, ip=HOME_IP)
        result = await container.auth.login(
            email=email, password=PASSWORD, org_id=None, meta=_meta(NEW_IP)
        )
        assert result.tokens is not None
        assert result.tokens.login_risk is LoginRisk.SUSPICIOUS


class TestMfaPath:
    # Fixed: the signed MFA challenge carries the wrong passwords that preceded it.
    async def test_success_from_a_new_network_after_failures_is_suspicious(
        self, container: Container
    ) -> None:
        email, tokens = await register(container)
        principal = await _principal(container, tokens)
        enrollment = await container.auth.begin_mfa_enrollment(
            principal, password=PASSWORD, meta=META
        )
        totp = pyotp.TOTP(enrollment.secret)
        # Enrol with the previous step so the current step stays usable for a login.
        await container.auth.confirm_mfa_enrollment(
            principal,
            code=totp.at(container.clock.now() - timedelta(seconds=30)),
            meta=_meta(HOME_IP),
        )

        await _fail_logins(container, email, FAILURES_BEFORE_SUCCESS, ip=HOME_IP)

        challenge = await container.auth.login(
            email=email, password=PASSWORD, org_id=None, meta=_meta(HOME_IP)
        )
        assert challenge.mfa_challenge is not None
        pair = await container.auth.verify_mfa(
            challenge_token=challenge.mfa_challenge,
            code=totp.at(container.clock.now()),
            meta=_meta(NEW_IP),  # new network, right after several wrong passwords
        )
        # Same conditions as the non-MFA control above -> should be SUSPICIOUS.
        assert pair.login_risk is LoginRisk.SUSPICIOUS
