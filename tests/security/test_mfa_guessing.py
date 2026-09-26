"""Second-factor guesses cannot outrun the lockout (review R13-6).

The password step reset the failure counter when it issued the MFA
challenge. Whoever knew the password could guess four TOTP codes, sign in
with the password again and guess four more - held back only by the rate
limits: some 20 guesses a minute per account, about an 8 % chance of a hit a
day. The counter now runs across both factors until a sign-in completes.
"""

from __future__ import annotations

from datetime import timedelta

import asyncpg
import pyotp
import pytest

from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import AuthenticationError
from tests.support.fixtures import META, PASSWORD, register

pytestmark = [pytest.mark.security, pytest.mark.integration]


async def _with_totp(container: Container) -> tuple[str, pyotp.TOTP]:
    email, tokens = await register(container)
    principal = await container.authenticator.authenticate(tokens.access_token)
    enrollment = await container.auth.begin_mfa_enrollment(principal, password=PASSWORD, meta=META)
    totp = pyotp.TOTP(enrollment.secret)
    await container.auth.confirm_mfa_enrollment(
        principal, code=totp.at(container.clock.now() - timedelta(seconds=30)), meta=META
    )
    return email, totp


def _wrong_code(totp: pyotp.TOTP, container: Container) -> str:
    now = container.clock.now()
    valid = {totp.at(now + timedelta(seconds=30 * step)) for step in (-1, 0, 1)}
    return next(f"{n:06d}" for n in range(1_000_000) if f"{n:06d}" not in valid)


async def _password_step(container: Container, email: str) -> str:
    result = await container.auth.login(email=email, password=PASSWORD, org_id=None, meta=META)
    assert result.mfa_challenge is not None
    return result.mfa_challenge


async def test_wrong_codes_add_up_across_password_steps(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    email, totp = await _with_totp(container)
    threshold = container.settings.security.lockout_threshold
    wrong = _wrong_code(totp, container)
    guesses = 0
    while guesses < threshold:
        challenge = await _password_step(container, email)  # the right password, again
        for _ in range(2):
            if guesses == threshold:
                break
            with pytest.raises(AuthenticationError):
                await container.auth.verify_mfa(challenge_token=challenge, code=wrong, meta=META)
            guesses += 1
    locked_until = await admin_conn.fetchval(
        "SELECT locked_until FROM users WHERE email = $1", email
    )
    assert locked_until is not None  # locked after the threshold, not per password step
    with pytest.raises(AuthenticationError):
        await _password_step(container, email)  # even the right password waits now


async def test_a_completed_sign_in_starts_the_count_afresh(
    container: Container, admin_conn: asyncpg.Connection
) -> None:
    email, totp = await _with_totp(container)
    wrong = _wrong_code(totp, container)
    challenge = await _password_step(container, email)
    with pytest.raises(AuthenticationError):
        await container.auth.verify_mfa(challenge_token=challenge, code=wrong, meta=META)
    failures = "SELECT failed_login_attempts FROM users WHERE email = $1"
    assert await admin_conn.fetchval(failures, email) == 1
    challenge = await _password_step(container, email)
    assert await admin_conn.fetchval(failures, email) == 1  # the password step keeps it
    await container.auth.verify_mfa(
        challenge_token=challenge, code=totp.at(container.clock.now()), meta=META
    )
    assert await admin_conn.fetchval(failures, email) == 0
