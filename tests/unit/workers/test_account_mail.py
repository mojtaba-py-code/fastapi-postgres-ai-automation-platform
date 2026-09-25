"""Account mail when e-mail is deliberately off (review F-12b).

An empty SMTP host means "no e-mail". Account mail - sign-in notices,
invitations, password resets - used to fail as smtp_not_configured, so every
message became a dead letter and DeadLettersAccumulating fired for a setting
the operator chose. It is now skipped and logged; with SMTP configured it is
sent as before.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from nexusflow.apps.workers import handlers
from nexusflow.apps.workers.messages import (
    InvitationMessage,
    PasswordResetMessage,
    SecurityEmailMessage,
)


class RecordingEmails:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send_notification(self, **_: Any) -> None:
        self.sent.append("notification")

    async def send_invitation(self, **_: Any) -> None:
        self.sent.append("invitation")

    async def send_password_reset(self, **_: Any) -> None:
        self.sent.append("password_reset")


def _deps(smtp_host: str | None) -> tuple[Any, RecordingEmails]:
    emails = RecordingEmails()
    settings = SimpleNamespace(notifications=SimpleNamespace(smtp_host=smtp_host))
    container = SimpleNamespace(settings=settings, security_emails=emails)
    return SimpleNamespace(container=container), emails


async def _send_all(deps: Any) -> None:
    await handlers.send_security_email(
        deps, SecurityEmailMessage(user_id=uuid4(), template="new_device_login")
    )
    await handlers.send_invitation(deps, InvitationMessage(org_id=uuid4(), invitation_id=uuid4()))
    await handlers.send_password_reset(deps, PasswordResetMessage(reset_id=uuid4()))


@pytest.mark.parametrize("host", [None, ""])
async def test_without_smtp_account_mail_is_skipped_not_failed(host: str | None) -> None:
    deps, emails = _deps(host)
    await _send_all(deps)  # no exception: nothing is retried or dead-lettered
    assert emails.sent == []


async def test_with_smtp_account_mail_is_sent() -> None:
    deps, emails = _deps("smtp.example.com")
    await _send_all(deps)
    assert emails.sent == ["notification", "invitation", "password_reset"]
