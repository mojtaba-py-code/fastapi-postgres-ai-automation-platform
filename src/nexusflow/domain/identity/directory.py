"""An organization's directory as its identity provider sees it (SCIM 2.0).

* :class:`ScimToken` - an organization's provisioning credential (``nxp_…``),
  stored as a keyed hash only.
* :class:`DirectoryUser` - a SCIM ``User`` resource: one organization's entry
  for one platform account (which organizations never own alone).
* Accounts an identity provider creates (by SCIM or a first single sign-on)
  have no password: :func:`new_directory_account`.

The use cases are in ``provisioning`` (SCIM) and ``sso_service`` (sign-in).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from nexusflow.core.errors import InvalidInputError
from nexusflow.core.ids import uuid7
from nexusflow.core.text import clean_text
from nexusflow.domain.identity.model import User
from nexusflow.domain.identity.sso import email_domain

MAX_PAGE_SIZE = 200
# The password hash of an account created by an identity provider: no password
# ever verifies against it (the anonymised accounts use the same value).
UNUSABLE_PASSWORD = "!"  # noqa: S105 - not a password: an impossible hash  # nosec B105


@dataclass(eq=False, kw_only=True)
class ScimToken:
    id: UUID
    org_id: UUID
    name: str
    token_prefix: str
    token_hash: str
    created_by: UUID | None
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    def is_usable(self, now: datetime) -> bool:
        return self.revoked_at is None and self.expires_at > now


@dataclass(eq=False, kw_only=True)
class DirectoryUser:
    """A SCIM ``User`` resource: one organization's directory entry for an account."""

    id: UUID
    org_id: UUID
    user_id: UUID
    user_name: str
    external_id: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    formatted_name: str | None = None
    active: bool = True
    created_at: datetime
    updated_at: datetime


class DirectoryFilterField(StrEnum):
    USER_NAME = "userName"
    EXTERNAL_ID = "externalId"
    EMAIL = "emails.value"


@dataclass(frozen=True, slots=True)
class DirectoryFilter:
    """``<field> eq "<value>"`` - the only filter supported."""

    field: DirectoryFilterField
    value: str


@dataclass(frozen=True, slots=True)
class DirectoryPage:
    total: int
    start_index: int
    items: list[DirectoryUser]


@dataclass(frozen=True, slots=True)
class DirectoryUserInput:
    """A full User representation (create and replace)."""

    user_name: str
    external_id: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    formatted_name: str | None = None
    active: bool = True


# Attributes a PATCH may change, with the value types each takes.
PATCHABLE: dict[str, type | tuple[type, ...]] = {
    "active": bool,
    "user_name": str,
    "external_id": (str, type(None)),
    "display_name": (str, type(None)),
    "given_name": (str, type(None)),
    "family_name": (str, type(None)),
    "formatted_name": (str, type(None)),
}


@dataclass(frozen=True, slots=True)
class DirectoryUserChanges:
    """Attributes set by a PATCH (``add``/``replace``); absent keys are unchanged."""

    values: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key, value in self.values.items():
            expected = PATCHABLE.get(key)
            if expected is None or not isinstance(value, expected):
                raise InvalidInputError(f"Cannot change {key!r} this way.", code="invalidValue")


def normalize_user_name(raw: str) -> str:
    """userName is the account's e-mail address (compared case-insensitively)."""
    address = clean_text(raw, max_length=254).lower()
    if email_domain(address) is None:
        raise InvalidInputError("userName must be an e-mail address.", code="invalidValue")
    return address


def new_directory_account(email: str, full_name: str, now: datetime) -> User:
    """An account created by an identity provider (SSO or SCIM): the address
    comes from the organization's own verified domain; there is no password."""
    return User(
        id=uuid7(),
        email=email,
        password_hash=UNUSABLE_PASSWORD,
        full_name=full_name,
        email_verified_at=now,
        password_changed_at=now,
        created_at=now,
        updated_at=now,
    )
