"""Task message schemas.

Broker messages are input like any other: every task validates its keyword
arguments against a strict model before touching a service (unknown keys are
rejected, identifiers must be UUIDs, strings are bounded).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress

from nexusflow.domain.automation.events import EventType
from nexusflow.domain.shared.files import FILES_PER_JOB


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Empty(Message):
    pass


class OrgMessage(Message):
    org_id: UUID


class OptionalOrgMessage(Message):
    org_id: UUID | None = None


class RunMessage(OrgMessage):
    run_id: UUID
    upload_id: UUID | None = None  # present on upload runs; informational


class DatasetMessage(OrgMessage):
    dataset_id: UUID


class InsightMessage(OrgMessage):
    insight_id: UUID


class DeliveryMessage(OrgMessage):
    delivery_id: UUID


class ReportMessage(OrgMessage):
    report_id: UUID


StorageKey = Annotated[
    str, Field(pattern=r"^(uploads|reports)/[0-9a-f-]{36}/[0-9a-f-]{36}\.[a-z]{3,4}$")
]


class FilesMessage(OrgMessage):
    keys: list[StorageKey] = Field(min_length=1, max_length=FILES_PER_JOB)


class SignInMessage(Message):
    at: AwareDatetime
    ip: IPvAnyAddress | None = None
    client: str = Field(pattern=r"^[A-Za-z ]{1,40}$")  # a fixed-vocabulary description


class SecurityEmailMessage(Message):
    user_id: UUID
    template: str = Field(pattern=r"^[a-z_]{1,48}$")
    sign_in: SignInMessage | None = None


class InvitationMessage(OrgMessage):
    invitation_id: UUID


class PasswordResetMessage(Message):
    reset_id: UUID


class OperatorAlertMessage(Message):
    severity: Literal["info", "warning", "critical"]
    summary: str = Field(max_length=500)


class EventMessage(Message):
    """Domain event envelope; the payload varies by event but holds IDs only."""

    model_config = ConfigDict(extra="allow", frozen=True)

    event: EventType
    org_id: UUID | None = None

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def value(self, key: str) -> Any:
        return (self.model_extra or {}).get(key)
