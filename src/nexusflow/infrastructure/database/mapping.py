"""Imperative (classical) ORM mapping of plain domain dataclasses to tables.

The domain layer never imports SQLAlchemy; this module attaches persistence to
the domain classes at application start-up. No relationships are mapped:
repositories issue explicit queries, which avoids implicit lazy loading (a
common source of N+1 queries and of I/O outside the tenant-scoped transaction).
"""

from __future__ import annotations

from sqlalchemy import Table, inspect
from sqlalchemy.orm import registry

from nexusflow.domain.alerts.model import Alert, AlertRule
from nexusflow.domain.automation.model import DeadLetter, Workflow, WorkflowRun
from nexusflow.domain.catalog.model import Dataset, Project
from nexusflow.domain.identity.model import (
    ApiKey,
    MfaRecoveryCode,
    PasswordResetToken,
    RefreshToken,
    ServiceAccount,
    SignupRequest,
    User,
    UserSession,
    WebAuthnCredential,
)
from nexusflow.domain.integrations.model import Integration
from nexusflow.domain.intelligence.model import Insight
from nexusflow.domain.notifications.model import NotificationChannel, NotificationDelivery
from nexusflow.domain.organizations.model import Invitation, Membership, Organization
from nexusflow.domain.records.model import Change, Record, RecordVersion
from nexusflow.domain.reports.model import Report
from nexusflow.domain.shared.outbox import OutboxMessage
from nexusflow.domain.sources.model import CollectionRun, Source
from nexusflow.domain.uploads.model import Upload
from nexusflow.domain.webhooks.model import InboundWebhookEvent, WebhookEndpoint
from nexusflow.infrastructure.database.metadata import metadata
from nexusflow.infrastructure.database.sealing import register_sealing_listeners
from nexusflow.infrastructure.database.tables import data as d
from nexusflow.infrastructure.database.tables import identity as t

mapper_registry = registry(metadata=metadata)

_MAPPINGS: list[tuple[type, Table]] = [
    (Organization, t.organizations),
    (User, t.users),
    (UserSession, t.user_sessions),
    (RefreshToken, t.refresh_tokens),
    (PasswordResetToken, t.password_reset_tokens),
    (SignupRequest, t.signup_requests),
    (MfaRecoveryCode, t.mfa_recovery_codes),
    (WebAuthnCredential, t.webauthn_credentials),
    (Membership, t.memberships),
    (Invitation, t.invitations),
    (ApiKey, t.api_keys),
    (ServiceAccount, t.service_accounts),
    (OutboxMessage, t.outbox_messages),
    (Project, d.projects),
    (Dataset, d.datasets),
    (Integration, d.integrations),
    (Source, d.sources),
    (Workflow, d.workflows),
    (WorkflowRun, d.workflow_runs),
    (CollectionRun, d.collection_runs),
    (Record, d.records),
    (RecordVersion, d.record_versions),
    (Insight, d.insights),
    (Change, d.changes),
    (NotificationChannel, d.notification_channels),
    (AlertRule, d.alert_rules),
    (Alert, d.alerts),
    (NotificationDelivery, d.notification_deliveries),
    (Report, d.reports),
    (WebhookEndpoint, d.webhook_endpoints),
    (InboundWebhookEvent, d.inbound_webhook_events),
    (Upload, d.uploads),
    (DeadLetter, d.dead_letters),
]


def register_mappings(extra: list[tuple[type, Table]] | None = None) -> None:
    """Idempotently map domain classes (safe to call from every entry point)."""
    for cls, table in [*_MAPPINGS, *(extra or [])]:
        if inspect(cls, raiseerr=False) is None:
            mapper_registry.map_imperatively(cls, table)
    register_sealing_listeners()  # sensitive values are sealed at rest, opened as rows load
