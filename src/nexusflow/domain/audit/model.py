"""Audit trail model.

Audit entries form a per-organization hash chain::

    hash_n = SHA-256(hash_{n-1} || canonical_n)

``canonical_n`` is the canonical JSON of every audited field, stored alongside
the row. The chain is appended by a ``SECURITY DEFINER`` database function (the
application role cannot INSERT/UPDATE/DELETE audit rows directly), and
:func:`verify_chain` recomputes it to detect tampering, deletion or reordering.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from nexusflow.core.jsonutil import JSONObject, canonical_json

GENESIS_HASH = bytes(32)
# Chain key of events that belong to no tenant (failed sign-ins for unknown
# accounts, operator CLI actions): the nil UUID, as in nf_append_audit.
PLATFORM_CHAIN = UUID(int=0)


class ActorType(StrEnum):
    USER = "user"
    API_KEY = "api_key"
    SERVICE = "service"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"


class AuditResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditAction(StrEnum):
    # authentication / sessions
    REGISTERED = "auth.registered"
    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_LOCKED = "auth.login.locked"
    LOGIN_NEW_DEVICE = "auth.login.new_device"  # new device *or* new network
    LOGIN_SUSPICIOUS = "auth.login.suspicious"
    MFA_FAILED = "auth.mfa.failed"
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_DISABLED = "auth.mfa.disabled"
    MFA_RECOVERY_USED = "auth.mfa.recovery_code_used"
    LOGOUT = "auth.logout"
    LOGOUT_ALL = "auth.logout_all"
    SESSION_REVOKED = "auth.session.revoked"
    REFRESH_REUSE_DETECTED = "auth.refresh.reuse_detected"
    PASSWORD_CHANGED = "auth.password.changed"  # noqa: S105 - event name  # nosec B105
    PASSWORD_CHANGE_FAILED = "auth.password.change_failed"  # noqa: S105 - event name  # nosec B105
    # A wrong password where an action asked for it (MFA, account deletion).
    PASSWORD_CONFIRMATION_FAILED = "auth.password.confirmation_failed"  # noqa: S105  # nosec B105
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"  # noqa: S105 - event name  # nosec B105
    PASSWORD_RESET_COMPLETED = "auth.password.reset_completed"  # noqa: S105 - event name  # nosec B105
    ORG_SWITCHED = "auth.org_switched"
    # A member's valid sign-in or switch into the organization, refused (or
    # started without the organization) by its network allowlist.
    NETWORK_ACCESS_DENIED = "auth.network_denied"
    ACCOUNT_DELETED = "auth.account_deleted"
    # organization & membership
    ORG_CREATED = "org.created"
    ORG_UPDATED = "org.updated"
    ORG_DELETION_REQUESTED = "org.deletion_requested"
    ORG_AUTOMATION_FROZEN = "org.automation_frozen"
    ORG_AUTOMATION_UNFROZEN = "org.automation_unfrozen"
    ORG_NETWORK_ALLOWLIST_CLEARED = "org.network_allowlist_cleared"  # operator recovery
    MEMBER_INVITED = "member.invited"
    MEMBER_INVITATION_REVOKED = "member.invitation_revoked"
    MEMBER_JOINED = "member.joined"
    MEMBER_ROLE_CHANGED = "member.role_changed"
    MEMBER_REMOVED = "member.removed"
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    # data management
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"
    DATASET_CREATED = "dataset.created"
    DATASET_UPDATED = "dataset.updated"
    DATASET_DELETED = "dataset.deleted"
    DATASET_EXPORTED = "dataset.exported"
    SOURCE_CREATED = "source.created"
    SOURCE_UPDATED = "source.updated"
    SOURCE_DELETED = "source.deleted"
    SOURCE_RUN_REQUESTED = "source.run_requested"
    UPLOAD_ACCEPTED = "upload.accepted"
    UPLOAD_REJECTED = "upload.rejected"
    # credentials & integrations
    INTEGRATION_CREATED = "integration.created"
    INTEGRATION_ROTATED = "integration.rotated"
    INTEGRATION_REVOKED = "integration.revoked"
    INTEGRATION_QUARANTINED = "integration.quarantined"
    WEBHOOK_ENDPOINT_CREATED = "webhook.endpoint_created"
    WEBHOOK_SECRET_ROTATED = "webhook.secret_rotated"  # noqa: S105 - event name  # nosec B105
    WEBHOOK_ENDPOINT_DISABLED = "webhook.endpoint_disabled"
    CHANNEL_CREATED = "channel.created"
    CHANNEL_UPDATED = "channel.updated"
    CHANNEL_DELETED = "channel.deleted"
    # intelligence, alerting, reporting
    ALERT_RULE_CREATED = "alert_rule.created"
    ALERT_RULE_UPDATED = "alert_rule.updated"
    ALERT_RULE_DELETED = "alert_rule.deleted"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    INSIGHT_REQUESTED = "insight.requested"
    INSIGHT_GENERATED = "insight.generated"
    REPORT_REQUESTED = "report.requested"
    REPORT_DOWNLOADED = "report.downloaded"
    # automation
    WORKFLOW_CREATED = "workflow.created"
    WORKFLOW_UPDATED = "workflow.updated"
    WORKFLOW_DISABLED = "workflow.disabled"
    WORKFLOW_DELETED = "workflow.deleted"
    WORKFLOW_ENABLED = "workflow.enabled"
    WORKFLOW_EXECUTED = "workflow.executed"
    AUTOMATION_STEP = "automation.step"
    SERVICE_ACCOUNT_CREATED = "service_account.created"
    SERVICE_ACCOUNT_ROTATED = "service_account.rotated"
    SERVICE_ACCOUNT_DISABLED = "service_account.disabled"
    SERVICE_ACCOUNT_ENABLED = "service_account.enabled"
    # data lifecycle (maintenance jobs)
    RETENTION_PURGED = "data.retention_purged"
    DATASET_PURGED = "dataset.purged"
    ORG_PURGED = "org.purged"
    PLATFORM_KILL_SWITCH_ENGAGED = "platform.kill_switch_engaged"
    PLATFORM_KILL_SWITCH_RELEASED = "platform.kill_switch_released"
    ENCRYPTION_KEYS_REWRAPPED = "platform.encryption_keys_rewrapped"
    DEAD_LETTER_RETRIED = "dead_letter.retried"
    DEAD_LETTER_DISCARDED = "dead_letter.discarded"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: UUID
    org_id: UUID | None
    occurred_at: datetime
    actor_type: ActorType
    actor_id: UUID | None
    action: AuditAction
    resource_type: str | None
    resource_id: str | None
    result: AuditResult
    ip: str | None
    user_agent: str | None
    request_id: str | None
    metadata: JSONObject

    @property
    def chain_key(self) -> UUID:
        return self.org_id or PLATFORM_CHAIN

    def canonical(self) -> str:
        return canonical_json(
            {
                "id": self.id,
                "org_id": self.org_id,
                "occurred_at": self.occurred_at,
                "actor_type": self.actor_type,
                "actor_id": self.actor_id,
                "action": self.action,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
                "result": self.result,
                "ip": self.ip,
                "user_agent": self.user_agent,
                "request_id": self.request_id,
                "metadata": self.metadata,
            }
        )


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    """A persisted audit row, as read back for queries and verification."""

    id: UUID
    org_id: UUID | None
    seq: int
    occurred_at: datetime
    actor_type: str
    actor_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    result: str
    ip: str | None
    user_agent: str | None
    request_id: str | None
    metadata: JSONObject
    canonical: str
    prev_hash: bytes
    hash: bytes


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    checked: int
    first_invalid_seq: int | None = None
    reason: str | None = None


def chain_hash(prev_hash: bytes, canonical: str) -> bytes:
    return hashlib.sha256(prev_hash + canonical.encode("utf-8")).digest()


def verify_chain(entries: Iterable[AuditLogEntry]) -> ChainVerification:
    """Verify linkage, hashes and that canonical text matches the row columns.

    ``entries`` must be one chain ordered by ``seq``. Verification starts at the
    first entry supplied, so chains truncated by retention can still be checked.
    """
    previous: AuditLogEntry | None = None
    checked = 0
    for entry in entries:
        if previous is not None:
            if entry.seq != previous.seq + 1:
                return ChainVerification(False, checked, entry.seq, "sequence_gap")
            if not hmac.compare_digest(entry.prev_hash, previous.hash):
                return ChainVerification(False, checked, entry.seq, "broken_link")
        if not hmac.compare_digest(chain_hash(entry.prev_hash, entry.canonical), entry.hash):
            return ChainVerification(False, checked, entry.seq, "hash_mismatch")
        if not _canonical_matches_columns(entry):
            return ChainVerification(False, checked, entry.seq, "row_modified")
        previous = entry
        checked += 1
    return ChainVerification(True, checked)


def _canonical_matches_columns(entry: AuditLogEntry) -> bool:
    try:
        payload = json.loads(entry.canonical)
    except ValueError:
        return False
    expected = {
        "id": str(entry.id),
        "org_id": str(entry.org_id) if entry.org_id else None,
        "actor_type": entry.actor_type,
        "actor_id": str(entry.actor_id) if entry.actor_id else None,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "result": entry.result,
        "ip": entry.ip,
        "user_agent": entry.user_agent,
        "request_id": entry.request_id,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        return False
    try:
        occurred_at = datetime.fromisoformat(str(payload.get("occurred_at")))
    except ValueError:
        return False
    if occurred_at != entry.occurred_at:
        return False
    return canonical_json(payload.get("metadata")) == canonical_json(entry.metadata)
