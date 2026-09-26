"""Builds audit events from the current principal and request metadata."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Protocol
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.ids import uuid7
from nexusflow.core.jsonutil import JSONObject, JSONValue
from nexusflow.core.text import single_line
from nexusflow.domain.audit.model import ActorType, AuditAction, AuditEvent, AuditResult
from nexusflow.domain.authorization.principal import Principal, PrincipalType
from nexusflow.domain.shared.context import RequestMeta

_MAX_KEYS = 30
_MAX_STRING = 300
_MAX_DEPTH = 3
_SENSITIVE_KEY = re.compile(
    r"(pass|secret|token|authori[sz]ation|api[-_]?key|cookie|credential|private|signature|otp)",
    re.IGNORECASE,
)
_ACTOR_TYPES = {
    PrincipalType.USER: ActorType.USER,
    PrincipalType.API_KEY: ActorType.API_KEY,
    PrincipalType.SERVICE: ActorType.SERVICE,
    PrincipalType.SYSTEM: ActorType.SYSTEM,
    PrincipalType.SCIM: ActorType.SCIM,
}


class AuditSink(Protocol):
    async def append(self, event: AuditEvent) -> None: ...


def sanitize_metadata(data: Mapping[str, Any] | None) -> JSONObject:
    """Bound size and drop anything that looks like a credential."""
    if not data:
        return {}
    return _sanitize_mapping(data, depth=0)


def _sanitize_mapping(data: Mapping[str, Any], *, depth: int) -> JSONObject:
    result: JSONObject = {}
    for index, (key, value) in enumerate(data.items()):
        if index >= _MAX_KEYS:
            result["_truncated"] = True
            break
        name = single_line(str(key), 64)
        if _SENSITIVE_KEY.search(name) and not isinstance(value, (bool, int)):
            result[name] = "[REDACTED]"
            continue
        result[name] = _sanitize_value(value, depth=depth + 1)
    return result


def _sanitize_value(value: Any, *, depth: int) -> JSONValue:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return single_line(value, _MAX_STRING)
    if isinstance(value, UUID):
        return str(value)
    if depth >= _MAX_DEPTH:
        return "[nested]"
    if isinstance(value, Mapping):
        return _sanitize_mapping(value, depth=depth)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize_value(v, depth=depth + 1) for v in list(value)[:_MAX_KEYS]]
    return single_line(str(value), _MAX_STRING)


class AuditRecorder:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def build(
        self,
        *,
        action: AuditAction,
        principal: Principal | None,
        meta: RequestMeta,
        result: AuditResult = AuditResult.SUCCESS,
        org_id: UUID | None = None,
        resource_type: str | None = None,
        resource_id: UUID | str | None = None,
        metadata: Mapping[str, Any] | None = None,
        actor_id: UUID | None = None,
    ) -> AuditEvent:
        if principal is None:
            actor_type = ActorType.ANONYMOUS
        else:
            actor_type = _ACTOR_TYPES[principal.type]
            actor_id = actor_id or principal.id
        return AuditEvent(
            id=uuid7(),
            org_id=org_id if org_id is not None else (principal.org_id if principal else None),
            occurred_at=self._clock.now(),
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            result=result,
            ip=meta.ip,
            user_agent=meta.user_agent,
            request_id=meta.request_id,
            metadata=sanitize_metadata(metadata),
        )

    async def record(self, sink: AuditSink, **kwargs: Any) -> AuditEvent:
        event = self.build(**kwargs)
        await sink.append(event)
        return event
