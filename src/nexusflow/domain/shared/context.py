"""Explicit request metadata passed into services (no hidden global state)."""

from __future__ import annotations

from dataclasses import dataclass

from nexusflow.core.text import single_line


@dataclass(frozen=True, slots=True)
class RequestMeta:
    """Where a request came from. Used for auditing and anomaly detection only -
    never as proof of identity (headers such as ``X-User-ID`` are not trusted).
    """

    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None

    @classmethod
    def create(
        cls, *, request_id: str | None, ip: str | None, user_agent: str | None
    ) -> RequestMeta:
        return cls(
            request_id=single_line(request_id, 64) if request_id else None,
            ip=single_line(ip, 45) if ip else None,
            user_agent=single_line(user_agent, 256) if user_agent else None,
        )


SYSTEM_META = RequestMeta(request_id=None, ip=None, user_agent="nexusflow-system")
