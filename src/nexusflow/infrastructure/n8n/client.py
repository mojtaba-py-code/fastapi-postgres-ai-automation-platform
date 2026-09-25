"""n8n integration: signed event webhooks and workflow kill switch.

Events are POSTed to n8n *internal* webhook URLs with a short-lived HS256 JWT
(``exp`` 60 s, unique ``jti``, audience ``n8n``) verified by n8n's "JWT Auth"
webhook authentication - n8n rejects forged or stale calls. Payloads contain
identifiers only. The n8n base URL is operator configuration (never user
input), so this client talks to it directly rather than through the SSRF guard.
"""

from __future__ import annotations

import time
from typing import Any

import httpx2
import jwt

from nexusflow.core.errors import PermanentError, TransientError
from nexusflow.core.ids import uuid7

# Event -> n8n webhook paths (one per listening workflow). An event may fan out
# to several workflows; a path no active workflow registers answers 404 and is
# skipped - events without listeners are not failures.
EVENT_PATHS: dict[str, tuple[str, ...]] = {
    "collection.completed": ("nexusflow/collection-completed",),
    "changes.detected": (
        "nexusflow/changes-detected/alerting",
        "nexusflow/changes-detected/analysis",
    ),
    "insight.created": ("nexusflow/insight-created",),
    "alert.triggered": ("nexusflow/alert-triggered",),
    "job.failed": ("nexusflow/job-failed",),
}


class N8nClient:
    def __init__(
        self,
        *,
        webhook_base_url: str,
        api_base_url: str,
        jwt_secret: str,
        api_key: str | None,
        timeout_seconds: float,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        if len(jwt_secret) < 32:
            raise ValueError("n8n webhook JWT secret must be at least 32 characters")
        self._webhook_base = webhook_base_url.rstrip("/")
        self._api_base = api_base_url.rstrip("/")
        self._secret = jwt_secret
        self._api_key = api_key
        self._client = httpx2.AsyncClient(
            timeout=timeout_seconds, trust_env=False, follow_redirects=False, transport=transport
        )

    def _token(self, event: str) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": "nexusflow",
                "aud": "n8n",
                "iat": now,
                "exp": now + 60,
                "jti": str(uuid7()),
                "event": event,
            },
            self._secret,
            algorithm="HS256",
        )

    async def emit(self, event: str, payload: dict[str, Any]) -> int:
        """Deliver an event to every listening workflow; returns deliveries made.

        Receivers are idempotent, so re-delivering to all paths after a partial
        failure (the task is retried) is safe.
        """
        paths = EVENT_PATHS.get(event)
        if paths is None:
            raise PermanentError(code="unknown_event")
        delivered = 0
        for path in paths:
            try:
                response = await self._client.post(
                    f"{self._webhook_base}/{path}",
                    json=payload,
                    headers={"Authorization": f"Bearer {self._token(event)}"},
                )
            except httpx2.HTTPError as exc:
                raise TransientError(
                    code="n8n_unreachable", internal_detail=type(exc).__name__
                ) from exc
            if response.status_code == 404:
                continue  # no active workflow listens on this path
            if response.status_code >= 500 or response.status_code == 429:
                raise TransientError(
                    code="n8n_unavailable", internal_detail=f"HTTP {response.status_code}"
                )
            if not 200 <= response.status_code < 300:  # a redirect is not a delivery either
                raise PermanentError(
                    code="n8n_rejected", internal_detail=f"HTTP {response.status_code}"
                )
            delivered += 1
        return delivered

    async def deactivate_workflow(self, workflow_id: str) -> None:
        """Platform kill switch: stop an n8n workflow through n8n's public API.

        n8n 2.x "unpublishes" a workflow; releases before 2.0 only know
        "deactivate", so that is tried when the newer endpoint does not exist.
        """
        if not self._api_key:
            raise PermanentError(code="n8n_api_key_missing")
        if not workflow_id.isalnum():
            raise PermanentError(code="invalid_workflow_id")
        response = await self._api_post(f"/api/v1/workflows/{workflow_id}/unpublish")
        if response.status_code in (404, 405):
            response = await self._api_post(f"/api/v1/workflows/{workflow_id}/deactivate")
        if not 200 <= response.status_code < 300:
            raise PermanentError(
                code="n8n_deactivation_failed", internal_detail=f"HTTP {response.status_code}"
            )

    async def _api_post(self, path: str) -> httpx2.Response:
        try:
            return await self._client.post(
                f"{self._api_base}{path}", headers={"X-N8N-API-KEY": self._api_key or ""}
            )
        except httpx2.HTTPError as exc:
            raise TransientError(
                code="n8n_unreachable", internal_detail=type(exc).__name__
            ) from exc

    async def aclose(self) -> None:
        await self._client.aclose()
