"""Sandbox-side client of the internal sandbox gateway.

The gateway URL is operator configuration (never user input), so this client
talks to it directly instead of through the SSRF guard - but it still refuses
redirects, ignores proxy environment variables and bounds every download.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import httpx2

from nexusflow.core.errors import PayloadTooLargeError, PermanentError, TransientError

_TICKET_HEADER = "X-Sandbox-Ticket"


class SandboxGatewayClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float,
        transport: httpx2.AsyncBaseTransport | None = None,  # tests: in-process ASGI app
    ) -> None:
        self._client = httpx2.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            trust_env=False,
            follow_redirects=False,
            transport=transport,
        )

    @staticmethod
    def _path(org_id: UUID, run_id: UUID, leaf: str) -> str:
        return f"/internal/v1/sandbox/orgs/{org_id}/runs/{run_id}/{leaf}"

    @staticmethod
    def _raise_for(response: httpx2.Response) -> None:
        if response.status_code >= 500 or response.status_code == 429:
            raise TransientError(
                code="gateway_unavailable", internal_detail=f"HTTP {response.status_code}"
            )
        if response.status_code == 409:
            raise PermanentError(code="run_closed")  # retried/finished elsewhere: stop quietly
        if response.status_code >= 400:
            raise PermanentError(
                code="gateway_rejected", internal_detail=f"HTTP {response.status_code}"
            )

    async def download_input(
        self, org_id: UUID, run_id: UUID, *, ticket: str, destination: Path, max_bytes: int
    ) -> Literal["csv", "xlsx"]:
        """Stream the run's input file to ``destination`` (size-capped)."""
        try:
            async with self._client.stream(
                "GET", self._path(org_id, run_id, "input"), headers={_TICKET_HEADER: ticket}
            ) as response:
                self._raise_for(response)
                received = 0
                with destination.open("wb") as handle:
                    async for chunk in response.aiter_bytes():
                        received += len(chunk)
                        if received > max_bytes:
                            raise PayloadTooLargeError()
                        handle.write(chunk)
                fmt = response.headers.get("x-input-format", "csv")
        except httpx2.HTTPError as exc:
            raise TransientError(
                code="gateway_unreachable", internal_detail=type(exc).__name__
            ) from exc
        return "xlsx" if fmt == "xlsx" else "csv"

    async def submit(
        self,
        org_id: UUID,
        run_id: UUID,
        *,
        ticket: str,
        items: list[dict[str, Any]] | None = None,
        truncated: bool = False,
        detail: dict[str, Any] | None = None,
        error_code: str | None = None,
    ) -> None:
        body: dict[str, Any] = (
            {"error_code": error_code}
            if error_code is not None
            else {"items": items or [], "truncated": truncated, "detail": detail or {}}
        )
        payload = json.dumps(body, ensure_ascii=False, default=str, separators=(",", ":")).encode()
        try:
            response = await self._client.post(
                self._path(org_id, run_id, "result"),
                content=payload,
                headers={_TICKET_HEADER: ticket, "Content-Type": "application/json"},
            )
        except httpx2.HTTPError as exc:
            raise TransientError(
                code="gateway_unreachable", internal_detail=type(exc).__name__
            ) from exc
        self._raise_for(response)

    async def aclose(self) -> None:
        await self._client.aclose()
