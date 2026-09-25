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
# Answers that make a job moot rather than failed - there is nothing to report:
# a stale ticket (401), a run that finished or moved on, or an attempt whose
# result is already in (409).
MOOT_CODES = frozenset({"invalid_ticket", "run_closed", "no_input"})


async def _error_code(response: httpx2.Response) -> str | None:
    """The platform's error code from a (small) error answer, if it has one."""
    body = b""
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) > 4096:  # not one of the platform's error answers
            return None
    try:
        document = json.loads(body)
    except ValueError:
        return None
    code = document.get("error") if isinstance(document, dict) else None
    return code if isinstance(code, str) else None


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
    async def _raise_for(response: httpx2.Response) -> None:
        status = response.status_code
        if status >= 500 or status == 429:
            raise TransientError(code="gateway_unavailable", internal_detail=f"HTTP {status}")
        if status == 401:
            # A stale ticket: the run was handed to a new attempt meanwhile.
            raise PermanentError(code="invalid_ticket")
        if status == 409:
            code = await _error_code(response)
            raise PermanentError(code=code if code in MOOT_CODES else "run_closed")
        if status >= 400:
            # The result itself was refused (too large, malformed...): a failure.
            detail = f"HTTP {status} {await _error_code(response)}"
            raise PermanentError(code="gateway_rejected", internal_detail=detail)

    async def download_input(
        self, org_id: UUID, run_id: UUID, *, ticket: str, destination: Path, max_bytes: int
    ) -> Literal["csv", "xlsx"]:
        """Stream the run's input file to ``destination`` (size-capped)."""
        try:
            async with self._client.stream(
                "GET", self._path(org_id, run_id, "input"), headers={_TICKET_HEADER: ticket}
            ) as response:
                await self._raise_for(response)
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
        try:
            # Standard JSON only: NaN and Infinity would be refused by the gateway.
            text = json.dumps(
                body, ensure_ascii=False, allow_nan=False, default=str, separators=(",", ":")
            )
        except ValueError as exc:
            raise PermanentError(code="invalid_result", internal_detail=str(exc)[:200]) from exc
        try:
            response = await self._client.post(
                self._path(org_id, run_id, "result"),
                content=text.encode(),
                headers={_TICKET_HEADER: ticket, "Content-Type": "application/json"},
            )
        except httpx2.HTTPError as exc:
            raise TransientError(
                code="gateway_unreachable", internal_detail=type(exc).__name__
            ) from exc
        await self._raise_for(response)

    async def aclose(self) -> None:
        await self._client.aclose()
