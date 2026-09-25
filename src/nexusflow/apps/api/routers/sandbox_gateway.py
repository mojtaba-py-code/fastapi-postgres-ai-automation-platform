"""Sandbox gateway (internal app): the sandbox's only way into the platform.

The sandbox worker has no database, storage or secrets. For each run it holds
a ticket (``X-Sandbox-Ticket``) bound to ``(org, run, attempt)``; with it, it
can download that run's input file once and submit that run's results -
nothing else. See :mod:`nexusflow.domain.pipeline.collection`.

Result submissions are verified *before* the body is read: an invalid ticket
costs one indexed lookup, never a large parse. Accepted bodies are capped per
run, pre-checked for their object count and parsed off the event loop - large
ones one at a time, so even valid tickets cannot exhaust the process memory.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response, status
from fastapi.responses import StreamingResponse

from nexusflow.apps.api.dependencies import ContainerDep, rate_limited
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES
from nexusflow.bootstrap.container import Container
from nexusflow.core.errors import InvalidInputError, PayloadTooLargeError, ServiceUnavailableError

_ERROR_CODE = re.compile(r"^[a-z0-9_]{1,64}$")
RESULT_PATH = r"^/internal/v1/sandbox/orgs/[^/]+/runs/[^/]+/result$"
_BYTES_PER_ITEM = 16 * 1024  # generous; flat items of bounded scalars
_UPLOAD_EXPANSION = 8  # JSON repeats field names per row; XLSX is zip-compressed
_MIN_BODY = 1024 * 1024
_SMALL_BODY = 2 * 1024 * 1024
_SLOT_WAIT_SECONDS = 30.0
# api-internal is a single process. Result bodies above _SMALL_BODY are buffered
# and parsed one at a time, so its memory stays bounded even for a compromised
# sandbox holding many valid tickets: it can only queue its own submissions.
_LARGE_RESULTS = asyncio.Semaphore(1)

Ticket = Annotated[str, Header(alias="X-Sandbox-Ticket", pattern=r"^[0-9a-f]{64}$")]

router = APIRouter(
    prefix="/internal/v1/sandbox",
    tags=["internal-sandbox"],
    responses=ERROR_RESPONSES,
    dependencies=[Depends(rate_limited("sandbox.gateway"))],
)


def result_body_limit(max_upload_bytes: int) -> int:
    """Outer cap enforced by the body-size middleware on this path."""
    return max(16 * 1024 * 1024, max_upload_bytes * 4)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")  # NaN/Infinity are not JSON


def _parse(body: bytes | bytearray, max_items: int) -> Any:
    # A C-speed upper bound on the number of objects, before building any.
    if body.count(b"{") > max_items * 4 + 16:
        raise InvalidInputError("The result holds too many objects.", code="invalid_result")
    try:
        return json.loads(body, parse_constant=_reject_constant)
    except RecursionError as exc:  # CPython's parser bounds nesting depth itself
        raise InvalidInputError("The result is nested too deeply.", code="json_too_deep") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidInputError("Malformed JSON document.", code="malformed_json") from exc


async def _read_body(request: Request, limit: int) -> bytearray:
    body = bytearray()  # grows in place: no second full-size copy on join
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise PayloadTooLargeError()
        body += chunk
    return body


def _declared_length(request: Request) -> int | None:
    raw = request.headers.get("content-length", "")
    return int(raw) if raw.isdigit() and len(raw) <= 12 else None


@asynccontextmanager
async def _large_result_slot() -> AsyncIterator[None]:
    try:
        async with asyncio.timeout(_SLOT_WAIT_SECONDS):
            await _LARGE_RESULTS.acquire()
    except TimeoutError as exc:
        raise ServiceUnavailableError(
            "The gateway is busy; retry the submission later.", code="gateway_busy"
        ) from exc
    try:
        yield
    finally:
        _LARGE_RESULTS.release()


@router.get(
    "/orgs/{org_id}/runs/{run_id}/input",
    response_class=StreamingResponse,
    summary="Download the uploaded file of an upload run (once per attempt, ticket holder only)",
)
async def download_input(
    org_id: UUID, run_id: UUID, ticket: Ticket, container: ContainerDep
) -> StreamingResponse:
    source = await container.collection.sandbox_input(org_id=org_id, run_id=run_id, ticket=ticket)
    return StreamingResponse(
        container.storage.stream(source.storage_key),
        media_type="application/octet-stream",
        headers={"Content-Length": str(source.size_bytes), "X-Input-Format": source.format},
    )


@router.post(
    "/orgs/{org_id}/runs/{run_id}/result",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit extracted items (or a failure code) for a run",
)
async def submit_result(
    org_id: UUID, run_id: UUID, ticket: Ticket, request: Request, container: ContainerDep
) -> Response:
    max_items, input_bytes = await container.collection.authorize_result(
        org_id=org_id, run_id=run_id, ticket=ticket
    )
    # Uploads: parsed rows can only expand the file so much when serialized.
    # Other runs: bounded by their item cap.
    produced = input_bytes * _UPLOAD_EXPANSION if input_bytes is not None else None
    limit = min(
        result_body_limit(container.settings.storage.max_upload_bytes),
        max(_MIN_BODY, produced if produced is not None else max_items * _BYTES_PER_ITEM),
    )
    submission = _Submission(org_id, run_id, ticket, max_items)
    declared = _declared_length(request)
    if declared is not None and declared <= _SMALL_BODY:
        # HTTP framing holds the body to its declared length: small by construction.
        await _stage(request, container, submission, limit=min(limit, declared))
    else:
        # The slot covers reading, parsing *and* staging: the parsed document is
        # the large allocation, so it must be gone before the next one starts.
        async with _large_result_slot():
            await _stage(request, container, submission, limit=limit)
    return Response(status_code=status.HTTP_202_ACCEPTED)


@dataclass(frozen=True, slots=True)
class _Submission:
    org_id: UUID
    run_id: UUID
    ticket: str
    max_items: int


async def _stage(
    request: Request, container: Container, submission: _Submission, *, limit: int
) -> None:
    body = await _read_body(request, limit)
    document = await asyncio.to_thread(_parse, body, submission.max_items)
    del body
    if not isinstance(document, dict):
        raise InvalidInputError("The result must be a JSON object.", code="invalid_result")
    error_code = document.get("error_code")
    if error_code is not None and (
        not isinstance(error_code, str) or not _ERROR_CODE.fullmatch(error_code)
    ):
        raise InvalidInputError("Invalid error code.", code="invalid_result")
    detail = document.get("detail")
    await container.collection.accept_sandbox_result(
        org_id=submission.org_id,
        run_id=submission.run_id,
        ticket=submission.ticket,
        items=document.get("items", []),
        truncated=document.get("truncated") is True,
        detail=detail if isinstance(detail, dict) else None,
        error_code=error_code,
    )
