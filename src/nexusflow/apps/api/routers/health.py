"""Liveness, readiness, JWKS and Prometheus metrics endpoints."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from nexusflow.apps.api.dependencies import StateDep

router = APIRouter(tags=["health"])


@router.get("/health/live", summary="Liveness probe (process is running)")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready", summary="Readiness probe (dependencies reachable)")
async def ready(state: StateDep) -> JSONResponse:
    checks: dict[str, str] = {}

    async def database() -> None:
        async with state.container.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    async def redis() -> None:
        await state.redis.ping()

    for name, probe in (("database", database), ("redis", redis)):
        try:
            async with asyncio.timeout(2):
                await probe()
            checks[name] = "ok"
        except Exception:  # noqa: BLE001 - any failure means "not ready"; details stay in logs
            checks[name] = "unavailable"
    healthy = all(value == "ok" for value in checks.values())
    body: dict[str, Any] = {"status": "ok" if healthy else "degraded", "checks": checks}
    return JSONResponse(body, status_code=200 if healthy else 503)


@router.get("/.well-known/jwks.json", summary="Public keys for verifying access tokens")
async def jwks(state: StateDep) -> dict[str, Any]:
    return {"keys": state.container.keyring.public_jwks()}


metrics_router = APIRouter(tags=["health"], include_in_schema=False)


@metrics_router.get("/metrics")
async def prometheus_metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
