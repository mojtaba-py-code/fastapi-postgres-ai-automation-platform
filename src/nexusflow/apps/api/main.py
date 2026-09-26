"""FastAPI application factory.

Two deployment modes share one code base:

* ``public`` - the tenant-facing REST API behind the reverse proxy;
* ``internal`` - the automation API used only by n8n on a private network
  (never routed through the public proxy; authenticated with per-workflow
  service tokens).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
from starlette.middleware.trustedhost import TrustedHostMiddleware

from nexusflow import __version__
from nexusflow.apps.api.dependencies import ApiState, apply_api_rate_limit
from nexusflow.apps.api.errors import install_error_handlers
from nexusflow.apps.api.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from nexusflow.apps.api.routers import (
    accounts,
    auth,
    catalog,
    health,
    identity_providers,
    intelligence,
    internal,
    sandbox_gateway,
    scim,
    sources,
    webhooks,
    workflows,
)
from nexusflow.bootstrap.container import Container, build_container
from nexusflow.bootstrap.messaging import attach_outbox_publisher
from nexusflow.core.config import Settings
from nexusflow.infrastructure.observability.logging import configure_logging, get_logger
from nexusflow.infrastructure.observability.tracing import (
    configure_tracing,
    instrument_celery,
    instrument_fastapi,
    instrument_sqlalchemy,
)

type AppMode = Literal["public", "internal"]
_log = get_logger("nexusflow.api")


_MULTIPART_OVERHEAD = 64 * 1024


def _body_limits(settings: Settings, mode: AppMode) -> dict[str, int]:
    """Per-route body limits; large bodies are only allowed where they are expected."""
    if mode == "internal":
        return {
            sandbox_gateway.RESULT_PATH: sandbox_gateway.result_body_limit(
                settings.storage.max_upload_bytes
            )
        }
    return {
        r"^/api/v1/sources/[^/]+/uploads$": settings.storage.max_upload_bytes + _MULTIPART_OVERHEAD,
        # One SCIM User or PatchOp: far below the default limit.
        scim.BODY_PATH: min(scim.MAX_BODY_BYTES, settings.app.max_request_body_bytes),
    }


def create_app(
    settings: Settings | None = None,
    *,
    mode: AppMode = "public",
    container: Container | None = None,
    redis: Redis | None = None,
    configure_logs: bool = True,
) -> FastAPI:
    settings = settings or Settings()
    if configure_logs:
        configure_logging(
            level=settings.observability.log_level,
            fmt=settings.observability.log_format,
            service=f"{settings.app.name}-api-{mode}",
        )
    tracing = configure_tracing(settings.observability, service_name=f"nexusflow-api-{mode}")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        built = container or build_container(
            settings, application_name=f"nexusflow-api-{mode}", redis=redis
        )
        if container is None:
            attach_outbox_publisher(built)
        if tracing:
            instrument_sqlalchemy(built.engine)
            instrument_celery()  # tasks published by this request carry its trace
        app.state.api = ApiState(
            container=built,
            redis=built.redis,
            limiter=built.limiter,
            replay_guard=built.replay_guard,
            flags=built.flags,
        )
        for warning in settings.security_warnings():
            _log.warning("security_posture", warning=warning)
        if mode == "public":  # the public API inspects uploads through plaintext copies
            scratch = await built.storage.purge_scratch()
            if scratch:
                _log.warning("stale_plaintext_copies_removed", count=scratch)
        _log.info("api_started", mode=mode, version=__version__)
        try:
            yield
        finally:
            if container is None:
                await built.aclose()

    docs = settings.app.api_docs_enabled
    app = FastAPI(
        title="NexusFlow AI",
        version=__version__,
        summary="Enterprise automation & intelligence platform API",
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=lifespan,
    )
    install_error_handlers(app)
    app.include_router(health.router)
    if settings.observability.metrics_enabled:
        app.include_router(health.metrics_router)
    if mode == "public":
        _include_public_routes(app)
    else:
        _include_internal_routes(app)

    # Starlette wraps later additions around earlier ones: outermost last.
    if settings.app.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.app.cors_allowed_origins,
            allow_credentials=False,  # bearer tokens only - no ambient credentials
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["authorization", "content-type", "idempotency-key", "x-request-id"],
            expose_headers=["x-request-id", "retry-after"],
            max_age=600,
        )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.app.allowed_hosts)
    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=settings.app.max_request_body_bytes,
        overrides=_body_limits(settings, mode),
    )
    app.add_middleware(
        SecurityHeadersMiddleware, hsts=settings.app.public_base_url.startswith("https://")
    )
    app.add_middleware(RequestContextMiddleware, trusted_proxies=settings.app.trusted_proxies)
    if tracing:
        instrument_fastapi(app)
    return app


_PROTECTED_ROUTERS = (
    accounts.users,
    accounts.organizations,
    accounts.api_keys,
    accounts.audit,
    identity_providers.router,
    catalog.projects,
    catalog.datasets,
    catalog.records,
    catalog.changes,
    sources.sources,
    sources.runs,
    sources.integrations,
    sources.webhook_endpoints,
    intelligence.intelligence,
    intelligence.alert_rules,
    intelligence.alerts,
    intelligence.channels,
    intelligence.reports,
    intelligence.analytics,
    workflows.workflows,
    workflows.dead_letters,
)


def _include_public_routes(app: FastAPI) -> None:
    v1 = APIRouter(prefix="/api/v1")
    v1.include_router(auth.router)  # per-route limits; mostly unauthenticated
    v1.include_router(webhooks.router)  # HMAC-authenticated inbound deliveries
    protected = APIRouter(dependencies=[Depends(apply_api_rate_limit)])
    for router in _PROTECTED_ROUTERS:
        protected.include_router(router)
    v1.include_router(protected)
    app.include_router(v1)
    # SCIM provisioning: its own token type, rate limit and error schema.
    app.include_router(scim.router)


def _include_internal_routes(app: FastAPI) -> None:
    """Private network only: automation API for n8n (service tokens) and the
    sandbox gateway (per-run tickets)."""
    app.include_router(internal.router)
    app.include_router(sandbox_gateway.router)


def create_public_app() -> FastAPI:
    """ASGI factory: ``uvicorn nexusflow.apps.api.main:create_public_app --factory``."""
    return create_app(mode="public")


def create_internal_app() -> FastAPI:
    return create_app(mode="internal")
