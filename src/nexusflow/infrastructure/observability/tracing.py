"""OpenTelemetry tracing (enabled when an OTLP endpoint is configured)."""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

from nexusflow.core.config import ObservabilitySettings

_configured = False


def configure_tracing(settings: ObservabilitySettings, *, service_name: str) -> bool:
    """Install a tracer provider once per process; returns True if tracing is on."""
    global _configured  # noqa: PLW0603 - OpenTelemetry's provider is process-global by design
    if settings.otlp_endpoint is None:
        return False
    if _configured:
        return True
    provider = TracerProvider(
        resource=Resource.create({"service.name": service_name}),
        sampler=ParentBased(TraceIdRatioBased(settings.trace_sample_ratio)),
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=f"{settings.otlp_endpoint.rstrip('/')}/v1/traces")
        )
    )
    trace.set_tracer_provider(provider)
    _configured = True
    return True


def instrument_fastapi(app: Any) -> None:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # noqa: PLC0415

    # Never record request/response headers: they carry bearer tokens.
    FastAPIInstrumentor.instrument_app(app, excluded_urls="health/live,health/ready,metrics")


def instrument_sqlalchemy(engine: Any) -> None:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # noqa: PLC0415

    SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine, enable_commenter=False)


def instrument_celery() -> None:
    """Task spans on both sides: publishers inject the trace context into task
    headers, workers continue it - an API request and the jobs it caused share
    one trace (and one ``trace_id`` in the logs)."""
    from opentelemetry.instrumentation.celery import CeleryInstrumentor  # noqa: PLC0415

    CeleryInstrumentor().instrument()  # type: ignore[no-untyped-call]


def tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)
