"""Prometheus metrics.

All metrics are defined in one place so names and label sets stay consistent.
Label values are always drawn from small, fixed vocabularies (route templates,
status classes, enum values) - never from user input - to avoid cardinality
explosions and to keep tenant data out of the metrics backend.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from prometheus_client import Counter, Gauge, Histogram

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_JOB_BUCKETS = (0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600)

# --- HTTP API ------------------------------------------------------------------
HTTP_REQUESTS = Counter(
    "nexusflow_http_requests_total",
    "HTTP requests handled by the API.",
    ["method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "nexusflow_http_request_duration_seconds",
    "HTTP request latency.",
    ["method", "route"],
    buckets=_LATENCY_BUCKETS,
)
HTTP_IN_FLIGHT = Gauge("nexusflow_http_requests_in_flight", "In-flight HTTP requests.")

# --- Security --------------------------------------------------------------------
AUTH_EVENTS = Counter(
    "nexusflow_auth_events_total",
    "Authentication events.",
    ["event", "result"],
)
RATE_LIMIT_REJECTIONS = Counter(
    "nexusflow_rate_limit_rejections_total",
    "Requests rejected by rate limiting.",
    ["scope"],
)
SSRF_BLOCKED = Counter(
    "nexusflow_ssrf_blocked_total",
    "Outbound requests blocked by the egress policy.",
    ["reason"],
)
WEBHOOK_EVENTS = Counter(
    "nexusflow_webhook_events_total",
    "Inbound webhook deliveries.",
    ["result"],
)
MALWARE_SCANS = Counter(
    "nexusflow_malware_scans_total",
    "Uploads scanned by ClamAV, by result (clean, infected or unavailable).",
    ["result"],
)
AUDIT_CHAIN_VERIFICATIONS = Counter(
    "nexusflow_audit_chain_verifications_total",
    "Scheduled audit hash-chain verifications, by result (ok or broken).",
    ["result"],
)
AUTHORIZATION_DENIALS = Counter(
    "nexusflow_authorization_denials_total",
    "Operations denied by authorization checks.",
    ["permission"],
)

# --- Pipelines / workflows -------------------------------------------------------
COLLECTION_RUNS = Counter(
    "nexusflow_collection_runs_total",
    "Collection runs by final status.",
    ["source_kind", "status"],
)
COLLECTION_DURATION = Histogram(
    "nexusflow_collection_run_duration_seconds",
    "Collection run duration.",
    ["source_kind"],
    buckets=_JOB_BUCKETS,
)
PIPELINE_ITEMS = Counter(
    "nexusflow_pipeline_items_total",
    "Items processed by pipeline stage and outcome.",
    ["stage", "outcome"],
)
CHANGES_DETECTED = Counter(
    "nexusflow_changes_detected_total",
    "Detected record changes.",
    ["change_type", "significance"],
)
WORKFLOW_RUNS = Counter(
    "nexusflow_workflow_runs_total",
    "Automation workflow runs by status.",
    ["status"],
)
WORKFLOW_STEP_DURATION = Histogram(
    "nexusflow_workflow_step_duration_seconds",
    "Automation workflow step duration.",
    ["step"],
    buckets=_JOB_BUCKETS,
)
TASKS = Counter(
    "nexusflow_tasks_total",
    "Background task executions.",
    ["task", "result"],
)
TASK_DURATION = Histogram(
    "nexusflow_task_duration_seconds",
    "Background task duration.",
    ["task"],
    buckets=_JOB_BUCKETS,
)
DEAD_LETTERS = Counter(
    "nexusflow_dead_letters_total",
    "Jobs moved to the dead-letter store.",
    ["task"],
)

# --- AI / notifications ----------------------------------------------------------
AI_REQUESTS = Counter(
    "nexusflow_ai_requests_total",
    "AI provider requests.",
    ["provider", "result"],
)
AI_TOKENS = Counter(
    "nexusflow_ai_tokens_total",
    "AI tokens consumed.",
    ["provider", "direction"],
)
AI_LATENCY = Histogram(
    "nexusflow_ai_request_duration_seconds",
    "AI provider latency.",
    ["provider"],
    buckets=_JOB_BUCKETS,
)
AI_TOOL_CALLS = Counter(
    "nexusflow_ai_tool_calls_total",
    "Tool calls requested by the AI model.",
    ["tool", "decision"],
)
NOTIFICATIONS = Counter(
    "nexusflow_notifications_total",
    "Notification delivery attempts.",
    ["channel", "result"],
)
CIRCUIT_STATE = Gauge(
    "nexusflow_circuit_breaker_open",
    "1 when a circuit breaker is open.",
    ["dependency"],
    # Across worker processes: the highest value among the *living* ones - a
    # recycled child's last state must not keep an alert firing for ever.
    multiprocess_mode="livemax",
)


@contextmanager
def observe_duration(histogram: Histogram, **labels: str) -> Iterator[None]:
    """Time the enclosed block into ``histogram`` - also when it raises."""
    started = time.perf_counter()
    try:
        yield
    finally:
        histogram.labels(**labels).observe(time.perf_counter() - started)


# Ingestion statistics -> (stage, outcome) labels of PIPELINE_ITEMS.
_PIPELINE_STAGES = {
    "valid": ("validate", "valid"),
    "invalid": ("validate", "invalid"),
    "duplicates": ("deduplicate", "duplicate"),
    "created": ("store", "created"),
    "updated": ("store", "updated"),
    "unchanged": ("store", "unchanged"),
    "deleted": ("store", "deleted"),
}


def record_ingestion(
    source_kind: str, status: str, stats: dict[str, object], duration: float | None
) -> None:
    COLLECTION_RUNS.labels(source_kind=source_kind, status=status).inc()
    if duration is not None:
        COLLECTION_DURATION.labels(source_kind=source_kind).observe(duration)
    for key, (stage, outcome) in _PIPELINE_STAGES.items():
        count = stats.get(key)
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            PIPELINE_ITEMS.labels(stage=stage, outcome=outcome).inc(count)
