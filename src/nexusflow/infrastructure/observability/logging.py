"""Structured JSON logging with defensive redaction.

* Every log line is a JSON object carrying request/trace correlation ids bound
  through ``structlog.contextvars``.
* A redaction processor masks values under sensitive keys (password, token,
  secret, authorization, ...) and scrubs well-known secret formats (JWTs,
  NexusFlow API keys, bearer tokens, credentials embedded in URLs, Slack and
  Telegram webhook secrets, private keys) wherever they appear.
* Tracebacks are rendered **without local variables** - structlog's default
  would otherwise serialize function locals, which can include credentials.
* Standard-library loggers (uvicorn, celery, sqlalchemy) are routed through the
  same pipeline so third-party output is redacted too.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog
from opentelemetry import trace
from structlog.tracebacks import ExceptionDictTransformer
from structlog.typing import EventDict, Processor

REDACTED = "[REDACTED]"
_MAX_STRING = 4000
_MAX_DEPTH = 6

_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd|phrase)?|secret|token|authori[sz]ation|api[-_]?key|cookie|credential"
    r"|private[-_]?key|signature|pepper|otp|mfa[-_]?code|recovery[-_]?code|dsn|webhook[-_]?url)",
    re.IGNORECASE,
)
_SAFE_KEYS = frozenset(
    {
        "event",
        "level",
        "logger",
        "timestamp",
        "request_id",
        "trace_id",
        "span_id",
        "token_type",
        "token_use",
        "password_changed",
        "secret_rotated",
    }
)
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"nx[fsp]_[a-z2-7]{12}_[A-Za-z0-9_-]{40,60}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}"),
    re.compile(r"xox[abposr]-[A-Za-z0-9-]{8,}"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20})://[^\s:/@]+:[^\s@/]+@"),
)


def redact_text(value: str) -> str:
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(REDACTED, value)
    if len(value) > _MAX_STRING:
        value = value[:_MAX_STRING] + "…[truncated]"
    return value


def redact(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact a log payload."""
    if depth > _MAX_DEPTH:
        return "[max-depth]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            scalar = isinstance(item, (int, float, bool)) or item is None
            if not scalar and key_str not in _SAFE_KEYS and _SENSITIVE_KEY.search(key_str):
                # Numbers under "sensitive" keys (e.g. ``input_tokens``) are not secrets.
                result[key_str] = REDACTED
            else:
                result[key_str] = redact(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(item, depth=depth + 1) for item in list(value)[:100]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(repr(value))


def _redaction_processor(_: Any, __: str, event_dict: EventDict) -> EventDict:
    redacted = redact(dict(event_dict))
    event_dict.clear()
    event_dict.update(redacted)
    return event_dict


def _trace_context_processor(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> Any:
    span = trace.get_current_span()
    context = span.get_span_context()
    if context.is_valid:
        event_dict.setdefault("trace_id", format(context.trace_id, "032x"))
        event_dict.setdefault("span_id", format(context.span_id, "016x"))
    return event_dict


def configure_logging(
    *, level: str = "INFO", fmt: str = "json", service: str = "nexusflow"
) -> None:
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    def add_service(_: Any, __: str, event_dict: EventDict) -> EventDict:
        event_dict.setdefault("service", service)
        return event_dict

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        add_service,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.ExtraAdder(),
        timestamper,
        _trace_context_processor,
        structlog.processors.StackInfoRenderer(),
    ]
    exception_renderer = structlog.processors.ExceptionRenderer(
        ExceptionDictTransformer(show_locals=False, max_frames=30)
    )
    renderer: Processor
    if fmt == "console":
        # plain_traceback: never pretty-print frame locals (they may hold secrets).
        renderer = structlog.dev.ConsoleRenderer(
            colors=False, exception_formatter=structlog.dev.plain_traceback
        )
        final: list[Processor] = [_redaction_processor, renderer]
    else:
        renderer = structlog.processors.JSONRenderer()
        final = [exception_renderer, _redaction_processor, renderer]

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelNamesMapping()[level]),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, *final],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for noisy in ("uvicorn.access", "httpcore2", "httpx2", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name)
    return logger
