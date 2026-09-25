"""Validation of model output - the model is treated as an untrusted component.

Output is accepted only if it parses as the strict :class:`AnalysisOutput`
schema, does not echo the secret prompt boundary, and cites mostly real change
ids. Links to hosts that do not occur in the analysed data are removed, so an
indirect prompt injection cannot turn an insight into a phishing message.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from nexusflow.core.errors import PermanentError
from nexusflow.core.text import clean_text
from nexusflow.domain.intelligence.model import AnalysisOutput

MAX_OUTPUT_CHARS = 60_000
_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+")
# A bare host with a path ("evil.example/login"): clients turn it into a link.
_BARE = re.compile(
    r"(?i)(?<![\w@./:-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}/[^\s<>\"')\]]*"
)
_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{1,63}$")
_LEAK_MARKERS = ("untrusted-data marker", "security rules - these override")


class OutputRejectedError(PermanentError):
    default_code = "ai_output_rejected"
    default_message = "The AI output failed validation."


def _extract_json(text: str) -> Any:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        candidate = candidate[candidate.find("{") :]
    start, end = candidate.find("{"), candidate.rfind("}")
    if start < 0 or end <= start:
        raise OutputRejectedError(code="ai_output_not_json")
    try:
        return json.loads(candidate[start : end + 1])
    except ValueError as exc:
        raise OutputRejectedError(code="ai_output_not_json") from exc


def _host(url: str) -> str | None:
    """The host a browser would open for ``url``, or None if it is not plain.

    Browsers read a backslash as a slash and end the host at "?" or "#", so
    "https://evil.example?.shop.example.com/" opens evil.example; only an
    ASCII host name counts (no user-info tricks, no look-alike Unicode).
    """
    candidate = url.replace("\\", "/")
    if not re.match(r"(?i)^https?://", candidate):
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
    except ValueError:
        return None
    if host is None or parts.username is not None or not _HOSTNAME.fullmatch(host):
        return None
    return host


def _scrub_urls(text: str, allowed_hosts: frozenset[str]) -> str:
    allowed = frozenset(h.lower().removeprefix("www.") for h in allowed_hosts)

    def replace(match: re.Match[str]) -> str:
        url = match.group(0)
        host = _host(url)
        if host is not None and any(host == h or host.endswith("." + h) for h in allowed):
            return url
        return "[link removed]"

    return _BARE.sub(replace, _URL.sub(replace, text))


def validate_output(
    text: str | None,
    *,
    boundary: str,
    allowed_change_ids: frozenset[str],
    allowed_hosts: frozenset[str],
) -> AnalysisOutput:
    if not text or len(text) > MAX_OUTPUT_CHARS:
        raise OutputRejectedError(code="ai_output_empty_or_too_long")
    lowered = text.lower()
    if boundary.lower() in lowered or any(marker in lowered for marker in _LEAK_MARKERS):
        raise OutputRejectedError(code="ai_output_prompt_echo")
    try:
        parsed = AnalysisOutput.model_validate(_extract_json(text))
    except ValidationError as exc:
        raise OutputRejectedError(
            code="ai_output_schema_violation", internal_detail=str(exc)[:500]
        ) from exc
    total_refs = sum(len(f.change_refs) for f in parsed.findings)
    unknown = sum(
        1 for f in parsed.findings for ref in f.change_refs if ref not in allowed_change_ids
    )
    if total_refs and unknown / total_refs > 0.5:
        raise OutputRejectedError(code="ai_output_hallucinated_references")

    def clean(value: str, limit: int) -> str:
        return _scrub_urls(clean_text(value, max_length=limit, multiline=True), allowed_hosts)

    findings = [
        finding.model_copy(
            update={
                "title": clean(finding.title, 160),
                "detail": clean(finding.detail, 1200),
                "change_refs": [r for r in finding.change_refs if r in allowed_change_ids],
            }
        )
        for finding in parsed.findings
    ]
    return parsed.model_copy(
        update={
            "summary": clean(parsed.summary, 2000),
            "findings": findings,
            "recommendations": [clean(r, 500) for r in parsed.recommendations],
        }
    )
