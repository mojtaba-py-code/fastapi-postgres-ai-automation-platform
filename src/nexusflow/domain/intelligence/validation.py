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

from pydantic import ValidationError

from nexusflow.core.errors import PermanentError
from nexusflow.core.text import clean_text
from nexusflow.domain.intelligence.model import AnalysisOutput

MAX_OUTPUT_CHARS = 60_000
_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+")
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


def _scrub_urls(text: str, allowed_hosts: frozenset[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        url = match.group(0)
        host = (
            re.sub(r"(?i)^(https?://)?(www\.)?", "", url).split("/", 1)[0].split(":", 1)[0].lower()
        )
        allowed = any(host == h or host.endswith("." + h) for h in allowed_hosts)
        return url if allowed else "[link removed]"

    return _URL.sub(replace, text)


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
