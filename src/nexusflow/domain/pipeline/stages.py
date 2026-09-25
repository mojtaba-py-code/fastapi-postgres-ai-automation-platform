"""Data pipeline stages between Collect and Store.

    Collect -> **Validate -> Normalize -> Clean -> Deduplicate -> Enrich** -> Store -> Analyze

* **Validate** - the item is an object, every required field is present, and
  only fields declared in the dataset schema go on (data minimisation: the
  rest is never stored);
* **Normalize** - each value is coerced to its declared type and canonical
  form (numbers, booleans, UTC timestamps, lower-case hosts, enum spelling,
  NFKC text without control or invisible characters);
* **Clean** - noise that is not information is removed: optional values that
  normalised to nothing, and tracking parameters in URLs, which would
  otherwise be reported as changes;
* **Deduplicate** - one record per key; the last occurrence wins;
* **Enrich** - the canonical key and a content fingerprint for change detection.

Each stage is a pure function of its input, so the pipeline is deterministic
and unit-tested stage by stage. Collect is done by the collectors; Store,
change detection (Analyze) and deletion inference by
:mod:`nexusflow.domain.pipeline.ingestion`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, localcontext
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from nexusflow.core.jsonutil import JSONValue, content_hash
from nexusflow.core.text import clean_text
from nexusflow.domain.catalog.model import DatasetSchema, FieldSpec, FieldType

MAX_ISSUES = 100
_MAX_SAFE_INTEGER = 2**53 - 1
_MAX_DECIMAL = Decimal("1e18")
_FRACTION_DIGITS = Decimal("1e-18")
_NUMBER_CLEANUP = re.compile(r"[^\d,.\-+eE]")
# An "e" that is not an exponent marker (currency codes: "EUR 9.90", "9.90 SEK").
_STRAY_EXPONENT = re.compile(r"(?<![\d.])[eE]|[eE](?![+\-]?\d)")
_TRUE = frozenset({"true", "yes", "y", "1", "on"})
_FALSE = frozenset({"false", "no", "n", "0", "off"})
# Campaign and click identifiers: they change per visit, never per product.
_TRACKING_PARAMS = frozenset(
    {
        "gclid",
        "gbraid",
        "wbraid",
        "dclid",
        "fbclid",
        "msclkid",
        "yclid",
        "igshid",
        "mc_cid",
        "mc_eid",
        "_ga",
        "_gl",
    }
)


class ItemRejectedError(Exception):
    def __init__(self, field: str | None, code: str) -> None:
        super().__init__(code)
        self.field = field
        self.code = code


@dataclass(frozen=True, slots=True)
class ItemIssue:
    index: int
    field: str | None
    code: str


@dataclass(frozen=True, slots=True)
class CleanRecord:
    key: str
    data: dict[str, JSONValue]
    content_hash: str


@dataclass(slots=True)
class PipelineResult:
    records: list[CleanRecord] = field(default_factory=list)
    received: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    truncated: bool = False
    issues: list[ItemIssue] = field(default_factory=list)

    @property
    def invalid_ratio(self) -> float:
        return self.invalid / self.received if self.received else 0.0

    def stats(self) -> dict[str, JSONValue]:
        return {
            "received": self.received,
            "valid": self.valid,
            "invalid": self.invalid,
            "duplicates": self.duplicates,
            "truncated": self.truncated,
            "issues": [
                {"index": i.index, "field": i.field, "code": i.code} for i in self.issues[:20]
            ],
        }


# ------------------------------------------------------------ normalizers


def _normalize_string(spec: FieldSpec, value: Any, *, multiline: bool) -> str:
    if isinstance(value, (dict, list)):
        raise ItemRejectedError(spec.name, "invalid_type")
    text = clean_text(str(value), max_length=spec.effective_max_length + 1, multiline=multiline)
    if len(text) > spec.effective_max_length:
        raise ItemRejectedError(spec.name, "too_long")
    return text


def _parse_decimal(spec: FieldSpec, value: Any) -> Decimal:
    if isinstance(value, bool):
        raise ItemRejectedError(spec.name, "invalid_number")
    if isinstance(value, (int, float)):
        number = Decimal(str(value))
    else:
        text = _STRAY_EXPONENT.sub("", _NUMBER_CLEANUP.sub("", str(value).strip()))[:64]
        if "," in text and "." in text:
            # Whichever separator comes last is the decimal separator.
            if text.rfind(",") > text.rfind("."):
                text = text.replace(".", "").replace(",", ".")
            else:
                text = text.replace(",", "")
        elif "," in text:
            head, _, tail = text.rpartition(",")
            text = (
                f"{head.replace(',', '')}.{tail}" if len(tail) in (1, 2) else text.replace(",", "")
            )
        try:
            number = Decimal(text)
        except InvalidOperation as exc:
            raise ItemRejectedError(spec.name, "invalid_number") from exc
    if not number.is_finite() or abs(number) > _MAX_DECIMAL:
        raise ItemRejectedError(spec.name, "invalid_number")
    if number.as_tuple().exponent < -18:  # type: ignore[operator]
        # At most 18 fractional digits are kept (like NUMERIC(38, 18)): "1e-999999"
        # must not become a million-character string that later overflows.
        with localcontext() as context:
            context.prec = 40
            number = number.quantize(_FRACTION_DIGITS)
    return number


def _normalize_integer(spec: FieldSpec, value: Any) -> int:
    number = _parse_decimal(spec, value)
    if number != number.to_integral_value() or abs(number) > _MAX_SAFE_INTEGER:
        raise ItemRejectedError(spec.name, "invalid_integer")
    return int(number)


def _normalize_decimal(spec: FieldSpec, value: Any) -> str:
    # Stored as a canonical string to preserve precision (no binary floats).
    number = _parse_decimal(spec, value).normalize()
    return format(number, "f")


def _normalize_boolean(spec: FieldSpec, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    token = str(value).strip().lower()
    if token in _TRUE:
        return True
    if token in _FALSE:
        return False
    raise ItemRejectedError(spec.name, "invalid_boolean")


def _normalize_datetime(spec: FieldSpec, value: Any) -> str:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            parsed = datetime.fromtimestamp(float(value), tz=UTC)
        else:
            parsed = datetime.fromisoformat(str(value).strip())  # accepts "Z" since 3.11
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise ItemRejectedError(spec.name, "invalid_datetime") from exc
    return parsed.astimezone(UTC).isoformat()


def _normalize_url(spec: FieldSpec, value: Any) -> str:
    text = _normalize_string(spec, value, multiline=False)
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise ItemRejectedError(spec.name, "invalid_url") from exc
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.username:
        raise ItemRejectedError(spec.name, "invalid_url")
    netloc = parts.hostname.lower() + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def _normalize_enum(spec: FieldSpec, value: Any) -> str:
    text = _normalize_string(spec, value, multiline=False).lower()
    for allowed in spec.enum_values or []:
        if allowed.lower() == text:
            return allowed
    raise ItemRejectedError(spec.name, "invalid_enum")


def normalize_value(spec: FieldSpec, value: Any) -> JSONValue:
    match spec.type:
        case FieldType.STRING:
            return _normalize_string(spec, value, multiline=False)
        case FieldType.TEXT:
            return _normalize_string(spec, value, multiline=True)
        case FieldType.INTEGER:
            return _normalize_integer(spec, value)
        case FieldType.DECIMAL:
            return _normalize_decimal(spec, value)
        case FieldType.BOOLEAN:
            return _normalize_boolean(spec, value)
        case FieldType.DATETIME:
            return _normalize_datetime(spec, value)
        case FieldType.URL:
            return _normalize_url(spec, value)
        case FieldType.ENUM:
            return _normalize_enum(spec, value)


def _is_blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


# ------------------------------------------------------------------ stages


def validate(schema: DatasetSchema, raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate: an object with every required field; undeclared fields are dropped."""
    if not isinstance(raw, Mapping):
        raise ItemRejectedError(None, "not_an_object")
    selected: dict[str, Any] = {}
    for spec in schema.fields:
        value = raw.get(spec.name)
        if _is_blank(value):
            if spec.required:
                raise ItemRejectedError(spec.name, "missing_required")
            continue
        selected[spec.name] = value
    if schema.key_field not in selected:
        raise ItemRejectedError(schema.key_field, "missing_key")
    return selected


def normalize(schema: DatasetSchema, item: Mapping[str, Any]) -> dict[str, JSONValue]:
    """Normalize: every value in its declared type and canonical form."""
    return {
        spec.name: normalize_value(spec, item[spec.name])
        for spec in schema.fields
        if spec.name in item
    }


def clean(schema: DatasetSchema, record: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Clean: drop values that normalised to nothing and tracking noise in URLs."""
    cleaned: dict[str, JSONValue] = {}
    for spec in schema.fields:
        if spec.name not in record:
            continue
        value = record[spec.name]
        if value == "":  # e.g. only invisible characters
            if spec.required:
                code = "missing_key" if spec.name == schema.key_field else "missing_required"
                raise ItemRejectedError(spec.name, code)
            continue
        if spec.type is FieldType.URL and isinstance(value, str):
            value = without_tracking_parameters(value)
        cleaned[spec.name] = value
    return cleaned


def without_tracking_parameters(url: str) -> str:
    """Remove utm_* and click identifiers; every other parameter is kept byte for byte."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [segment for segment in parts.query.split("&") if segment and not _tracking(segment)]
    return urlunsplit(parts._replace(query="&".join(kept)))


def _tracking(segment: str) -> bool:
    name = unquote_plus(segment.partition("=")[0]).strip().lower()
    return name.startswith("utm_") or name in _TRACKING_PARAMS


def deduplicate(
    records: Iterable[tuple[str, dict[str, JSONValue]]],
) -> tuple[dict[str, dict[str, JSONValue]], int]:
    """Deduplicate: one record per key, the last occurrence wins; returns (unique, dropped)."""
    unique: dict[str, dict[str, JSONValue]] = {}
    dropped = 0
    for key, data in records:
        if key in unique:
            dropped += 1
        unique[key] = data
    return unique, dropped


def enrich(key: str, data: dict[str, JSONValue]) -> CleanRecord:
    """Enrich: canonical key and content fingerprint for change detection."""
    return CleanRecord(key=key[:512], data=data, content_hash=content_hash(data))


def prepare_item(schema: DatasetSchema, raw: Mapping[str, Any]) -> dict[str, JSONValue]:
    """Validate, normalize and clean one item; raises :class:`ItemRejectedError`."""
    return clean(schema, normalize(schema, validate(schema, raw)))


def run_pipeline(
    schema: DatasetSchema, items: Iterable[Mapping[str, Any]], *, max_items: int
) -> PipelineResult:
    result = PipelineResult()
    prepared: list[tuple[str, dict[str, JSONValue]]] = []
    for index, raw in enumerate(items):
        if index >= max_items:
            result.truncated = True
            break
        result.received += 1
        try:
            record = prepare_item(schema, raw)
        except ItemRejectedError as rejection:
            result.invalid += 1
            if len(result.issues) < MAX_ISSUES:
                result.issues.append(ItemIssue(index, rejection.field, rejection.code))
            continue
        prepared.append((str(record[schema.key_field]), record))
    unique, result.duplicates = deduplicate(prepared)
    result.valid = len(unique)
    result.records = [enrich(key, data) for key, data in unique.items()]
    return result
