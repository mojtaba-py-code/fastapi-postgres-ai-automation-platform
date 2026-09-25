"""Data sources and collection runs.

Each source kind has a strictly validated configuration model. Anything that
reaches the network layer (URLs, headers, query strings) is constrained here
first, and URLs are additionally checked against the SSRF policy by the
service before a configuration is accepted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from nexusflow.core.jsonutil import JSONObject

FIELD_NAME = r"^[a-z][a-z0-9_]{0,62}$"
# Share of the previously live records one full snapshot may delete. A snapshot
# that suddenly lacks most records (broken page, layout change, hostile source)
# must not wipe the dataset; set 1.0 on a source to allow any deletion.
DEFAULT_MAX_DELETION_RATIO = 0.5
JSON_PATH = re.compile(r"^[A-Za-z0-9_\-]{1,64}(\.[A-Za-z0-9_\-]{1,64}|\[\d{1,4}\]){0,10}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_HEADER_VALUE = re.compile(r"^[\x20-\x7e]{0,1000}$")
_ATTRIBUTE = re.compile(r"^[a-z][a-z0-9_:-]{0,40}$")
FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "cookie",
        "authorization",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "expect",
        "keep-alive",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    }
)


class SourceKind(StrEnum):
    WEBSITE = "website"
    REST_API = "rest_api"
    WEBHOOK = "webhook"
    FILE_UPLOAD = "file_upload"


class SourceStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    QUARANTINED = "quarantined"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _check_path(value: str) -> str:
    if not JSON_PATH.fullmatch(value):
        raise ValueError("invalid path (use dot notation like data.items or items[0].price)")
    return value


def _check_mapping(mapping: dict[str, str]) -> dict[str, str]:
    for target, path in mapping.items():
        if not re.fullmatch(FIELD_NAME, target):
            raise ValueError(f"invalid dataset field name {target!r}")
        _check_path(path)
    return mapping


class FieldExtraction(_Strict):
    selector: str = Field(min_length=1, max_length=300)
    attribute: str | None = Field(default=None, max_length=41)

    @field_validator("attribute")
    @classmethod
    def _attribute(cls, value: str | None) -> str | None:
        if value is not None and not _ATTRIBUTE.fullmatch(value):
            raise ValueError("invalid attribute name")
        return value


class WebsiteConfig(_Strict):
    kind: Literal[SourceKind.WEBSITE] = SourceKind.WEBSITE
    url: str = Field(min_length=10, max_length=2048)
    item_selector: str = Field(min_length=1, max_length=300)
    fields: dict[str, FieldExtraction] = Field(min_length=1, max_length=50)
    render_javascript: bool = False
    snapshot_mode: Literal["full", "incremental"] = "full"
    max_deletion_ratio: float = Field(default=DEFAULT_MAX_DELETION_RATIO, ge=0.0, le=1.0)
    max_items: int = Field(default=500, ge=1, le=10_000)

    @field_validator("fields")
    @classmethod
    def _names(cls, value: dict[str, FieldExtraction]) -> dict[str, FieldExtraction]:
        for name in value:
            if not re.fullmatch(FIELD_NAME, name):
                raise ValueError(f"invalid field name {name!r}")
        return value


class PageParamPagination(_Strict):
    type: Literal["page_param"] = "page_param"
    param: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    start: int = Field(default=1, ge=0, le=1_000_000)
    max_pages: int = Field(default=5, ge=1, le=50)


class CursorPagination(_Strict):
    type: Literal["cursor"] = "cursor"
    cursor_path: str = Field(max_length=200)
    cursor_param: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    max_pages: int = Field(default=5, ge=1, le=50)

    @field_validator("cursor_path")
    @classmethod
    def _cursor_path(cls, value: str) -> str:
        return _check_path(value)


class RestApiConfig(_Strict):
    kind: Literal[SourceKind.REST_API] = SourceKind.REST_API
    url: str = Field(min_length=10, max_length=2048)
    method: Literal["GET", "POST"] = "GET"
    query: dict[str, str] = Field(default_factory=dict, max_length=20)
    headers: dict[str, str] = Field(default_factory=dict, max_length=20)
    body: JSONObject | None = None
    items_path: str | None = Field(default=None, max_length=200)
    field_mapping: dict[str, str] = Field(min_length=1, max_length=100)
    pagination: Annotated[
        PageParamPagination | CursorPagination | None, Field(discriminator="type")
    ] = None
    snapshot_mode: Literal["full", "incremental"] = "full"
    max_deletion_ratio: float = Field(default=DEFAULT_MAX_DELETION_RATIO, ge=0.0, le=1.0)
    max_items: int = Field(default=1000, ge=1, le=50_000)

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, str]) -> dict[str, str]:
        for name, header_value in value.items():
            if not _HEADER_NAME.fullmatch(name) or name.lower() in FORBIDDEN_HEADERS:
                raise ValueError(f"header {name!r} is not allowed (use an integration for auth)")
            if not _HEADER_VALUE.fullmatch(header_value):
                raise ValueError(f"header {name!r} has an invalid value")
        return value

    @field_validator("query")
    @classmethod
    def _query(cls, value: dict[str, str]) -> dict[str, str]:
        for name, param in value.items():
            if not re.fullmatch(r"^[A-Za-z0-9_.\-\[\]]{1,64}$", name) or len(param) > 500:
                raise ValueError(f"query parameter {name!r} is invalid")
        return value

    @field_validator("items_path")
    @classmethod
    def _items_path(cls, value: str | None) -> str | None:
        return _check_path(value) if value is not None else None

    @field_validator("field_mapping")
    @classmethod
    def _mapping(cls, value: dict[str, str]) -> dict[str, str]:
        return _check_mapping(value)

    @model_validator(mode="after")
    def _body_only_for_post(self) -> Self:
        if self.body is not None and self.method != "POST":
            raise ValueError("a request body is only allowed for POST")
        return self


class WebhookConfig(_Strict):
    kind: Literal[SourceKind.WEBHOOK] = SourceKind.WEBHOOK
    items_path: str | None = Field(default=None, max_length=200)
    field_mapping: dict[str, str] = Field(min_length=1, max_length=100)
    max_items: int = Field(default=1000, ge=1, le=10_000)

    @field_validator("items_path")
    @classmethod
    def _items_path(cls, value: str | None) -> str | None:
        return _check_path(value) if value is not None else None

    @field_validator("field_mapping")
    @classmethod
    def _mapping(cls, value: dict[str, str]) -> dict[str, str]:
        return _check_mapping(value)


class FileUploadConfig(_Strict):
    kind: Literal[SourceKind.FILE_UPLOAD] = SourceKind.FILE_UPLOAD
    format: Literal["csv", "xlsx"]
    column_mapping: dict[str, str] = Field(min_length=1, max_length=200)
    delimiter: Literal[",", ";", "\t", "|"] = ","
    sheet_name: str | None = Field(default=None, max_length=31)
    snapshot_mode: Literal["full", "incremental"] = "full"
    max_deletion_ratio: float = Field(default=DEFAULT_MAX_DELETION_RATIO, ge=0.0, le=1.0)

    @field_validator("column_mapping")
    @classmethod
    def _columns(cls, value: dict[str, str]) -> dict[str, str]:
        for target, column in value.items():
            if not re.fullmatch(FIELD_NAME, target) or not 0 < len(column) <= 200:
                raise ValueError(f"invalid column mapping for {target!r}")
        return value


SourceConfig = Annotated[
    WebsiteConfig | RestApiConfig | WebhookConfig | FileUploadConfig, Field(discriminator="kind")
]
SOURCE_CONFIG_ADAPTER: TypeAdapter[
    WebsiteConfig | RestApiConfig | WebhookConfig | FileUploadConfig
] = TypeAdapter(SourceConfig)

type AnySourceConfig = WebsiteConfig | RestApiConfig | WebhookConfig | FileUploadConfig


def mapped_fields(config: AnySourceConfig) -> set[str]:
    if isinstance(config, WebsiteConfig):
        return set(config.fields)
    if isinstance(config, FileUploadConfig):
        return set(config.column_mapping)
    return set(config.field_mapping)


@dataclass(eq=False, kw_only=True)
class Source:
    id: UUID
    org_id: UUID
    project_id: UUID
    dataset_id: UUID
    name: str
    kind: SourceKind
    config: dict[str, Any] = field(default_factory=dict)
    integration_id: UUID | None = None
    status: SourceStatus = SourceStatus.ACTIVE
    consecutive_failures: int = 0
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime

    @property
    def parsed_config(self) -> AnySourceConfig:
        return SOURCE_CONFIG_ADAPTER.validate_python(self.config)

    @property
    def is_runnable(self) -> bool:
        return self.status in (SourceStatus.ACTIVE, SourceStatus.ERROR)

    def record_success(self, now: datetime) -> None:
        self.consecutive_failures = 0
        self.last_run_at = now
        self.last_success_at = now
        if self.status is SourceStatus.ERROR:
            self.status = SourceStatus.ACTIVE
        self.updated_at = now

    def record_failure(self, now: datetime, *, error_threshold: int = 5) -> None:
        self.consecutive_failures += 1
        self.last_run_at = now
        if self.consecutive_failures >= error_threshold and self.status is SourceStatus.ACTIVE:
            self.status = SourceStatus.ERROR
        self.updated_at = now


class RunTrigger(StrEnum):
    MANUAL = "manual"
    SCHEDULE = "schedule"
    WEBHOOK = "webhook"
    UPLOAD = "upload"
    AUTOMATION = "automation"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_RUN_STATUSES = frozenset({RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.CANCELLED})


@dataclass(eq=False, kw_only=True)
class CollectionRun:
    id: UUID
    org_id: UUID
    source_id: UUID
    trigger: RunTrigger
    status: RunStatus = RunStatus.QUEUED
    workflow_run_id: UUID | None = None
    idempotency_key: str | None = None
    attempt: int = 0
    stats: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_detail: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_RUN_STATUSES

    def start(self, now: datetime) -> bool:
        """QUEUED -> RUNNING. Returns False if another worker already owns the run."""
        if self.status is not RunStatus.QUEUED:
            return False
        self.status = RunStatus.RUNNING
        self.started_at = now
        self.attempt += 1
        return True

    def succeed(self, now: datetime, stats: dict[str, Any]) -> None:
        self.status = RunStatus.SUCCEEDED
        self.stats = stats
        self.finished_at = now
        self.error_code = None
        self.error_detail = None

    def fail(self, now: datetime, *, code: str, detail: str | None = None) -> None:
        self.status = RunStatus.FAILED
        self.error_code = code[:64]
        self.error_detail = detail[:500] if detail else None
        self.finished_at = now

    def cancel(self, now: datetime, *, code: str) -> None:
        """Stop a run for a reason that is not the source's fault (e.g. a freeze)."""
        self.status = RunStatus.CANCELLED
        self.error_code = code[:64]
        self.finished_at = now

    def requeue(self) -> None:
        """Allow a retry of a RUNNING run whose worker died (reaper)."""
        if self.status is RunStatus.RUNNING:
            self.status = RunStatus.QUEUED
