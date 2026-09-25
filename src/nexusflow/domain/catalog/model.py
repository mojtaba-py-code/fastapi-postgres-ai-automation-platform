"""Projects, datasets and their typed schemas.

A *dataset* declares the shape of the records it holds (fields, types, key
field), how changes are scored, and how sensitive the data is. The schema is
enforced by the ingestion pipeline, so malformed or unexpected data never
reaches storage, analysis or reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

FIELD_NAME = r"^[a-z][a-z0-9_]{0,62}$"
RESERVED_FIELDS = frozenset({"id", "org_id", "record_key", "_source", "_run"})


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class FieldType(StrEnum):
    STRING = "string"
    TEXT = "text"
    INTEGER = "integer"
    DECIMAL = "decimal"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    URL = "url"
    ENUM = "enum"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def leaves_platform(self) -> bool:
        """Whether record values may be sent to third parties (an external AI
        provider, alert channels). Restricted data never leaves the platform."""
        return self is not DataClassification.RESTRICTED


_NUMERIC = frozenset({FieldType.INTEGER, FieldType.DECIMAL})
_KEY_TYPES = frozenset({FieldType.STRING, FieldType.INTEGER, FieldType.URL})


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class FieldSpec(_Strict):
    name: str = Field(pattern=FIELD_NAME)
    type: FieldType
    required: bool = False
    max_length: int | None = Field(default=None, ge=1, le=100_000)
    enum_values: list[str] | None = Field(default=None, max_length=100)
    sensitive: bool = False
    description: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.name in RESERVED_FIELDS:
            raise ValueError(f"field name {self.name!r} is reserved")
        if self.type is FieldType.ENUM and not self.enum_values:
            raise ValueError("enum fields need enum_values")
        if self.type is not FieldType.ENUM and self.enum_values is not None:
            raise ValueError("enum_values is only valid for enum fields")
        return self

    @property
    def effective_max_length(self) -> int:
        if self.max_length is not None:
            return self.max_length
        return (
            10_000 if self.type is FieldType.TEXT else 2048 if self.type is FieldType.URL else 500
        )


class NumericThreshold(_Strict):
    medium_pct: float = Field(default=5.0, gt=0, le=10_000)
    high_pct: float = Field(default=20.0, gt=0, le=10_000)
    critical_pct: float = Field(default=50.0, gt=0, le=10_000)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if not self.medium_pct <= self.high_pct <= self.critical_pct:
            raise ValueError("thresholds must satisfy medium <= high <= critical")
        return self


class ChangePolicy(_Strict):
    tracked_fields: list[str] | None = Field(default=None, max_length=100)
    ignored_fields: list[str] = Field(default_factory=list, max_length=100)
    numeric_thresholds: dict[str, NumericThreshold] = Field(default_factory=dict, max_length=50)


class DatasetSchema(_Strict):
    fields: list[FieldSpec] = Field(min_length=1, max_length=100)
    key_field: str = Field(pattern=FIELD_NAME)
    change_policy: ChangePolicy = Field(default_factory=ChangePolicy)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        names = [f.name for f in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("field names must be unique")
        by_name = {f.name: f for f in self.fields}
        key = by_name.get(self.key_field)
        if key is None:
            raise ValueError("key_field must be one of the fields")
        if key.type not in _KEY_TYPES or not key.required:
            raise ValueError("key_field must be a required string, integer or url field")
        if key.sensitive:
            # Record keys identify records everywhere - alerts, reports, the changes
            # API, AI analysis - so they cannot be masked like other sensitive fields.
            raise ValueError(
                "key_field cannot be sensitive: key the dataset on a non-personal identifier"
            )
        policy = self.change_policy
        for name in [*(policy.tracked_fields or []), *policy.ignored_fields]:
            if name not in by_name:
                raise ValueError(f"change policy references unknown field {name!r}")
        for name in policy.numeric_thresholds:
            if by_name.get(name) is None or by_name[name].type not in _NUMERIC:
                raise ValueError(f"numeric threshold on non-numeric field {name!r}")
        return self

    def field(self, name: str) -> FieldSpec | None:
        return next((f for f in self.fields if f.name == name), None)

    @property
    def sensitive_fields(self) -> frozenset[str]:
        return frozenset(f.name for f in self.fields if f.sensitive)

    @property
    def tracked_fields(self) -> frozenset[str]:
        policy = self.change_policy
        if policy.tracked_fields is not None:  # an explicit allowlist, even an empty one
            candidates = policy.tracked_fields
        else:
            candidates = [f.name for f in self.fields if f.name != self.key_field]
        return frozenset(candidates) - frozenset(policy.ignored_fields)


@dataclass(eq=False, kw_only=True)
class Project:
    id: UUID
    org_id: UUID
    name: str
    description: str | None = None
    status: ProjectStatus = ProjectStatus.ACTIVE
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime


@dataclass(eq=False, kw_only=True)
class Dataset:
    id: UUID
    org_id: UUID
    project_id: UUID
    name: str
    description: str | None = None
    schema: dict[str, Any] = field(default_factory=dict)
    classification: DataClassification = DataClassification.INTERNAL
    retention_days: int = 180
    created_by: UUID | None = None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None

    @property
    def spec(self) -> DatasetSchema:
        return DatasetSchema.model_validate(self.schema)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None
