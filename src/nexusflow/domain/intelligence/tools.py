"""Explicit tool-permission layer between the model and the platform.

    user input -> validation -> policy -> AI -> **tool permission check** -> tool

* only tools registered here exist - all of them read-only;
* every call is checked against the tool allowlist, its argument schema
  (unknown arguments rejected), the acting principal's permissions and a
  per-analysis call budget;
* tools are scoped to the analysed organization and dataset - the model cannot
  name another tenant or dataset, because those ids are not parameters;
* results are redacted and size-limited before they reach the model.
The model can never execute commands, fetch URLs or write data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from nexusflow.core.clock import Clock
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission
from nexusflow.domain.catalog.service import get_dataset
from nexusflow.domain.intelligence.ports import ToolCall, ToolResult, ToolSpec
from nexusflow.domain.intelligence.redaction import redact_value, strip_sensitive
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWorkFactory


@dataclass(frozen=True, slots=True)
class ToolContext:
    org_id: UUID
    dataset_id: UUID
    principal: Principal


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RecordHistoryArgs(_Args):
    record_key: str = Field(min_length=1, max_length=512)


class NoArgs(_Args):
    pass


class AnalysisTool(Protocol):
    spec: ToolSpec
    permission: Permission
    args_model: type[_Args]

    async def run(self, args: Any, ctx: ToolContext) -> Any: ...


class RecordHistoryTool:
    permission: Permission = Permission.RECORDS_READ
    args_model: type[_Args] = RecordHistoryArgs
    spec: ToolSpec

    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory
        self.spec = ToolSpec(
            name="get_record_history",
            description="Return the last versions of one record of the analysed dataset.",
            input_schema={
                "type": "object",
                "properties": {"record_key": {"type": "string", "maxLength": 512}},
                "required": ["record_key"],
                "additionalProperties": False,
            },
        )

    async def run(self, args: RecordHistoryArgs, ctx: ToolContext) -> Any:
        async with self._uow_factory(TenantScope.system(ctx.org_id)) as uow:
            dataset = await get_dataset(uow, ctx.org_id, ctx.dataset_id)
            record = await uow.data.records.get_by_key(ctx.org_id, ctx.dataset_id, args.record_key)
            if record is None:
                return {"found": False}
            versions = await uow.data.records.history(ctx.org_id, record.id, limit=5)
        sensitive = dataset.spec.sensitive_fields
        history = [
            {
                "version": v.version,
                "captured_at": v.captured_at.isoformat(),
                "deleted": v.is_deletion,
                "data": redact_value(strip_sensitive(v.data, sensitive))[0],
            }
            for v in versions
        ]
        return {"found": True, "record_key": record.record_key, "versions": history}


class DatasetOverviewTool:
    permission: Permission = Permission.DATASETS_READ
    args_model: type[_Args] = NoArgs
    spec: ToolSpec

    def __init__(self, uow_factory: UnitOfWorkFactory, clock: Clock) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self.spec = ToolSpec(
            name="get_dataset_overview",
            description="Return the analysed dataset's schema and recent change statistics.",
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        )

    async def run(self, args: NoArgs, ctx: ToolContext) -> Any:
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(ctx.org_id)) as uow:
            dataset = await get_dataset(uow, ctx.org_id, ctx.dataset_id)
            volume = await uow.data.changes.volume(
                ctx.org_id, dataset_ids=[ctx.dataset_id], start=now - timedelta(days=7), end=now
            )
        by_significance: dict[str, int] = {}
        for row in volume:
            by_significance[row.significance.value] = (
                by_significance.get(row.significance.value, 0) + row.count
            )
        return {
            "dataset": dataset.name,
            "fields": [
                {"name": f.name, "type": f.type.value}
                for f in dataset.spec.fields
                if not f.sensitive
            ],
            "changes_last_7_days": sum(row.count for row in volume),
            "by_significance": by_significance,
        }


@dataclass
class ToolGateway:
    tools: dict[str, AnalysisTool]
    max_calls: int = 5
    max_result_chars: int = 6000
    calls: int = 0
    decisions: list[tuple[str, str]] = field(default_factory=list)

    @property
    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(tool.spec for tool in self.tools.values())

    async def execute(self, call: ToolCall, ctx: ToolContext) -> ToolResult:
        tool = self.tools.get(call.name)
        if tool is None:
            return self._deny(call, "unknown_tool", "This tool is not available.")
        if self.calls >= self.max_calls:
            return self._deny(call, "budget_exhausted", "Tool call budget exhausted.")
        if not ctx.principal.has(tool.permission):
            return self._deny(call, "permission_denied", "Not permitted.")
        try:
            args = tool.args_model.model_validate(call.arguments)
        except ValidationError:
            return self._deny(call, "invalid_arguments", "Invalid tool arguments.")
        self.calls += 1
        try:
            result = await tool.run(args, ctx)
        except Exception:  # noqa: BLE001 - tool failures must not crash the analysis
            return self._deny(call, "tool_error", "The tool failed.")
        encoded = json.dumps(result, ensure_ascii=False, default=str)
        if len(encoded) > self.max_result_chars:
            encoded = encoded[: self.max_result_chars] + '..."[truncated]"'
        self.decisions.append((call.name, "allowed"))
        return ToolResult(call_id=call.id, content=encoded)

    def _deny(self, call: ToolCall, decision: str, message: str) -> ToolResult:
        self.decisions.append((call.name[:64], decision))
        return ToolResult(call_id=call.id, content=json.dumps({"error": message}), is_error=True)
