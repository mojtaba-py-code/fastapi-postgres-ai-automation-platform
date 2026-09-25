"""Provider-agnostic AI contract.

Business logic talks to :class:`AIProvider` only; swapping Anthropic for
another vendor (or a self-hosted model) means adding an implementation in
``infrastructure/ai`` - nothing in the domain changes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from nexusflow.core.errors import PermanentError, TransientError


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True, slots=True)
class ModelTurn:
    text: str | None
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: str = "end_turn"
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    system_prompt: str
    user_prompt: str
    output_schema: dict[str, Any]
    tools: tuple[ToolSpec, ...] = field(default_factory=tuple)
    max_output_tokens: int = 8000


class AIConversation(Protocol):
    async def send(self, tool_results: Sequence[ToolResult] = ()) -> ModelTurn: ...


class AIProvider(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    def start(self, request: AnalysisRequest) -> AIConversation: ...


class AIUnavailableError(TransientError):
    default_code = "ai_unavailable"
    default_message = "The AI provider is temporarily unavailable."


class AIRequestError(PermanentError):
    default_code = "ai_request_rejected"
    default_message = "The AI provider rejected the request."


class AIRefusalError(PermanentError):
    default_code = "ai_refused"
    default_message = "The AI provider declined to answer."
