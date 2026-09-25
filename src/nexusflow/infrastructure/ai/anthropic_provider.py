"""Anthropic Claude implementation of the :class:`AIProvider` port.

* Structured output: ``output_config.format`` with the strict analysis JSON
  schema; tools are declared ``strict`` so arguments are schema-valid.
* Refusals: server-side ``fallbacks="default"`` (opt-in, configurable) re-runs a
  declined request on Anthropic's recommended fallback model; a final
  ``stop_reason == "refusal"`` is surfaced as a permanent refusal.
* Errors are classified: 429/5xx/timeouts/connection -> transient (retried by
  the job with backoff); 4xx -> permanent. A circuit breaker stops hammering an
  unavailable API.
* Full assistant content blocks are appended to the history on tool turns, as
  the API requires.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any, cast

import anthropic

from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.core.resilience import CircuitBreaker
from nexusflow.domain.intelligence.ports import (
    AIRequestError,
    AIUnavailableError,
    AnalysisRequest,
    ModelTurn,
    ToolCall,
    ToolResult,
)
from nexusflow.infrastructure.observability import metrics

_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicConversation:
    def __init__(self, provider: AnthropicProvider, request: AnalysisRequest) -> None:
        self._provider = provider
        self._request = request
        self._messages: list[dict[str, Any]] = [{"role": "user", "content": request.user_prompt}]
        self._last_content: Any = None

    async def send(self, tool_results: Sequence[ToolResult] = ()) -> ModelTurn:
        if tool_results:
            self._messages.append({"role": "assistant", "content": self._last_content})
            self._messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": result.call_id,
                            "content": result.content,
                            "is_error": result.is_error,
                        }
                        for result in tool_results
                    ],
                }
            )
        response = await self._provider.call(self._request, self._messages)
        self._last_content = response.content
        text_parts = [block.text for block in response.content if block.type == "text"]
        calls = tuple(
            ToolCall(id=block.id, name=block.name, arguments=dict(block.input or {}))
            for block in response.content
            if block.type == "tool_use"
        )
        usage = response.usage
        return ModelTurn(
            text="".join(text_parts) or None,
            tool_calls=calls,
            stop_reason=str(response.stop_reason or "end_turn"),
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        )


class AnthropicProvider:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_retries: int,
        effort: str | None,
        server_side_fallbacks: bool,
        breaker: CircuitBreaker,
        client: anthropic.AsyncAnthropic | None = None,
    ) -> None:
        self._client = client or anthropic.AsyncAnthropic(
            api_key=api_key,
            timeout=anthropic.Timeout(timeout_seconds, connect=10.0),
            max_retries=max_retries,
        )
        self._model = model
        self._effort = effort
        self._fallbacks = server_side_fallbacks
        self._breaker = breaker

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def model(self) -> str:
        return self._model

    def start(self, request: AnalysisRequest) -> AnthropicConversation:
        return AnthropicConversation(self, request)

    async def call(self, request: AnalysisRequest, messages: list[dict[str, Any]]) -> Any:
        try:
            self._breaker.before_call()
        except ServiceUnavailableError as exc:
            # Fail fast, but as a transient failure: the analysis job retries with
            # backoff once the circuit half-opens instead of being dead-lettered.
            raise AIUnavailableError(code="ai_circuit_open", internal_detail=str(exc)) from exc
        output_config: dict[str, Any] = {
            "format": {"type": "json_schema", "schema": request.output_schema}
        }
        if self._effort:
            output_config["effort"] = self._effort
        params: dict[str, Any] = {
            "model": self._model,
            "max_tokens": request.max_output_tokens,
            "system": request.system_prompt,
            "messages": messages,
            "output_config": output_config,
        }
        if request.tools:
            params["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                    "strict": True,
                }
                for tool in request.tools
            ]
        if self._fallbacks:
            params["betas"] = [_FALLBACK_BETA]
            params["fallbacks"] = "default"
        started = time.perf_counter()
        try:
            response = await cast(Any, self._client.beta.messages).create(**params)
        except (
            anthropic.RateLimitError,
            anthropic.APIConnectionError,
            anthropic.APITimeoutError,
        ) as exc:
            self._record_failure("transient")
            raise AIUnavailableError(internal_detail=type(exc).__name__) from exc
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500:
                self._record_failure("transient")
                raise AIUnavailableError(internal_detail=f"HTTP {exc.status_code}") from exc
            metrics.AI_REQUESTS.labels(provider="anthropic", result="rejected").inc()
            raise AIRequestError(internal_detail=f"HTTP {exc.status_code}") from exc
        self._breaker.record_success()
        metrics.CIRCUIT_STATE.labels(dependency="anthropic").set(0)
        metrics.AI_LATENCY.labels(provider="anthropic").observe(time.perf_counter() - started)
        metrics.AI_REQUESTS.labels(provider="anthropic", result=str(response.stop_reason)).inc()
        usage = response.usage
        metrics.AI_TOKENS.labels(provider="anthropic", direction="input").inc(
            int(usage.input_tokens or 0)
        )
        metrics.AI_TOKENS.labels(provider="anthropic", direction="output").inc(
            int(usage.output_tokens or 0)
        )
        return response

    def _record_failure(self, result: str) -> None:
        self._breaker.record_failure()
        metrics.AI_REQUESTS.labels(provider="anthropic", result=result).inc()
        metrics.CIRCUIT_STATE.labels(dependency="anthropic").set(1 if self._breaker.is_open else 0)

    async def aclose(self) -> None:
        await self._client.close()
