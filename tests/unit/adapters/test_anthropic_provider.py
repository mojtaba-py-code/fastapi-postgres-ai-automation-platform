"""Anthropic implementation of the AI port (``infrastructure.ai.anthropic_provider``).

The provider is built with a fake ``client`` exposing ``beta.messages.create``;
responses are real SDK ``BetaMessage`` objects and failures are real
``anthropic`` exception instances (built on ``httpx2`` requests/responses).
Covers the exact request parameters, the tool-turn history, mapping responses
to ``ModelTurn``, error classification, metrics and the circuit breaker.
"""

from __future__ import annotations

import contextlib
import copy
from types import SimpleNamespace
from typing import Any, cast

import anthropic
import httpx2
import pytest
from anthropic.types.beta import BetaMessage
from prometheus_client import REGISTRY

from nexusflow.core.errors import (
    PermanentError,
    TransientError,
)
from nexusflow.core.resilience import CircuitBreaker, CircuitState
from nexusflow.domain.intelligence.ports import (
    AIRequestError,
    AIUnavailableError,
    AnalysisRequest,
    ModelTurn,
    ToolCall,
    ToolResult,
    ToolSpec,
)
from nexusflow.infrastructure.ai.anthropic_provider import AnthropicProvider

MODEL = "claude-opus-5"
API_KEY = "sk-ant-test-" + "k" * 40
FALLBACK_BETA = "server-side-fallback-2026-07-01"
OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"summary": {"type": "string"}, "risk": {"type": "integer"}},
    "required": ["summary", "risk"],
    "additionalProperties": False,
}
HISTORY_TOOL = ToolSpec(
    name="get_record_history",
    description="Version history of one record.",
    input_schema={
        "type": "object",
        "properties": {"record_key": {"type": "string"}},
        "required": ["record_key"],
        "additionalProperties": False,
    },
)
OVERVIEW_TOOL = ToolSpec(
    name="get_dataset_overview",
    description="Aggregate statistics of the dataset.",
    input_schema={"type": "object", "properties": {}, "additionalProperties": False},
)
REQUEST = AnalysisRequest(
    system_prompt="You are a careful pricing analyst.",
    user_prompt="Analyse the changes between <data> markers.",
    output_schema=OUTPUT_SCHEMA,
    tools=(HISTORY_TOOL, OVERVIEW_TOOL),
    max_output_tokens=4_096,
)
PLAIN_REQUEST = AnalysisRequest(
    system_prompt="You are a careful pricing analyst.",
    user_prompt="Summarise.",
    output_schema=OUTPUT_SCHEMA,
)
API_REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def _message(
    *content: dict[str, Any],
    stop_reason: str | None = "end_turn",
    input_tokens: int = 1_200,
    output_tokens: int = 300,
) -> BetaMessage:
    return BetaMessage.model_validate(
        {
            "id": "msg_01TestTestTestTestTest",
            "type": "message",
            "role": "assistant",
            "model": MODEL,
            "content": list(content),
            "stop_reason": stop_reason,
            "stop_sequence": None,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        }
    )


def _text(text: str) -> dict[str, Any]:
    return {"type": "text", "text": text}


def _tool_use(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"type": "tool_use", "id": call_id, "name": name, "input": arguments}


ANSWER = _message(_text('{"summary": "Prices fell.", "risk": 2}'))


def _status_error(
    error: type[anthropic.APIStatusError], status: int, kind: str = "api_error"
) -> anthropic.APIStatusError:
    body = {"type": "error", "error": {"type": kind, "message": "simulated"}}
    response = httpx2.Response(status, request=API_REQUEST, json=body)
    return error("simulated", response=response, body=body)


class FakeBetaMessages:
    def __init__(self, outcomes: list[BetaMessage | BaseException]) -> None:
        self._outcomes = outcomes
        self.calls: list[dict[str, Any]] = []

    async def create(self, **params: Any) -> BetaMessage:
        # Snapshot: the provider keeps appending to the same history list.
        self.calls.append(copy.deepcopy(params))
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class FakeAnthropic:
    """Just enough of ``anthropic.AsyncAnthropic`` for the provider."""

    def __init__(self, *outcomes: BetaMessage | BaseException) -> None:
        self.messages = FakeBetaMessages(list(outcomes))
        self.beta = SimpleNamespace(messages=self.messages)
        self.closed = False

    async def close(self) -> None:
        self.closed = True


def _provider(
    client: FakeAnthropic,
    *,
    effort: str | None = None,
    fallbacks: bool = False,
    breaker: CircuitBreaker | None = None,
) -> AnthropicProvider:
    return AnthropicProvider(
        api_key=API_KEY,
        model=MODEL,
        timeout_seconds=60.0,
        max_retries=0,
        effort=effort,
        server_side_fallbacks=fallbacks,
        breaker=breaker or CircuitBreaker("anthropic", failure_threshold=3, reset_timeout=60.0),
        client=cast(anthropic.AsyncAnthropic, client),
    )


def _sample(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _circuit_gauge() -> float | None:
    return REGISTRY.get_sample_value("nexusflow_circuit_breaker_open", {"dependency": "anthropic"})


class TestRequestParameters:
    async def test_the_request_carries_model_limits_prompts_schema_and_strict_tools(self) -> None:
        client = FakeAnthropic(ANSWER)

        await _provider(client).start(REQUEST).send()

        assert client.messages.calls == [
            {
                "model": MODEL,
                "max_tokens": 4_096,
                "system": "You are a careful pricing analyst.",
                "messages": [
                    {"role": "user", "content": "Analyse the changes between <data> markers."}
                ],
                "output_config": {"format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
                "tools": [
                    {
                        "name": "get_record_history",
                        "description": "Version history of one record.",
                        "input_schema": HISTORY_TOOL.input_schema,
                        "strict": True,
                    },
                    {
                        "name": "get_dataset_overview",
                        "description": "Aggregate statistics of the dataset.",
                        "input_schema": OVERVIEW_TOOL.input_schema,
                        "strict": True,
                    },
                ],
            }
        ]

    async def test_tools_are_omitted_when_none_are_offered(self) -> None:
        client = FakeAnthropic(ANSWER)
        await _provider(client).start(PLAIN_REQUEST).send()
        [params] = client.messages.calls
        assert "tools" not in params
        assert params["max_tokens"] == 8_000  # the port's default output budget

    @pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
    async def test_effort_is_sent_inside_output_config(self, effort: str) -> None:
        client = FakeAnthropic(ANSWER)
        await _provider(client, effort=effort).start(PLAIN_REQUEST).send()
        [params] = client.messages.calls
        assert params["output_config"] == {
            "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
            "effort": effort,
        }

    async def test_server_side_fallbacks_are_opt_in(self) -> None:
        enabled, disabled = FakeAnthropic(ANSWER), FakeAnthropic(ANSWER)

        await _provider(enabled, fallbacks=True).start(PLAIN_REQUEST).send()
        await _provider(disabled, fallbacks=False).start(PLAIN_REQUEST).send()

        [with_fallbacks] = enabled.messages.calls
        assert with_fallbacks["betas"] == [FALLBACK_BETA]
        assert with_fallbacks["fallbacks"] == "default"
        [without] = disabled.messages.calls
        assert "betas" not in without
        assert "fallbacks" not in without


class TestConversation:
    async def test_tool_turns_append_the_assistant_content_before_the_results(self) -> None:
        first = _message(
            _text("Let me look at the history."),
            _tool_use("toolu_01", "get_record_history", {"record_key": "sku-1"}),
            _tool_use("toolu_02", "get_dataset_overview", {}),
            stop_reason="tool_use",
        )
        second = _message(
            _tool_use("toolu_03", "get_record_history", {"record_key": "sku-2"}),
            stop_reason="tool_use",
        )
        client = FakeAnthropic(first, second, ANSWER)
        conversation = _provider(client).start(REQUEST)
        user_turn = {"role": "user", "content": REQUEST.user_prompt}

        await conversation.send()
        await conversation.send(
            [
                ToolResult(call_id="toolu_01", content='{"versions": 3}'),
                ToolResult(call_id="toolu_02", content="tool failed", is_error=True),
            ]
        )
        await conversation.send([ToolResult(call_id="toolu_03", content='{"versions": 1}')])

        first_call, second_call, third_call = client.messages.calls
        assert first_call["messages"] == [user_turn]
        first_results = {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_01",
                    "content": '{"versions": 3}',
                    "is_error": False,
                },
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_02",
                    "content": "tool failed",
                    "is_error": True,
                },
            ],
        }
        assert second_call["messages"] == [
            user_turn,
            {"role": "assistant", "content": first.content},
            first_results,
        ]
        assert third_call["messages"] == [
            user_turn,
            {"role": "assistant", "content": first.content},
            first_results,
            {"role": "assistant", "content": second.content},
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_03",
                        "content": '{"versions": 1}',
                        "is_error": False,
                    }
                ],
            },
        ]
        # Every turn repeats the same system prompt, schema and tools.
        assert {call["system"] for call in client.messages.calls} == {REQUEST.system_prompt}
        assert all(call["tools"] == first_call["tools"] for call in client.messages.calls)

    async def test_a_final_text_turn_maps_to_a_model_turn(self) -> None:
        client = FakeAnthropic(
            _message(_text('{"summary": '), _text('"ok", "risk": 1}'), input_tokens=900)
        )
        turn = await _provider(client).start(REQUEST).send()
        assert turn == ModelTurn(
            text='{"summary": "ok", "risk": 1}',
            tool_calls=(),
            stop_reason="end_turn",
            input_tokens=900,
            output_tokens=300,
        )

    async def test_tool_use_blocks_map_to_tool_calls(self) -> None:
        client = FakeAnthropic(
            _message(
                {"type": "thinking", "thinking": "", "signature": "c2lnbmF0dXJl"},
                _tool_use("toolu_01", "get_record_history", {"record_key": "sku-1"}),
                _tool_use("toolu_02", "get_dataset_overview", {}),
                stop_reason="tool_use",
                input_tokens=2_000,
                output_tokens=150,
            )
        )
        turn = await _provider(client).start(REQUEST).send()
        assert turn == ModelTurn(
            text=None,
            tool_calls=(
                ToolCall(
                    id="toolu_01", name="get_record_history", arguments={"record_key": "sku-1"}
                ),
                ToolCall(id="toolu_02", name="get_dataset_overview", arguments={}),
            ),
            stop_reason="tool_use",
            input_tokens=2_000,
            output_tokens=150,
        )

    @pytest.mark.parametrize(
        ("stop_reason", "expected"),
        [("refusal", "refusal"), ("max_tokens", "max_tokens"), (None, "end_turn")],
    )
    async def test_stop_reasons_are_passed_through(
        self, stop_reason: str | None, expected: str
    ) -> None:
        client = FakeAnthropic(_message(stop_reason=stop_reason, output_tokens=0))
        turn = await _provider(client).start(REQUEST).send()
        assert (turn.text, turn.stop_reason) == (None, expected)

    async def test_conversations_are_independent(self) -> None:
        client = FakeAnthropic(ANSWER, ANSWER)
        provider = _provider(client)
        await provider.start(REQUEST).send()
        await provider.start(PLAIN_REQUEST).send()
        first, second = client.messages.calls
        assert first["messages"] == [{"role": "user", "content": REQUEST.user_prompt}]
        assert second["messages"] == [{"role": "user", "content": "Summarise."}]


class TestErrorClassification:
    @pytest.mark.parametrize(
        ("failure", "detail"),
        [
            pytest.param(
                _status_error(anthropic.RateLimitError, 429, "rate_limit_error"),
                "RateLimitError",
                id="429",
            ),
            pytest.param(
                anthropic.APIConnectionError(request=API_REQUEST), "APIConnectionError", id="conn"
            ),
            pytest.param(anthropic.APITimeoutError(API_REQUEST), "APITimeoutError", id="timeout"),
            pytest.param(_status_error(anthropic.InternalServerError, 500), "HTTP 500", id="500"),
            pytest.param(_status_error(anthropic.APIStatusError, 502), "HTTP 502", id="502"),
            pytest.param(
                _status_error(anthropic.APIStatusError, 503, "overloaded_error"),
                "HTTP 503",
                id="503",
            ),
            pytest.param(
                _status_error(anthropic.APIStatusError, 529, "overloaded_error"),
                "HTTP 529",
                id="529",
            ),
        ],
    )
    async def test_unavailability_is_transient(self, failure: Exception, detail: str) -> None:
        before = _sample("nexusflow_ai_requests_total", provider="anthropic", result="transient")

        with pytest.raises(AIUnavailableError) as exc:
            await _provider(FakeAnthropic(failure)).start(REQUEST).send()

        assert isinstance(exc.value, TransientError)
        assert exc.value.internal_detail == detail
        assert exc.value.__cause__ is failure
        after = _sample("nexusflow_ai_requests_total", provider="anthropic", result="transient")
        assert after == before + 1

    @pytest.mark.parametrize(
        ("error", "status"),
        [
            (anthropic.BadRequestError, 400),
            (anthropic.AuthenticationError, 401),
            (anthropic.PermissionDeniedError, 403),
            (anthropic.NotFoundError, 404),
            (anthropic.RequestTooLargeError, 413),
            (anthropic.UnprocessableEntityError, 422),
        ],
    )
    async def test_rejected_requests_are_permanent(
        self, error: type[anthropic.APIStatusError], status: int
    ) -> None:
        failure = _status_error(error, status, "invalid_request_error")
        before = _sample("nexusflow_ai_requests_total", provider="anthropic", result="rejected")

        with pytest.raises(AIRequestError) as exc:
            await _provider(FakeAnthropic(failure)).start(REQUEST).send()

        assert isinstance(exc.value, PermanentError)
        assert exc.value.internal_detail == f"HTTP {status}"
        assert exc.value.__cause__ is failure
        assert API_KEY not in f"{exc.value!r} {exc.value} {exc.value.internal_detail}"
        after = _sample("nexusflow_ai_requests_total", provider="anthropic", result="rejected")
        assert after == before + 1

    async def test_successful_calls_record_usage_and_outcome(self) -> None:
        client = FakeAnthropic(_message(_text("{}"), input_tokens=1_234, output_tokens=56))
        tokens_in = _sample("nexusflow_ai_tokens_total", provider="anthropic", direction="input")
        tokens_out = _sample("nexusflow_ai_tokens_total", provider="anthropic", direction="output")
        ended = _sample("nexusflow_ai_requests_total", provider="anthropic", result="end_turn")

        await _provider(client).start(REQUEST).send()

        assert (
            _sample("nexusflow_ai_tokens_total", provider="anthropic", direction="input")
            == tokens_in + 1_234
        )
        assert (
            _sample("nexusflow_ai_tokens_total", provider="anthropic", direction="output")
            == tokens_out + 56
        )
        assert (
            _sample("nexusflow_ai_requests_total", provider="anthropic", result="end_turn")
            == ended + 1
        )


def _unavailable() -> anthropic.APIStatusError:
    return _status_error(anthropic.InternalServerError, 500)


class TestCircuitBreaker:
    async def test_it_opens_after_the_configured_consecutive_failures(self) -> None:
        breaker = CircuitBreaker("anthropic", failure_threshold=3, reset_timeout=60.0)
        client = FakeAnthropic(_unavailable(), _unavailable(), _unavailable(), ANSWER)
        provider = _provider(client, breaker=breaker)

        for _ in range(3):
            with pytest.raises(AIUnavailableError):
                await provider.start(REQUEST).send()
        assert breaker.state is CircuitState.OPEN
        assert _circuit_gauge() == 1.0

        with pytest.raises(AIUnavailableError) as exc:
            await provider.start(REQUEST).send()
        assert exc.value.code == "ai_circuit_open"
        assert len(client.messages.calls) == 3  # failed fast: the API was not called

    async def test_rejected_requests_do_not_trip_the_breaker(self) -> None:
        breaker = CircuitBreaker("anthropic", failure_threshold=2, reset_timeout=60.0)
        client = FakeAnthropic(*(_status_error(anthropic.BadRequestError, 400) for _ in range(3)))
        provider = _provider(client, breaker=breaker)

        for _ in range(3):
            with pytest.raises(AIRequestError):
                await provider.start(REQUEST).send()

        assert breaker.state is CircuitState.CLOSED
        assert len(client.messages.calls) == 3

    async def test_a_success_resets_the_failure_count(self) -> None:
        breaker = CircuitBreaker("anthropic", failure_threshold=3, reset_timeout=60.0)
        client = FakeAnthropic(
            _unavailable(), _unavailable(), ANSWER, _unavailable(), _unavailable()
        )
        provider = _provider(client, breaker=breaker)

        outcomes = []
        for _ in range(5):
            try:
                await provider.start(REQUEST).send()
                outcomes.append("ok")
            except AIUnavailableError:
                outcomes.append("unavailable")

        assert outcomes == ["unavailable", "unavailable", "ok", "unavailable", "unavailable"]
        assert breaker.state is CircuitState.CLOSED
        assert breaker.failures == 2

    @pytest.mark.parametrize(
        ("trial", "state", "gauge"),
        [(ANSWER, CircuitState.CLOSED, 0.0), (_unavailable(), CircuitState.OPEN, 1.0)],
        ids=["trial-succeeds", "trial-fails"],
    )
    async def test_after_the_reset_timeout_one_trial_call_decides(
        self, trial: BetaMessage | Exception, state: CircuitState, gauge: float
    ) -> None:
        breaker = CircuitBreaker("anthropic", failure_threshold=1, reset_timeout=30.0)
        client = FakeAnthropic(_unavailable(), trial)
        provider = _provider(client, breaker=breaker)
        with pytest.raises(AIUnavailableError):
            await provider.start(REQUEST).send()
        assert breaker.is_open

        breaker.opened_at -= 31.0  # the reset timeout has elapsed
        with contextlib.suppress(AIUnavailableError):
            await provider.start(REQUEST).send()

        assert len(client.messages.calls) == 2  # the half-open trial reached the API
        assert breaker.state is state
        assert _circuit_gauge() == gauge

    async def test_an_open_circuit_is_retryable(self) -> None:
        breaker = CircuitBreaker("anthropic", failure_threshold=1, reset_timeout=60.0)
        provider = _provider(FakeAnthropic(_unavailable()), breaker=breaker)
        with pytest.raises(AIUnavailableError):
            await provider.start(REQUEST).send()

        with pytest.raises(TransientError) as exc:
            await provider.start(REQUEST).send()
        assert exc.value.code == "ai_circuit_open"


class TestClientLifecycle:
    async def test_name_and_model(self) -> None:
        provider = _provider(FakeAnthropic())
        assert (provider.name, provider.model) == ("anthropic", MODEL)

    async def test_aclose_closes_the_client(self) -> None:
        client = FakeAnthropic()
        await _provider(client).aclose()
        assert client.closed is True

    async def test_the_default_client_is_configured_from_the_settings(self) -> None:
        provider = AnthropicProvider(
            api_key=API_KEY,
            model=MODEL,
            timeout_seconds=90.0,
            max_retries=4,
            effort=None,
            server_side_fallbacks=True,
            breaker=CircuitBreaker("anthropic"),
        )
        try:
            client = provider._client
            assert isinstance(client, anthropic.AsyncAnthropic)
            assert client.api_key == API_KEY
            assert client.max_retries == 4
            assert isinstance(client.timeout, httpx2.Timeout)
            assert (client.timeout.read, client.timeout.connect) == (90.0, 10.0)
        finally:
            await provider.aclose()
