"""The n8n client: signed event delivery and the kill switch's workflow unpublishing."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx2
import jwt
import pytest

from nexusflow.core.errors import PermanentError, TransientError
from nexusflow.infrastructure.n8n.client import EVENT_PATHS, N8nClient

SECRET = "n8n-webhook-secret-" + "x" * 32
API_KEY = "n8n-api-key-value"

type Answer = Callable[[httpx2.Request], httpx2.Response]


class Recorder:
    def __init__(self, answer: Answer) -> None:
        self.answer = answer
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.answer(request)


def _client(recorder: Recorder, *, api_key: str | None = API_KEY) -> N8nClient:
    return N8nClient(
        webhook_base_url="http://n8n:5678/webhook/",
        api_base_url="http://n8n:5678",
        jwt_secret=SECRET,
        api_key=api_key,
        timeout_seconds=5,
        transport=httpx2.MockTransport(recorder),
    )


def _status(code: int) -> Answer:
    return lambda request: httpx2.Response(code)


class TestEvents:
    async def test_every_listening_workflow_gets_a_signed_short_lived_event(self) -> None:
        recorder = Recorder(_status(200))
        client = _client(recorder)
        delivered = await client.emit("changes.detected", {"org_id": "o-1", "dataset_id": "d-1"})

        assert delivered == 2
        assert [r.url.path for r in recorder.requests] == [
            f"/webhook/{path}" for path in EVENT_PATHS["changes.detected"]
        ]
        claims = []
        for request in recorder.requests:
            assert json.loads(request.content) == {"org_id": "o-1", "dataset_id": "d-1"}
            token = request.headers["authorization"].removeprefix("Bearer ")
            claims.append(jwt.decode(token, SECRET, algorithms=["HS256"], audience="n8n"))
        assert all(c["exp"] - c["iat"] == 60 and c["event"] == "changes.detected" for c in claims)
        assert len({c["jti"] for c in claims}) == 2  # every token is unique
        await client.aclose()

    async def test_a_path_without_a_listening_workflow_is_skipped(self) -> None:
        recorder = Recorder(lambda r: httpx2.Response(404 if "analysis" in r.url.path else 200))
        assert await _client(recorder).emit("changes.detected", {}) == 1

    @pytest.mark.parametrize(
        ("status", "error", "code"),
        [
            (500, TransientError, "n8n_unavailable"),
            (503, TransientError, "n8n_unavailable"),
            (429, TransientError, "n8n_unavailable"),
            (401, PermanentError, "n8n_rejected"),
            (400, PermanentError, "n8n_rejected"),
            (302, PermanentError, "n8n_rejected"),  # a redirect is not a delivery
        ],
    )
    async def test_failures_are_classified(
        self, status: int, error: type[Exception], code: str
    ) -> None:
        with pytest.raises(error) as exc:
            await _client(Recorder(_status(status))).emit("job.failed", {})
        assert exc.value.code == code  # type: ignore[attr-defined]

    async def test_an_unreachable_n8n_is_a_temporary_failure(self) -> None:
        def refuse(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("refused", request=request)

        with pytest.raises(TransientError) as exc:
            await _client(Recorder(refuse)).emit("job.failed", {})
        assert exc.value.code == "n8n_unreachable"

    async def test_unknown_events_are_refused(self) -> None:
        recorder = Recorder(_status(200))
        with pytest.raises(PermanentError):
            await _client(recorder).emit("tenant.data.dump", {})
        assert recorder.requests == []

    def test_a_weak_signing_secret_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least 32"):
            N8nClient(
                webhook_base_url="http://n8n",
                api_base_url="http://n8n",
                jwt_secret="short",
                api_key=None,
                timeout_seconds=5,
            )


class TestKillSwitch:
    async def test_a_workflow_is_unpublished_with_the_api_key(self) -> None:
        recorder = Recorder(_status(200))
        await _client(recorder).deactivate_workflow("Wf123abc")
        [request] = recorder.requests
        assert (request.method, request.url.path) == (
            "POST",
            "/api/v1/workflows/Wf123abc/unpublish",
        )
        assert request.headers["x-n8n-api-key"] == API_KEY

    async def test_releases_before_n8n_2_are_deactivated_instead(self) -> None:
        recorder = Recorder(lambda r: httpx2.Response(404 if "unpublish" in r.url.path else 200))
        await _client(recorder).deactivate_workflow("Wf123abc")
        assert [r.url.path for r in recorder.requests] == [
            "/api/v1/workflows/Wf123abc/unpublish",
            "/api/v1/workflows/Wf123abc/deactivate",
        ]

    @pytest.mark.parametrize("status", [401, 403, 500, 302])
    async def test_a_failed_unpublish_is_reported(self, status: int) -> None:
        with pytest.raises(PermanentError) as exc:
            await _client(Recorder(_status(status))).deactivate_workflow("Wf123abc")
        assert exc.value.code == "n8n_deactivation_failed"

    async def test_nothing_is_sent_without_an_api_key_or_for_a_crafted_id(self) -> None:
        recorder = Recorder(_status(200))
        with pytest.raises(PermanentError) as missing:
            await _client(recorder, api_key=None).deactivate_workflow("Wf123abc")
        assert missing.value.code == "n8n_api_key_missing"
        with pytest.raises(PermanentError) as crafted:
            await _client(recorder).deactivate_workflow("../../credentials")
        assert crafted.value.code == "invalid_workflow_id"
        assert recorder.requests == []

    async def test_an_unreachable_api_is_a_temporary_failure(self) -> None:
        def refuse(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("refused", request=request)

        with pytest.raises(TransientError):
            await _client(Recorder(refuse)).deactivate_workflow("Wf123abc")
