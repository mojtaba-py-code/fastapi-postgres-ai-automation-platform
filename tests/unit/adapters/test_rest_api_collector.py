"""REST API collection (``RestApiCollector`` in ``infrastructure.scraping.collectors``).

The API is an in-memory transport behind the real SSRF-guarded client, and the
per-integration quota is the real GCRA limiter on a fake Redis with a frozen
clock. Covers request construction (method, query, headers, JSON body),
credential injection and redirect hygiene, page-param and cursor pagination,
the item cap and ``truncated`` flag, content-type and payload validation, the
quota and error classification.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import fakeredis
import httpx2
import pytest
from redis.asyncio import Redis

from nexusflow.core.clock import FrozenClock
from nexusflow.core.config import RateLimitRule
from nexusflow.core.errors import (
    InvalidInputError,
    NexusFlowError,
    PermanentError,
    PolicyViolationError,
    RateLimitedError,
    TransientError,
)
from nexusflow.domain.integrations.model import IntegrationKind, ResolvedCredential
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.domain.sources.model import RestApiConfig
from nexusflow.infrastructure.http.client import (
    OutboundConnectionError,
    OutboundTimeoutError,
    ResponseTooLargeError,
    RetryableUpstreamStatusError,
    UnexpectedContentTypeError,
    UpstreamStatusError,
)
from nexusflow.infrastructure.redis.rate_limit import RateLimitDecision, RateLimiter
from nexusflow.infrastructure.scraping.collectors import CollectedItems, RestApiCollector
from tests.unit.adapters.fakes import (
    USER_AGENT,
    Handler,
    RecordingHandler,
    SafeClientFactory,
    json_response,
    respond,
)

API_URL = "https://api.example.com/v1/products"
INTEGRATION_ID = UUID("0192f0c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f")
RULE = RateLimitRule(limit=60, period_seconds=60)
BEARER = "live-api-token-" + "s" * 24
BEARER_CREDENTIAL = ResolvedCredential(IntegrationKind.HTTP_BEARER, BEARER, {})
BASIC_CREDENTIAL = ResolvedCredential(
    IntegrationKind.HTTP_BASIC, "p@ss:w0rd-secret", {"username": "api-user"}
)
HEADER_CREDENTIAL = ResolvedCredential(
    IntegrationKind.HTTP_HEADER, "header-secret-value", {"header_name": "X-Api-Token"}
)
CREDENTIAL_HEADERS = [
    pytest.param(BEARER_CREDENTIAL, "authorization", f"Bearer {BEARER}", id="bearer"),
    pytest.param(
        BASIC_CREDENTIAL,
        "authorization",
        "Basic " + base64.b64encode(b"api-user:p@ss:w0rd-secret").decode(),
        id="basic",
    ),
    pytest.param(HEADER_CREDENTIAL, "x-api-token", "header-secret-value", id="custom-header"),
]


def _products(*numbers: int) -> list[dict[str, Any]]:
    return [
        {
            "sku": f"SKU-{n}",
            "name": f"Product {n}",
            "pricing": {"amount": n * 10, "currency": "EUR"},
            "tags": ["new"],
        }
        for n in numbers
    ]


def _mapped(*numbers: int) -> list[dict[str, Any]]:
    return [{"sku": f"SKU-{n}", "title": f"Product {n}", "price": n * 10} for n in numbers]


def _config(**overrides: Any) -> RestApiConfig:
    values: dict[str, Any] = {
        "url": API_URL,
        "items_path": "data.items",
        "field_mapping": {"sku": "sku", "title": "name", "price": "pricing.amount"},
    }
    values.update(overrides)
    return RestApiConfig.model_validate(values)


def _page(*numbers: int, **extra: Any) -> httpx2.Response:
    return json_response({"data": {"items": _products(*numbers)}, **extra})


def _serve(handler: Handler) -> RecordingHandler:
    return RecordingHandler(handler)


def _always(*numbers: int) -> RecordingHandler:
    return _serve(lambda request: _page(*numbers))


class SpyLimiter(RateLimiter):
    """The real GCRA limiter (fake Redis, frozen clock) that also records calls."""

    def __init__(self, redis: Redis) -> None:
        clock = FrozenClock(datetime(2026, 9, 1, 12, 0, tzinfo=UTC))
        super().__init__(redis, prefix="nf:", clock=clock)
        self.calls: list[tuple[str, str, RateLimitRule]] = []

    async def enforce(self, scope: str, identity: str, rule: RateLimitRule) -> RateLimitDecision:
        self.calls.append((scope, identity, rule))
        return await super().enforce(scope, identity, rule)


async def _collect(
    factory: SafeClientFactory,
    api: RecordingHandler,
    config: RestApiConfig,
    *,
    credential: ResolvedCredential | None = None,
    integration_id: UUID | None = None,
    max_items: int = 1000,
    limiter: RateLimiter | None = None,
    rule: RateLimitRule = RULE,
    policy: UrlPolicy | None = None,
    **limits: float,
) -> CollectedItems:
    collector = RestApiCollector(client=factory(api, **limits), limiter=limiter, rule=rule)
    return await collector.collect(
        config,
        policy=policy or UrlPolicy(),
        credential=credential,
        integration_id=integration_id,
        max_items=max_items,
    )


def _params(api: RecordingHandler) -> list[dict[str, str]]:
    return [dict(request.url.params) for request in api.requests]


class TestRequestConstruction:
    async def test_get_request_carries_query_and_headers_but_no_body(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _always(1, 2)
        config = _config(
            query={"category": "tools", "sort": "-price"},
            headers={"X-Tenant": "acme", "Accept-Language": "de"},
        )

        result = await _collect(safe_client_factory, api, config)

        assert result == CollectedItems(items=_mapped(1, 2), truncated=False, detail={"pages": 1})
        [request] = api.requests
        assert request.method == "GET"
        assert str(request.url).startswith(API_URL + "?")
        assert dict(request.url.params) == {"category": "tools", "sort": "-price"}
        assert request.headers["accept"] == "application/json"
        assert request.headers["x-tenant"] == "acme"
        assert request.headers["accept-language"] == "de"
        assert request.headers["user-agent"] == USER_AGENT
        assert request.content == b""

    async def test_post_sends_the_configured_json_body(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _always(1)
        body = {"filter": {"in_stock": True}, "fields": ["sku", "name"]}

        await _collect(safe_client_factory, api, _config(method="POST", body=body))

        [request] = api.requests
        assert request.method == "POST"
        assert request.headers["content-type"] == "application/json"
        assert json.loads(request.content) == body

    async def test_only_scalar_values_are_mapped_and_missing_paths_are_null(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        mapping = {"sku": "sku", "pricing": "pricing", "tags": "tags", "colour": "attrs.colour"}
        result = await _collect(safe_client_factory, _always(1), _config(field_mapping=mapping))
        assert result.items == [{"sku": "SKU-1", "colour": None}]

    async def test_a_single_object_is_one_item(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _serve(lambda request: json_response({"data": {"sku": "ONLY-1", "name": "One"}}))
        config = _config(items_path="data", field_mapping={"sku": "sku", "title": "name"})
        result = await _collect(safe_client_factory, api, config)
        assert result.items == [{"sku": "ONLY-1", "title": "One"}]

    async def test_a_top_level_array_needs_no_items_path(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _serve(lambda request: json_response(_products(1, 2)))
        result = await _collect(safe_client_factory, api, _config(items_path=None))
        assert result.items == _mapped(1, 2)


class TestCredentials:
    @pytest.mark.parametrize(("credential", "header", "value"), CREDENTIAL_HEADERS)
    async def test_credentials_are_sent_as_headers(
        self,
        safe_client_factory: SafeClientFactory,
        credential: ResolvedCredential,
        header: str,
        value: str,
    ) -> None:
        api = _always(1)
        await _collect(safe_client_factory, api, _config(), credential=credential)
        [request] = api.requests
        assert request.headers[header] == value

    @pytest.mark.security
    @pytest.mark.parametrize(("credential", "header", "value"), CREDENTIAL_HEADERS)
    async def test_credentials_are_not_forwarded_to_another_origin(
        self,
        safe_client_factory: SafeClientFactory,
        credential: ResolvedCredential,
        header: str,
        value: str,
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            if request.url.host == "api.example.com":
                return respond(302, headers={"location": "https://cdn.example.net/export.json"})
            return _page(1, 2)

        api = _serve(handle)
        result = await _collect(safe_client_factory, api, _config(), credential=credential)

        assert result.items == _mapped(1, 2)
        first, second = api.requests
        assert first.headers[header] == value
        assert header not in second.headers
        assert credential.secret not in str(second.headers)
        assert second.headers["accept"] == "application/json"

    @pytest.mark.parametrize(("credential", "header", "value"), CREDENTIAL_HEADERS)
    async def test_same_origin_redirects_keep_the_credential(
        self,
        safe_client_factory: SafeClientFactory,
        credential: ResolvedCredential,
        header: str,
        value: str,
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            if request.url.path == "/v1/products":
                return respond(301, headers={"location": "/v2/products"})
            return _page(1)

        api = _serve(handle)
        await _collect(safe_client_factory, api, _config(), credential=credential)
        assert [request.headers.get(header) for request in api.requests] == [value, value]

    @pytest.mark.security
    @pytest.mark.parametrize(
        "kind",
        [
            IntegrationKind.SLACK_WEBHOOK,
            IntegrationKind.TELEGRAM_BOT,
            IntegrationKind.WEBHOOK_SIGNING,
        ],
    )
    async def test_non_http_auth_credentials_are_refused_before_any_request(
        self, safe_client_factory: SafeClientFactory, kind: IntegrationKind
    ) -> None:
        api = _always(1)
        secret = "not-for-this-api-" + "z" * 32
        with pytest.raises(PermanentError) as exc:
            await _collect(
                safe_client_factory,
                api,
                _config(),
                credential=ResolvedCredential(kind, secret, {}),
            )
        assert exc.value.code == "invalid_integration"
        assert api.requests == []
        assert secret not in f"{exc.value!r} {exc.value} {exc.value.internal_detail}"

    @pytest.mark.security
    async def test_secrets_never_appear_in_upstream_errors(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _serve(lambda request: json_response({"error": "bad token"}, 401))
        with pytest.raises(UpstreamStatusError) as exc:
            await _collect(safe_client_factory, api, _config(), credential=BEARER_CREDENTIAL)
        assert BEARER not in f"{exc.value!r} {exc.value} {exc.value.internal_detail}"
        assert exc.value.status_code == 401


class TestPagination:
    async def test_page_param_pagination_runs_until_an_empty_page(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        pages = {"1": (1, 2), "2": (3, 4), "3": ()}
        api = _serve(lambda request: _page(*pages[request.url.params["page"]]))
        config = _config(
            query={"per_page": "2"},
            pagination={"type": "page_param", "param": "page", "start": 1, "max_pages": 5},
        )

        result = await _collect(safe_client_factory, api, config)

        assert result == CollectedItems(
            items=_mapped(1, 2, 3, 4), truncated=False, detail={"pages": 3}
        )
        assert _params(api) == [
            {"per_page": "2", "page": "1"},
            {"per_page": "2", "page": "2"},
            {"per_page": "2", "page": "3"},
        ]

    async def test_page_param_pagination_starts_at_the_configured_value(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        pages = {"0": (1,), "1": ()}
        api = _serve(lambda request: _page(*pages[request.url.params["offset_page"]]))
        config = _config(pagination={"type": "page_param", "param": "offset_page", "start": 0})
        result = await _collect(safe_client_factory, api, config)
        assert result.items == _mapped(1)
        assert [params["offset_page"] for params in _params(api)] == ["0", "1"]

    async def test_page_param_pagination_stops_at_max_pages(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _serve(lambda request: _page(int(request.url.params["page"])))
        config = _config(pagination={"type": "page_param", "param": "page", "max_pages": 2})
        result = await _collect(safe_client_factory, api, config)
        assert result.items == _mapped(1, 2)
        assert result.detail == {"pages": 2}
        assert [params["page"] for params in _params(api)] == ["1", "2"]

    async def test_cursor_pagination_follows_the_cursor_until_it_is_absent(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        pages: dict[str | None, tuple[tuple[int, ...], str | None]] = {
            None: ((1, 2), "c2"),
            "c2": ((3, 4), "c3"),
            "c3": ((5,), None),
        }

        def handle(request: httpx2.Request) -> httpx2.Response:
            numbers, next_cursor = pages[request.url.params.get("after")]
            return _page(*numbers, meta={"next": next_cursor})

        api = _serve(handle)
        config = _config(
            query={"limit": "2"},
            pagination={
                "type": "cursor",
                "cursor_path": "meta.next",
                "cursor_param": "after",
                "max_pages": 10,
            },
        )

        result = await _collect(safe_client_factory, api, config)

        assert result == CollectedItems(
            items=_mapped(1, 2, 3, 4, 5), truncated=False, detail={"pages": 3}
        )
        assert _params(api) == [
            {"limit": "2"},
            {"limit": "2", "after": "c2"},
            {"limit": "2", "after": "c3"},
        ]

    @pytest.mark.parametrize(
        ("next_cursors", "expected_after"),
        [
            pytest.param(["c2", "c2"], [None, "c2"], id="repeated-cursor-stops"),
            pytest.param([{"token": "c2"}], [None], id="object-cursor-stops"),
            pytest.param([["c2"]], [None], id="list-cursor-stops"),
            pytest.param([200, None], [None, "200"], id="integer-cursor-as-string"),
        ],
    )
    async def test_cursor_values_are_validated(
        self,
        safe_client_factory: SafeClientFactory,
        next_cursors: list[object],
        expected_after: list[str | None],
    ) -> None:
        cursors = iter(next_cursors)
        api = _serve(lambda request: _page(1, meta={"next": next(cursors)}))
        config = _config(
            pagination={"type": "cursor", "cursor_path": "meta.next", "cursor_param": "after"}
        )
        await _collect(safe_client_factory, api, config)
        assert [params.get("after") for params in _params(api)] == expected_after

    async def test_cursor_values_are_capped_at_512_characters(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        cursors = iter(["x" * 2_000, None])
        api = _serve(lambda request: _page(1, meta={"next": next(cursors)}))
        config = _config(
            pagination={"type": "cursor", "cursor_path": "meta.next", "cursor_param": "after"}
        )
        await _collect(safe_client_factory, api, config)
        assert api.requests[1].url.params["after"] == "x" * 512

    async def test_an_empty_page_ends_cursor_pagination(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _serve(lambda request: _page(meta={"next": "c-next"}))
        config = _config(
            pagination={"type": "cursor", "cursor_path": "meta.next", "cursor_param": "after"}
        )
        result = await _collect(safe_client_factory, api, config)
        assert result == CollectedItems(items=[], truncated=False, detail={"pages": 1})

    async def test_an_empty_string_cursor_ends_pagination(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        pages: dict[str | None, tuple[tuple[int, ...], str]] = {
            None: ((1, 2), "c2"),
            "c2": ((3, 4), ""),
        }

        def handle(request: httpx2.Request) -> httpx2.Response:
            numbers, next_cursor = pages[request.url.params.get("after")]
            return _page(*numbers, meta={"next": next_cursor})

        api = _serve(handle)
        config = _config(
            pagination={"type": "cursor", "cursor_path": "meta.next", "cursor_param": "after"}
        )
        result = await _collect(safe_client_factory, api, config)
        assert result.items == _mapped(1, 2, 3, 4)
        assert len(api.requests) == 2

    @pytest.mark.parametrize(
        "pagination",
        [
            pytest.param({"type": "page_param", "param": "page", "max_pages": 2}, id="page"),
            pytest.param(
                {
                    "type": "cursor",
                    "cursor_path": "meta.next",
                    "cursor_param": "after",
                    "max_pages": 2,
                },
                id="cursor",
            ),
        ],
    )
    async def test_stopping_at_the_page_cap_is_reported_as_truncated(
        self, safe_client_factory: SafeClientFactory, pagination: dict[str, object]
    ) -> None:
        counter = iter(range(1, 100))

        def handle(request: httpx2.Request) -> httpx2.Response:
            number = next(counter)
            return _page(number, meta={"next": f"c{number + 1}"})

        api = _serve(handle)
        result = await _collect(safe_client_factory, api, _config(pagination=pagination))
        assert len(api.requests) == 2  # more pages exist, but the cap was reached
        assert result.truncated is True


class TestItemLimit:
    @pytest.mark.parametrize(
        ("source_limit", "run_limit", "expected", "truncated"),
        [(3, 100, 3, True), (100, 2, 2, True), (100, 100, 5, False)],
    )
    async def test_the_limit_is_the_smaller_of_source_and_run_limits(
        self,
        safe_client_factory: SafeClientFactory,
        source_limit: int,
        run_limit: int,
        expected: int,
        truncated: bool,
    ) -> None:
        result = await _collect(
            safe_client_factory,
            _always(1, 2, 3, 4, 5),
            _config(max_items=source_limit),
            max_items=run_limit,
        )
        assert result.items == _mapped(1, 2, 3, 4, 5)[:expected]
        assert result.truncated is truncated

    async def test_reaching_the_limit_stops_pagination(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        pages = {"1": (1, 2), "2": (3, 4), "3": (5, 6)}
        api = _serve(lambda request: _page(*pages[request.url.params["page"]]))
        config = _config(pagination={"type": "page_param", "param": "page"}, max_items=3)

        result = await _collect(safe_client_factory, api, config)

        assert result == CollectedItems(items=_mapped(1, 2, 3), truncated=True, detail={"pages": 2})
        assert len(api.requests) == 2

    async def test_filling_the_limit_exactly_is_reported_as_possibly_truncated(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _always(1, 2, 3)
        result = await _collect(safe_client_factory, api, _config(max_items=3))
        assert result.truncated is True  # more data may exist beyond the limit
        assert len(api.requests) == 1


class TestResponseValidation:
    @pytest.mark.parametrize(
        "content_type",
        [
            "application/json",
            "application/json; charset=utf-8",
            "application/ld+json",
            "text/json",
            "application/problem+json",
        ],
    )
    async def test_json_content_types_are_accepted(
        self, safe_client_factory: SafeClientFactory, content_type: str
    ) -> None:
        api = _serve(
            lambda request: json_response(
                {"data": {"items": _products(1)}}, content_type=content_type
            )
        )
        result = await _collect(safe_client_factory, api, _config())
        assert result.items == _mapped(1)

    @pytest.mark.parametrize(
        "content_type", ["text/html", "text/plain", "application/xml", "text/csv", None]
    )
    async def test_other_content_types_are_rejected(
        self, safe_client_factory: SafeClientFactory, content_type: str | None
    ) -> None:
        body = json.dumps({"data": {"items": _products(1)}})
        api = _serve(lambda request: respond(200, body, content_type=content_type))
        with pytest.raises(UnexpectedContentTypeError) as exc:
            await _collect(safe_client_factory, api, _config())
        assert isinstance(exc.value, PermanentError)

    @pytest.mark.parametrize(
        ("body", "code"),
        [
            pytest.param(b'{"data": {"items": [', "malformed_json", id="malformed"),
            pytest.param(b'{"data": {"items": [NaN]}}', "malformed_json", id="nan"),
            pytest.param(b'{"data": {}}', "items_not_found", id="missing-items"),
            pytest.param(b'{"data": {"items": "none"}}', "items_not_found", id="not-a-list"),
            pytest.param(b"[" * 41 + b"]" * 41, "json_too_deep", id="too-deep"),
        ],
    )
    async def test_invalid_payloads_are_rejected(
        self, safe_client_factory: SafeClientFactory, body: bytes, code: str
    ) -> None:
        api = _serve(lambda request: respond(200, body, content_type="application/json"))
        config = _config(items_path=None) if code == "json_too_deep" else _config()
        with pytest.raises(InvalidInputError) as exc:
            await _collect(safe_client_factory, api, config)
        assert exc.value.code == code

    async def test_oversized_responses_are_rejected(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _always(*range(1, 2_000))
        with pytest.raises(ResponseTooLargeError):
            await _collect(safe_client_factory, api, _config(), max_response_bytes=16 * 1024)


class TestErrorClassification:
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422])
    async def test_client_errors_are_permanent(
        self, safe_client_factory: SafeClientFactory, status: int
    ) -> None:
        api = _serve(lambda request: json_response({"error": "no"}, status))
        with pytest.raises(UpstreamStatusError) as exc:
            await _collect(safe_client_factory, api, _config())
        assert isinstance(exc.value, PermanentError)
        assert exc.value.status_code == status

    @pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504])
    async def test_throttling_and_server_errors_are_transient(
        self, safe_client_factory: SafeClientFactory, status: int
    ) -> None:
        api = _serve(lambda request: json_response({}, status, headers={"retry-after": "30"}))
        with pytest.raises(RetryableUpstreamStatusError) as exc:
            await _collect(safe_client_factory, api, _config())
        assert isinstance(exc.value, TransientError)
        assert (exc.value.status_code, exc.value.retry_after_seconds) == (status, 30)

    @pytest.mark.parametrize(
        ("failure", "error"),
        [
            (httpx2.ConnectError, OutboundConnectionError),
            (httpx2.ReadError, OutboundConnectionError),
            (httpx2.ConnectTimeout, OutboundTimeoutError),
            (httpx2.ReadTimeout, OutboundTimeoutError),
            (httpx2.WriteTimeout, OutboundTimeoutError),
        ],
    )
    async def test_network_failures_are_transient(
        self,
        safe_client_factory: SafeClientFactory,
        failure: type[httpx2.TransportError],
        error: type[NexusFlowError],
    ) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            raise failure("simulated", request=request)

        with pytest.raises(error) as exc:
            await _collect(safe_client_factory, _serve(handle), _config())
        assert isinstance(exc.value, TransientError)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "url", ["https://10.0.0.8/api/items", "https://metadata.google.internal/computeMetadata"]
    )
    async def test_blocked_destinations_are_never_requested(
        self, safe_client_factory: SafeClientFactory, url: str
    ) -> None:
        api = _always(1)
        with pytest.raises(PolicyViolationError):
            await _collect(safe_client_factory, api, _config(url=url))
        assert api.requests == []

    @pytest.mark.security
    async def test_redirects_into_the_internal_network_are_blocked(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        api = _serve(
            lambda request: respond(302, headers={"location": "https://169.254.169.254/latest/"})
        )
        with pytest.raises(PolicyViolationError):
            await _collect(safe_client_factory, api, _config(), credential=BEARER_CREDENTIAL)
        assert len(api.requests) == 1


class TestIntegrationQuota:
    async def test_every_page_is_charged_to_the_integration(
        self, safe_client_factory: SafeClientFactory, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        pages = {"1": (1,), "2": (2,), "3": ()}
        api = _serve(lambda request: _page(*pages[request.url.params["page"]]))
        limiter = SpyLimiter(fake_redis)

        await _collect(
            safe_client_factory,
            api,
            _config(pagination={"type": "page_param", "param": "page"}),
            credential=BEARER_CREDENTIAL,
            integration_id=INTEGRATION_ID,
            limiter=limiter,
        )

        assert limiter.calls == [("external_api.integration", str(INTEGRATION_ID), RULE)] * 3

    async def test_an_exhausted_quota_stops_collection(
        self, safe_client_factory: SafeClientFactory, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        api = _serve(lambda request: _page(int(request.url.params["page"])))
        with pytest.raises(RateLimitedError) as exc:
            await _collect(
                safe_client_factory,
                api,
                _config(pagination={"type": "page_param", "param": "page", "max_pages": 5}),
                integration_id=INTEGRATION_ID,
                limiter=SpyLimiter(fake_redis),
                rule=RateLimitRule(limit=2, period_seconds=60),
            )
        assert exc.value.retry_after_seconds == 30
        assert len(api.requests) == 2  # the third page was never requested

    async def test_sources_without_an_integration_are_not_charged(
        self, safe_client_factory: SafeClientFactory, fake_redis: fakeredis.FakeAsyncRedis
    ) -> None:
        limiter = SpyLimiter(fake_redis)
        await _collect(safe_client_factory, _always(1), _config(), limiter=limiter)
        assert limiter.calls == []
