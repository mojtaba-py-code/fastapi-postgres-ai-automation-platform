"""One request ID links an inbound request to every job it causes, across the outbox."""

from __future__ import annotations

import json

import asyncpg
import httpx2
import pytest

from tests.support.api import signup
from tests.support.bus import InProcessBus
from tests.support.business import (
    WEBHOOK_CONFIG,
    create_dataset,
    create_project,
    create_source,
    org_id_of,
    signed_headers,
)

pytestmark = pytest.mark.integration


async def test_a_webhook_request_id_follows_every_job_it_causes(
    api: httpx2.AsyncClient, bus: InProcessBus, admin_conn: asyncpg.Connection
) -> None:
    owner = await signup(api)
    org_id = await org_id_of(owner)
    project_id = await create_project(owner)
    dataset_id = await create_dataset(owner, project_id)
    source_id = await create_source(owner, project_id, dataset_id, WEBHOOK_CONFIG)
    endpoint = await owner.post(
        "/api/v1/webhook-endpoints", json={"source_id": source_id, "name": "feed"}
    )
    assert endpoint.status_code == 201, endpoint.text
    path = endpoint.json()["url"].removeprefix("https://nexusflow.test.example")
    body = json.dumps(
        {
            "items": [
                {
                    "sku": "A-1",
                    "title": "Lamp",
                    "price": "9.90",
                    "supplier": {"email": "a@x.example"},
                }
            ]
        }
    ).encode()
    already = len(bus.messages)

    received = await api.post(
        path, content=body, headers=signed_headers(endpoint.json()["secret"], body)
    )
    assert received.status_code == 202, received.text
    request_id = received.headers["x-request-id"]
    handled = await bus.drain(org_id)

    caused = bus.messages[already:]
    assert len(caused) >= 3, handled  # the collection job, and the events and jobs it caused
    assert {message.correlation_id for message in caused} == {request_id}
    stored = await admin_conn.fetch(
        "SELECT correlation_id FROM outbox_messages WHERE id = ANY($1::uuid[])",
        [message.id for message in caused],
    )
    assert {row["correlation_id"] for row in stored} == {request_id}
