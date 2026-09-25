"""Stored files (uploads, reports) never outlive the rows that reference them."""

from __future__ import annotations

import os
import time
from uuid import uuid4

import pytest
from asgi_lifespan import LifespanManager

from nexusflow.apps.api.main import create_app
from nexusflow.bootstrap.container import Container

pytestmark = pytest.mark.integration


async def test_the_api_removes_plaintext_copies_left_by_a_killed_process(
    container: Container,
) -> None:
    root = container.storage.local_path(f"uploads/{uuid4()}/{uuid4()}.csv").parents[2]
    left_behind = root / ".scratch" / "left-behind.csv"
    left_behind.parent.mkdir(parents=True, exist_ok=True)
    left_behind.write_bytes(b"SKU\r\nplaintext\r\n")
    hours_ago = time.time() - 2 * 3600
    os.utime(left_behind, (hours_ago, hours_ago))

    app = create_app(container.settings, container=container, configure_logs=False)
    async with LifespanManager(app):
        pass

    assert not left_behind.exists()
