"""Everything in this package talks to PostgreSQL."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "integration" in item.nodeid.split("::")[0]:
            item.add_marker(pytest.mark.integration)
