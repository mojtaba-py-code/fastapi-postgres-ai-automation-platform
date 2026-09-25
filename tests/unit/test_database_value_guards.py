"""Client-controlled values must never reach the database as a 500.

Two layers: cursor values are range-checked against the sort column before
they are bound, and any SQLSTATE class 22 ("data exception") that still slips
through is mapped to a 422 without echoing the statement or its parameters.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import httpx2
import pytest
from fastapi import FastAPI
from sqlalchemy import BigInteger, Column, DateTime, Enum, Integer, MetaData, SmallInteger, Table
from sqlalchemy.exc import DBAPIError

from nexusflow.apps.api.errors import install_error_handlers
from nexusflow.core.errors import InvalidInputError
from nexusflow.infrastructure.database.pagination import _coerce

_table = Table(
    "probe",
    MetaData(),
    Column("small", SmallInteger),
    Column("regular", Integer),
    Column("big", BigInteger),
    Column("at", DateTime(timezone=True)),
    Column("state", Enum("open", "closed", name="probe_state")),
)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("small", 2**15 - 1),
        ("small", -(2**15)),
        ("regular", 2**31 - 1),
        ("big", -(2**63)),
        ("state", "open"),
    ],
)
def test_values_inside_the_column_range_are_accepted(column: str, value: object) -> None:
    assert _coerce(value, _table.c[column]) == value  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("small", 2**15),
        ("small", -(2**15) - 1),
        ("regular", 2**31),
        ("big", 2**63),
        ("small", "1"),
        ("state", "deleted"),  # not a label of the PostgreSQL enum
        ("at", "2026-01-01T00:00:00"),  # naive
        ("at", "0001-01-01T00:00:00+05:00"),  # before year 1 in UTC
        ("at", "9999-12-31T23:00:00-05:00"),  # after 9999 in UTC
        ("at", 1_700_000_000),
    ],
)
def test_values_the_column_cannot_hold_are_invalid_cursors(column: str, value: object) -> None:
    with pytest.raises(InvalidInputError) as caught:
        _coerce(value, _table.c[column])  # type: ignore[arg-type]
    assert caught.value.code == "invalid_cursor"


def test_timestamps_are_normalised_to_utc() -> None:
    coerced = _coerce("2026-03-01T04:30:00+04:30", _table.c.at)
    assert coerced == datetime(2026, 3, 1, tzinfo=UTC)
    assert coerced.utcoffset() == timedelta(0)
    assert coerced.tzinfo is not timezone(timedelta(hours=4, minutes=30))


class _DriverError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__(f"driver error {sqlstate}")
        self.sqlstate = sqlstate


def _app(sqlstate: str) -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise DBAPIError("SELECT secret FROM t WHERE x = $1", ("p4ssw0rd",), _DriverError(sqlstate))

    return app


async def _get(app: FastAPI) -> httpx2.Response:
    transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get("/boom")


@pytest.mark.parametrize("sqlstate", ["22000", "22021", "22003", "22P02"])
async def test_data_exceptions_are_client_errors_without_sql_details(sqlstate: str) -> None:
    response = await _get(_app(sqlstate))
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_value"
    assert "SELECT" not in response.text
    assert "p4ssw0rd" not in response.text


@pytest.mark.parametrize("sqlstate", ["23505", "40001", "57014", "08006"])
async def test_other_database_errors_remain_server_errors(sqlstate: str) -> None:
    response = await _get(_app(sqlstate))
    assert response.status_code == 500
    assert response.json()["error"] == "internal_server_error"
    assert "p4ssw0rd" not in response.text
