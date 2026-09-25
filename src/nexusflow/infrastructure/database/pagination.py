"""Keyset pagination for SQLAlchemy statements."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    ColumnElement,
    DateTime,
    Enum,
    Integer,
    Row,
    Select,
    SmallInteger,
    literal,
    tuple_,
)
from sqlalchemy.ext.asyncio import AsyncSession

from nexusflow.core.errors import InvalidInputError
from nexusflow.core.pagination import Page, PageRequest, SortValue, encode_cursor

type SortKey = tuple[SortValue | datetime, UUID]


# Subclasses first: SmallInteger and BigInteger both derive from Integer.
_INTEGER_BOUNDS: tuple[tuple[type[Integer], int], ...] = (
    (SmallInteger, 2**15),
    (BigInteger, 2**63),
    (Integer, 2**31),
)


def _coerce(value: SortValue, column: ColumnElement[Any]) -> Any:
    """Type- and range-check a client-supplied cursor value against the sort column.

    A cursor minted for one sort field and replayed with another, or crafted
    by hand, must fail as a 422 - never as a driver/database error (500).
    """
    invalid = InvalidInputError("The pagination cursor is invalid.", code="invalid_cursor")
    column_type = column.type
    if isinstance(column_type, DateTime):
        if not isinstance(value, str):
            raise invalid
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise invalid from exc
        if parsed.tzinfo is None:
            raise invalid
        try:
            # Normalise here: an offset that pushes the instant past year 1 or
            # 9999 would otherwise overflow inside the driver.
            return parsed.astimezone(UTC)
        except OverflowError as exc:
            raise invalid from exc
    if isinstance(column_type, Integer):
        bound = next(limit for kind, limit in _INTEGER_BOUNDS if isinstance(column_type, kind))
        if isinstance(value, int) and -bound <= value < bound:
            return value
        raise invalid
    if isinstance(column_type, Enum):
        if value in column_type.enums:
            return value
        raise invalid
    try:
        expected = column_type.python_type
    except NotImplementedError:
        raise invalid from None
    if expected is str and isinstance(value, str):
        return value
    if expected is float and isinstance(value, (int, float)):
        return float(value)
    raise invalid


def _apply_keyset[S: Select[Any]](
    statement: S,
    *,
    page: PageRequest,
    sort_columns: Mapping[str, ColumnElement[Any]],
    id_column: ColumnElement[Any],
) -> S:
    sort_column = sort_columns.get(page.sort.field)
    if sort_column is None:
        raise InvalidInputError("Unsupported sort field.", code="invalid_sort")
    if page.cursor is not None:
        boundary = tuple_(
            literal(_coerce(page.cursor.sort_value, sort_column), type_=sort_column.type),
            literal(page.cursor.last_id, type_=id_column.type),
        )
        position = tuple_(sort_column, id_column)
        statement = statement.where(
            position < boundary if page.sort.descending else position > boundary
        )
    if page.sort.descending:
        statement = statement.order_by(sort_column.desc(), id_column.desc())
    else:
        statement = statement.order_by(sort_column.asc(), id_column.asc())
    return statement.limit(page.limit + 1)


def _page[T](items: list[T], page: PageRequest, key: Callable[[T], SortKey]) -> Page[T]:
    has_more = len(items) > page.limit
    visible = items[: page.limit]
    next_cursor = encode_cursor(*key(visible[-1])) if has_more and visible else None
    return Page(items=visible, next_cursor=next_cursor)


async def paginate[T](
    session: AsyncSession,
    statement: Select[tuple[T]],
    *,
    page: PageRequest,
    sort_columns: Mapping[str, ColumnElement[Any]],
    id_column: ColumnElement[Any],
    key: Callable[[T], SortKey],
) -> Page[T]:
    """Paginate an ORM entity query (``select(Entity)``)."""
    keyset = _apply_keyset(statement, page=page, sort_columns=sort_columns, id_column=id_column)
    result = await session.execute(keyset)
    return _page(list(result.scalars().all()), page, key)


async def paginate_rows[T](
    session: AsyncSession,
    statement: Select[Any],
    *,
    page: PageRequest,
    sort_columns: Mapping[str, ColumnElement[Any]],
    id_column: ColumnElement[Any],
    convert: Callable[[Row[Any]], T],
    key: Callable[[T], SortKey],
) -> Page[T]:
    """Paginate a multi-column query, converting each row into a read model."""
    keyset = _apply_keyset(statement, page=page, sort_columns=sort_columns, id_column=id_column)
    result = await session.execute(keyset)
    return _page([convert(row) for row in result.all()], page, key)
