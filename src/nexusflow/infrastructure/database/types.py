"""Custom SQLAlchemy column types."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import String
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class StrEnumType[E: StrEnum](TypeDecorator[E]):
    """Stores a ``StrEnum`` as VARCHAR; migrations add matching CHECK constraints."""

    impl = String
    cache_ok = True

    def __init__(self, enum_cls: type[E], length: int = 32) -> None:
        super().__init__(length)
        self._enum_cls = enum_cls

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return self._enum_cls(value).value

    def process_result_value(self, value: Any, dialect: Dialect) -> E | None:
        if value is None:
            return None
        return self._enum_cls(value)
