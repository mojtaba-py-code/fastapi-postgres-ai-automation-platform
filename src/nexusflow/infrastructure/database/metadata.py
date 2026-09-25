"""Shared SQLAlchemy metadata with deterministic constraint naming."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import CheckConstraint, MetaData

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


def enum_check(column: str, enum_cls: type[StrEnum], *, nullable: bool = False) -> CheckConstraint:
    """CHECK constraint restricting a VARCHAR column to the enum's values."""
    values = ", ".join(f"'{member.value}'" for member in enum_cls)
    condition = f"{column} IN ({values})"
    if nullable:
        condition = f"{column} IS NULL OR {condition}"
    return CheckConstraint(condition, name=column)
