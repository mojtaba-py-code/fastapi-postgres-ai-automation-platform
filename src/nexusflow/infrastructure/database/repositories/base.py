"""Generic tenant-scoped repository.

Every lookup filters by ``org_id`` explicitly (defence in depth on top of RLS),
so an identifier from another tenant simply yields ``None`` -> HTTP 404.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any, ClassVar
from uuid import UUID

from sqlalchemy import ColumnElement, Table, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from nexusflow.core.errors import ConflictError
from nexusflow.core.pagination import Page, PageRequest
from nexusflow.infrastructure.database.pagination import SortKey, paginate


class TenantRepository[E]:
    entity: ClassVar[type[Any]]
    table: ClassVar[Table]
    sortable: ClassVar[tuple[str, ...]] = ("created_at",)

    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, entity: E) -> None:
        self._s.add(entity)
        try:
            await self._s.flush()  # deterministic insert order (no ORM relationships)
        except IntegrityError as exc:
            raise ConflictError(
                "A resource with the same unique attributes already exists.",
                code="duplicate",
                internal_detail=str(exc.orig)[:300],
            ) from exc

    async def get(self, org_id: UUID, entity_id: UUID) -> E | None:
        statement = select(self.entity).where(
            self.table.c.org_id == org_id, self.table.c.id == entity_id
        )
        result: E | None = (await self._s.execute(statement)).scalar_one_or_none()
        return result

    async def get_for_update(self, org_id: UUID, entity_id: UUID) -> E | None:
        statement = (
            select(self.entity)
            .where(self.table.c.org_id == org_id, self.table.c.id == entity_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        result: E | None = (await self._s.execute(statement)).scalar_one_or_none()
        return result

    async def delete(self, entity: E) -> None:
        await self._s.delete(entity)
        await self._s.flush()

    async def list_page(
        self,
        org_id: UUID,
        page: PageRequest,
        filters: Mapping[str, Any] | None = None,
        extra: Iterable[ColumnElement[bool]] = (),
    ) -> Page[E]:
        statement = select(self.entity).where(self.table.c.org_id == org_id, *extra)
        for column, value in (filters or {}).items():
            if value is not None:
                statement = statement.where(self.table.c[column] == value)
        sort_columns = {name: self.table.c[name] for name in self.sortable}
        return await paginate(
            self._s,
            statement,
            page=page,
            sort_columns=sort_columns,
            id_column=self.table.c.id,
            key=self._sort_key(page),
        )

    async def count(self, org_id: UUID, **filters: Any) -> int:
        statement = (
            select(func.count()).select_from(self.table).where(self.table.c.org_id == org_id)
        )
        for column, value in filters.items():
            statement = statement.where(self.table.c[column] == value)
        return int((await self._s.execute(statement)).scalar_one())

    def _sort_key(self, page: PageRequest) -> Callable[[E], SortKey]:
        field = page.sort.field

        def key(entity: E) -> SortKey:
            return (getattr(entity, field), getattr(entity, "id"))  # noqa: B009

        return key
