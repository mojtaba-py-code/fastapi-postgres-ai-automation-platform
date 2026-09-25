"""The authenticated caller of an operation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from nexusflow.core.errors import PermissionDeniedError
from nexusflow.domain.authorization.roles import Permission, Role, permissions_for


class PrincipalType(StrEnum):
    USER = "user"
    API_KEY = "api_key"
    SERVICE = "service"
    SYSTEM = "system"


class ServiceScope(StrEnum):
    """Scopes for platform service tokens (n8n workflows); never tenant permissions."""

    COLLECT = "automation:collect"
    DETECT = "automation:detect"
    ANALYZE = "automation:analyze"
    ALERT = "automation:alert"
    RECOVER = "automation:recover"
    OPERATOR_ALERT = "automation:operator_alert"


@dataclass(frozen=True, slots=True)
class Principal:
    type: PrincipalType
    id: UUID
    org_id: UUID | None
    role: Role | None
    permissions: frozenset[Permission] = field(default_factory=frozenset)
    service_scopes: frozenset[ServiceScope] = field(default_factory=frozenset)
    user_id: UUID | None = None
    session_id: UUID | None = None
    label: str = ""

    @classmethod
    def for_user(
        cls,
        *,
        user_id: UUID,
        org_id: UUID | None,
        role: Role | None,
        session_id: UUID | None,
        label: str = "",
    ) -> Principal:
        return cls(
            type=PrincipalType.USER,
            id=user_id,
            org_id=org_id,
            role=role,
            permissions=permissions_for(role) if role else frozenset(),
            user_id=user_id,
            session_id=session_id,
            label=label,
        )

    @classmethod
    def system(cls, org_id: UUID | None = None) -> Principal:
        """Internal jobs acting on behalf of the platform (never from a request)."""
        return cls(
            type=PrincipalType.SYSTEM,
            id=UUID(int=0),
            org_id=org_id,
            role=None,
            label="system",
        )

    @property
    def is_system(self) -> bool:
        return self.type is PrincipalType.SYSTEM

    def has(self, permission: Permission) -> bool:
        return self.is_system or permission in self.permissions

    def require(self, permission: Permission) -> None:
        if not self.has(permission):
            raise PermissionDeniedError(internal_detail=f"missing {permission.value}")

    def require_org(self) -> UUID:
        if self.org_id is None:
            raise PermissionDeniedError(
                "Select an organization before performing this action.",
                code="organization_required",
            )
        return self.org_id

    def require_scope(self, scope: ServiceScope) -> None:
        if self.type is not PrincipalType.SERVICE or scope not in self.service_scopes:
            raise PermissionDeniedError(internal_detail=f"missing service scope {scope.value}")

    @property
    def actor_user_id(self) -> UUID | None:
        """The human accountable for the action, if any (for ``created_by`` columns)."""
        return self.user_id
