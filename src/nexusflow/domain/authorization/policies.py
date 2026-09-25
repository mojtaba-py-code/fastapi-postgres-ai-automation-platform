"""Resource-level authorization rules that go beyond a single permission check."""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from nexusflow.core.errors import ConflictError, InvalidInputError, PermissionDeniedError
from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission, Role, permissions_for, role_covers


def ensure_can_assign_role(actor: Principal, *, current: Role | None, new: Role) -> None:
    """Privilege-escalation guard for invitations and role changes.

    * the actor needs ``members:manage``;
    * only owners may grant, modify or revoke the owner role;
    * nobody can grant a role carrying permissions they do not hold themselves.
    """
    actor.require(Permission.MEMBERS_MANAGE)
    if actor.role is None:
        raise PermissionDeniedError()
    touches_owner = new is Role.OWNER or current is Role.OWNER
    if touches_owner and actor.role is not Role.OWNER:
        raise PermissionDeniedError("Only owners can manage the owner role.", code="owner_required")
    if not role_covers(actor.role, new):
        raise PermissionDeniedError(
            "You cannot grant a role with more privileges than your own.",
            code="role_escalation",
        )


def ensure_not_self(actor: Principal, target_user_id: UUID) -> None:
    if actor.user_id == target_user_id:
        raise PermissionDeniedError(
            "You cannot change your own role; ask another owner or administrator.",
            code="self_modification",
        )


def ensure_owner_remains(owner_count: int, *, removing_owner: bool) -> None:
    if removing_owner and owner_count <= 1:
        raise ConflictError("An organization must keep at least one owner.", code="last_owner")


def validate_api_key_grant(actor: Principal, *, role: Role, scopes: Iterable[str]) -> list[str]:
    """API keys may carry at most the creator's privileges (least privilege)."""
    actor.require(Permission.API_KEYS_MANAGE)
    if actor.role is None or not role_covers(actor.role, role):
        raise PermissionDeniedError("API keys cannot exceed your own role.", code="role_escalation")
    allowed = permissions_for(role)
    requested: list[str] = []
    for scope in scopes:
        if scope not in Permission or Permission(scope) not in allowed:
            raise InvalidInputError(f"Scope {scope!r} is not allowed for role {role.value}.")
        if scope not in requested:
            requested.append(scope)
    if not requested:
        raise InvalidInputError("At least one scope is required.", code="scopes_required")
    return sorted(requested)
