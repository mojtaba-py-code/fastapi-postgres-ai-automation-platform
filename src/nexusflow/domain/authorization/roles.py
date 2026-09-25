"""Role-based access control: roles, permissions and the role->permission matrix.

Permissions are fine-grained ``resource:action`` strings. Roles are fixed
bundles of permissions (least privilege); API keys carry an explicit subset.
Every server-side operation checks a permission - the client/UI is never
trusted to hide actions.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(StrEnum):
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    MEMBERS_READ = "members:read"
    MEMBERS_MANAGE = "members:manage"
    API_KEYS_MANAGE = "api_keys:manage"
    AUDIT_READ = "audit:read"

    PROJECTS_READ = "projects:read"
    PROJECTS_WRITE = "projects:write"
    DATASETS_READ = "datasets:read"
    DATASETS_WRITE = "datasets:write"
    DATASETS_EXPORT = "datasets:export"
    RECORDS_READ = "records:read"
    RECORDS_READ_SENSITIVE = "records:read_sensitive"
    SOURCES_READ = "sources:read"
    SOURCES_WRITE = "sources:write"
    SOURCES_RUN = "sources:run"
    UPLOADS_WRITE = "uploads:write"
    CHANGES_READ = "changes:read"

    INSIGHTS_READ = "insights:read"
    INSIGHTS_GENERATE = "insights:generate"
    REPORTS_READ = "reports:read"
    REPORTS_GENERATE = "reports:generate"
    REPORTS_DOWNLOAD = "reports:download"

    ALERTS_READ = "alerts:read"
    ALERTS_WRITE = "alerts:write"
    ALERTS_ACK = "alerts:ack"
    CHANNELS_READ = "channels:read"
    CHANNELS_WRITE = "channels:write"

    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_WRITE = "integrations:write"
    WEBHOOKS_READ = "webhooks:read"
    WEBHOOKS_WRITE = "webhooks:write"

    WORKFLOWS_READ = "workflows:read"
    WORKFLOWS_WRITE = "workflows:write"
    WORKFLOWS_EXECUTE = "workflows:execute"
    WORKFLOWS_DISABLE = "workflows:disable"
    DEAD_LETTERS_MANAGE = "dead_letters:manage"


_READ_ONLY: frozenset[Permission] = frozenset(
    {
        Permission.ORG_READ,
        Permission.PROJECTS_READ,
        Permission.DATASETS_READ,
        Permission.RECORDS_READ,
        Permission.SOURCES_READ,
        Permission.CHANGES_READ,
        Permission.INSIGHTS_READ,
        Permission.REPORTS_READ,
        Permission.ALERTS_READ,
        Permission.WORKFLOWS_READ,
    }
)

_OPERATOR = _READ_ONLY | {
    Permission.MEMBERS_READ,
    Permission.SOURCES_RUN,
    Permission.UPLOADS_WRITE,
    Permission.ALERTS_ACK,
    Permission.CHANNELS_READ,
    Permission.WORKFLOWS_EXECUTE,
    Permission.WORKFLOWS_DISABLE,  # operators may stop automation during incidents
    Permission.REPORTS_DOWNLOAD,
    Permission.DEAD_LETTERS_MANAGE,
}

_ANALYST = _READ_ONLY | {
    Permission.MEMBERS_READ,
    Permission.PROJECTS_WRITE,
    Permission.DATASETS_WRITE,
    Permission.DATASETS_EXPORT,
    Permission.RECORDS_READ_SENSITIVE,
    Permission.SOURCES_WRITE,
    Permission.SOURCES_RUN,
    Permission.UPLOADS_WRITE,
    Permission.INSIGHTS_GENERATE,
    Permission.REPORTS_GENERATE,
    Permission.REPORTS_DOWNLOAD,
    Permission.ALERTS_WRITE,
    Permission.ALERTS_ACK,
    Permission.CHANNELS_READ,
    Permission.WORKFLOWS_WRITE,
    Permission.WORKFLOWS_EXECUTE,
}

_ADMIN = (
    _ANALYST
    | _OPERATOR
    | {
        Permission.ORG_UPDATE,
        Permission.MEMBERS_MANAGE,
        Permission.API_KEYS_MANAGE,
        Permission.AUDIT_READ,
        Permission.CHANNELS_WRITE,
        Permission.INTEGRATIONS_READ,
        Permission.INTEGRATIONS_WRITE,
        Permission.WEBHOOKS_READ,
        Permission.WEBHOOKS_WRITE,
        Permission.WORKFLOWS_DISABLE,
    }
)

_OWNER = _ADMIN | {Permission.ORG_DELETE}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(_OWNER),
    Role.ADMIN: frozenset(_ADMIN),
    Role.ANALYST: frozenset(_ANALYST),
    Role.OPERATOR: frozenset(_OPERATOR),
    Role.VIEWER: frozenset(_READ_ONLY),
}


def permissions_for(role: Role) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


def role_covers(actor: Role, target: Role) -> bool:
    """True if ``actor`` holds every permission of ``target`` (no escalation)."""
    return ROLE_PERMISSIONS[target] <= ROLE_PERMISSIONS[actor]
