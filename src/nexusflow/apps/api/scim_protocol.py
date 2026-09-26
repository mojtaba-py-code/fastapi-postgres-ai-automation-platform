"""The SCIM 2.0 wire format (RFC 7643 resources, RFC 7644 protocol).

Only what provisioning Users needs: the core User schema (attribute names
compared case-insensitively, as RFC 7643 section 2.1 requires), PatchOp
``add``/``replace``, filters ``<attribute> eq "<value>"`` on ``userName``,
``externalId`` and ``emails.value``, ListResponse and the Error schema.

Unknown attributes (enterprise extension, phone numbers, ``roles``, ``groups``,
``id``, ``meta``...) are ignored - a service provider may ignore what it does
not support (RFC 7644, section 3.3) and identity providers send many - so
nothing a client sends can reach a field the service does not map. Passwords
are refused outright: people sign in at their identity provider.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from nexusflow.core.jsonutil import JSONObject, JSONValue
from nexusflow.domain.identity.directory import (
    MAX_PAGE_SIZE,
    DirectoryFilter,
    DirectoryFilterField,
    DirectoryUser,
    DirectoryUserChanges,
    DirectoryUserInput,
)

MEDIA_TYPE = "application/scim+json"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SERVICE_PROVIDER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"
# RFC 7644, section 3.12.
SCIM_TYPES = frozenset(
    {
        "invalidFilter",
        "tooMany",
        "uniqueness",
        "mutability",
        "invalidSyntax",
        "invalidPath",
        "noTarget",
        "invalidValue",
        "invalidVers",
        "sensitive",
    }
)
MAX_OPERATIONS = 50
_MAX_FILTER_LENGTH = 512
_FILTER = re.compile(
    r'^\s*([A-Za-z][A-Za-z0-9_.:-]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.IGNORECASE
)
_FILTER_FIELDS = {
    "username": DirectoryFilterField.USER_NAME,
    "externalid": DirectoryFilterField.EXTERNAL_ID,
    "emails.value": DirectoryFilterField.EMAIL,
    "emails": DirectoryFilterField.EMAIL,
}
_EMAIL_VALUE_PATH = re.compile(r'^emails\[type eq "[a-z]{1,20}"\]\.value$')
_NAME_PARTS = {
    "givenname": "given_name",
    "familyname": "family_name",
    "formatted": "formatted_name",
}
# Core User attributes this service provider does not store: a PATCH that sets
# them is accepted and they are ignored, as in a full representation. Roles,
# entitlements and groups are among them - SCIM grants no role but the default.
_IGNORED_ATTRIBUTES = frozenset(
    {
        "nickname",
        "profileurl",
        "title",
        "usertype",
        "preferredlanguage",
        "locale",
        "timezone",
        "phonenumbers",
        "addresses",
        "ims",
        "photos",
        "entitlements",
        "roles",
        "groups",
        "x509certificates",
        "name.middlename",
        "name.honorificprefix",
        "name.honorificsuffix",
    }
)


class ScimError(Exception):
    """An error answered in the SCIM Error schema (RFC 7644, section 3.12)."""

    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type


def error_document(status: int, detail: str, scim_type: str | None = None) -> JSONObject:
    document: JSONObject = {"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}
    if scim_type is not None:
        document["scimType"] = scim_type
    return document


def _syntax(detail: str) -> ScimError:
    return ScimError(400, detail, "invalidSyntax")


def _invalid(detail: str) -> ScimError:
    return ScimError(400, detail, "invalidValue")


def _lowered(document: Mapping[str, Any], what: str) -> dict[str, Any]:
    """Attribute names are case-insensitive: two spellings of one name are ambiguous."""
    lowered: dict[str, Any] = {}
    for key, value in document.items():
        name = key.lower()
        if name in lowered:
            raise _syntax(f"The {what} names {key!r} twice.")
        lowered[name] = value
    return lowered


def _has_schema(document: Mapping[str, Any], schema: str) -> bool:
    schemas = document.get("schemas")
    return isinstance(schemas, list) and any(
        isinstance(item, str) and item.lower() == schema.lower() for item in schemas
    )


def _text(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _invalid(f"{name} must be a string.")
    return value


def _boolean(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    # Microsoft Entra ID sends booleans as the strings "True" and "False".
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise _invalid(f"{name} must be a boolean.")


def _check_emails(value: Any) -> None:
    """``emails`` is accepted in its standard shape and otherwise ignored: the
    account's address is ``userName``."""
    if value is None:
        return
    items = value if isinstance(value, list) else [value]
    for item in items[:20]:
        if not isinstance(item, dict) or not isinstance(item.get("value", ""), str):
            raise _invalid("emails must be a list of objects with a string value.")


def parse_filter(raw: str | None) -> DirectoryFilter | None:
    if raw is None or not raw.strip():
        return None
    if len(raw) > _MAX_FILTER_LENGTH:
        raise ScimError(400, "The filter is too long.", "invalidFilter")
    match = _FILTER.fullmatch(raw)
    if match is None:
        raise ScimError(
            400,
            'Only "userName", "externalId" and "emails.value" with "eq" are supported.',
            "invalidFilter",
        )
    attribute = match[1].lower()
    if attribute.startswith(USER_SCHEMA.lower() + ":"):
        attribute = attribute[len(USER_SCHEMA) + 1 :]
    field = _FILTER_FIELDS.get(attribute)
    if field is None:
        raise ScimError(400, f"Filtering on {match[1]!r} is not supported.", "invalidFilter")
    try:
        value = json.loads(f'"{match[2]}"')
    except ValueError as exc:
        raise ScimError(400, "The filter value is not a valid string.", "invalidFilter") from exc
    if not isinstance(value, str) or len(value) > 255:
        raise ScimError(400, "The filter value is too long.", "invalidFilter")
    return DirectoryFilter(field=field, value=value)


def parse_user(body: JSONValue) -> DirectoryUserInput:
    """A full User representation (POST and PUT)."""
    if not isinstance(body, dict):
        raise _syntax("The body must be a JSON object.")
    document = _lowered(body, "resource")
    if not _has_schema(document, USER_SCHEMA):
        raise _syntax(f"schemas must include {USER_SCHEMA}.")
    if "password" in document:
        raise _invalid("Passwords are not accepted: people sign in at the identity provider.")
    user_name = _text(document.get("username"), "userName")
    if not user_name:
        raise _invalid("userName is required.")
    name = document.get("name")
    if name is not None and not isinstance(name, dict):
        raise _invalid("name must be an object.")
    parts = _lowered(name or {}, "name")
    _check_emails(document.get("emails"))
    return DirectoryUserInput(
        user_name=user_name,
        external_id=_text(document.get("externalid"), "externalId"),
        display_name=_text(document.get("displayname"), "displayName"),
        given_name=_text(parts.get("givenname"), "name.givenName"),
        family_name=_text(parts.get("familyname"), "name.familyName"),
        formatted_name=_text(parts.get("formatted"), "name.formatted"),
        active=_boolean(document["active"], "active") if "active" in document else True,
    )


def parse_patch(body: JSONValue) -> DirectoryUserChanges:
    """A PatchOp: ``add``/``replace`` of active, userName, externalId,
    displayName, name (and its parts) and emails."""
    if not isinstance(body, dict):
        raise _syntax("The body must be a JSON object.")
    document = _lowered(body, "request")
    if not _has_schema(document, PATCH_SCHEMA):
        raise _syntax(f"schemas must include {PATCH_SCHEMA}.")
    operations = document.get("operations")
    if not isinstance(operations, list) or not operations:
        raise _syntax("Operations must be a non-empty list.")
    if len(operations) > MAX_OPERATIONS:
        raise ScimError(400, f"At most {MAX_OPERATIONS} operations per request.", "tooMany")
    values: dict[str, Any] = {}
    for raw in operations:
        if not isinstance(raw, dict):
            raise _syntax("Each operation must be an object.")
        operation = _lowered(raw, "operation")
        op = operation.get("op")
        if not isinstance(op, str) or op.lower() not in ("add", "replace"):
            raise _invalid('Only the "add" and "replace" operations are supported.')
        path = operation.get("path")
        value = operation.get("value")
        if path is None:
            if not isinstance(value, dict):
                raise _invalid("An operation without a path needs an object value.")
            for key, item in value.items():
                _set(values, str(key), item)
        elif isinstance(path, str):
            _set(values, path, value)
        else:
            raise ScimError(400, "path must be a string.", "invalidPath")
    return DirectoryUserChanges(values)


# Simple attributes a PATCH may set: SCIM name -> (field, label).
_SIMPLE = {
    "username": ("user_name", "userName"),
    "externalid": ("external_id", "externalId"),
    "displayname": ("display_name", "displayName"),
}


def _set(values: dict[str, Any], path: str, value: Any) -> None:
    name = path.strip().lower()
    if name.startswith(USER_SCHEMA.lower() + ":"):
        name = name[len(USER_SCHEMA) + 1 :]
    if name == "password":
        raise _invalid("Passwords are not accepted: people sign in at the identity provider.")
    if name in _IGNORED_ATTRIBUTES or name.startswith("urn:"):
        return  # not stored here (an extension schema, or a core attribute not kept)
    if name == "active":
        values["active"] = _boolean(value, "active")
    elif name in _SIMPLE:
        field, label = _SIMPLE[name]
        text = _text(value, label)
        # userName cannot be removed: an empty one fails the address check.
        values[field] = (text or "") if field == "user_name" else text
    elif name == "name" or (name.startswith("name.") and name[5:] in _NAME_PARTS):
        _set_name(values, name, path, value)
    elif name == "emails":
        _check_emails(value)  # the account's address is userName (see above)
    elif _EMAIL_VALUE_PATH.fullmatch(name):
        _text(value, path)
    else:
        raise ScimError(400, f"Changing {path!r} is not supported.", "invalidPath")


def _set_name(values: dict[str, Any], name: str, path: str, value: Any) -> None:
    if name != "name":
        values[_NAME_PARTS[name[5:]]] = _text(value, path)
        return
    if not isinstance(value, dict):
        raise _invalid("name must be an object.")
    for part, item in _lowered(value, "name").items():
        if part in _NAME_PARTS:
            values[_NAME_PARTS[part]] = _text(item, f"name.{part}")


def _instant(value: datetime) -> str:
    return value.isoformat()


def user_resource(record: DirectoryUser, base_url: str) -> JSONObject:
    location = f"{base_url}/scim/v2/Users/{record.id}"
    resource: JSONObject = {
        "schemas": [USER_SCHEMA],
        "id": str(record.id),
        "userName": record.user_name,
        "emails": [{"value": record.user_name, "type": "work", "primary": True}],
        "active": record.active,
        "meta": {
            "resourceType": "User",
            "created": _instant(record.created_at),
            "lastModified": _instant(record.updated_at),
            "location": location,
        },
    }
    if record.external_id is not None:
        resource["externalId"] = record.external_id
    if record.display_name is not None:
        resource["displayName"] = record.display_name
    name: JSONObject = {
        key: value
        for key, value in (
            ("formatted", record.formatted_name),
            ("givenName", record.given_name),
            ("familyName", record.family_name),
        )
        if value is not None
    }
    if name:
        resource["name"] = name
    return resource


def list_response(resources: list[JSONValue], *, total: int, start_index: int) -> JSONObject:
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def service_provider_config(base_url: str, documentation: str) -> JSONObject:
    return {
        "schemas": [SERVICE_PROVIDER_SCHEMA],
        "documentationUri": documentation,
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_PAGE_SIZE},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "A NexusFlow SCIM token (nxp_...) in the Authorization header.",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{base_url}/scim/v2/ServiceProviderConfig",
        },
    }


def user_resource_type(base_url: str) -> JSONObject:
    return {
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "A member of the organization",
        "schema": USER_SCHEMA,
        "meta": {
            "resourceType": "ResourceType",
            "location": f"{base_url}/scim/v2/ResourceTypes/User",
        },
    }


def _attribute(
    name: str,
    *,
    kind: str = "string",
    required: bool = False,
    unique: str = "none",
    case_exact: bool = False,
    mutability: str = "readWrite",
    multi: bool = False,
    sub: list[JSONValue] | None = None,
) -> JSONObject:
    attribute: JSONObject = {
        "name": name,
        "type": kind,
        "multiValued": multi,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": unique,
    }
    if sub is not None:
        attribute["subAttributes"] = sub
    return attribute


def user_schema(base_url: str) -> JSONObject:
    """The attributes this service provider supports (RFC 7643, section 7)."""
    return {
        "schemas": [SCHEMA_SCHEMA],
        "id": USER_SCHEMA,
        "name": "User",
        "description": "User Account",
        "attributes": [
            _attribute("userName", required=True, unique="server", mutability="immutable"),
            _attribute(
                "name",
                kind="complex",
                sub=[
                    _attribute("formatted"),
                    _attribute("familyName"),
                    _attribute("givenName"),
                ],
            ),
            _attribute("displayName"),
            _attribute(
                "emails",
                kind="complex",
                multi=True,
                sub=[
                    _attribute("value"),
                    _attribute("type"),
                    _attribute("primary", kind="boolean"),
                ],
            ),
            _attribute("active", kind="boolean"),
            _attribute("externalId", case_exact=True),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": f"{base_url}/scim/v2/Schemas/{USER_SCHEMA}",
        },
    }
