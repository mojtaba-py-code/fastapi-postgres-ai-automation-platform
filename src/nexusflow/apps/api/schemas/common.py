"""Shared API schema building blocks.

* Request models forbid unknown fields (``extra="forbid"``): clients cannot
  smuggle server-controlled attributes (``org_id``, ``role``, ``status``...) into
  a request - the classic mass-assignment vulnerability.
* Response models are explicit allowlists of fields; domain entities are never
  serialized directly, so new columns (hashes, secrets) cannot leak by accident.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class ResponseModel(BaseModel):
    model_config = ConfigDict(
        from_attributes=True, frozen=True, validate_by_name=True, validate_by_alias=True
    )


class PageResponse[T](ResponseModel):
    items: list[T]
    next_cursor: str | None


class ErrorItem(ResponseModel):
    field: str | None
    message: str
    code: str


class ErrorResponse(ResponseModel):
    error: str
    message: str
    request_id: str | None
    details: list[ErrorItem] | None = None


ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse, "description": "Missing or invalid credentials"},
    403: {"model": ErrorResponse, "description": "Not permitted"},
    404: {"model": ErrorResponse, "description": "Not found (or not visible to this tenant)"},
    422: {"model": ErrorResponse, "description": "Validation failed"},
    429: {"model": ErrorResponse, "description": "Rate limited"},
}
