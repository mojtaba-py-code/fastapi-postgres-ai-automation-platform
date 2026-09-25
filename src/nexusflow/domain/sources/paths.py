"""Tiny, safe JSON path resolver (``data.items[0].price``).

Deliberately minimal: no wildcards, filters or expressions - nothing that
could be abused for expensive evaluation. Paths are validated against
``JSON_PATH`` when a source is configured.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from nexusflow.core.errors import InvalidInputError

_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
_MISSING = object()


def resolve_path(document: Any, path: str) -> Any:
    """Return the value at ``path`` or ``None`` when any segment is missing."""
    current = document
    for name, index in _TOKEN.findall(path):
        if name:
            if not isinstance(current, Mapping):
                return None
            current = current.get(name, _MISSING)
        else:
            if not isinstance(current, Sequence) or isinstance(current, (str, bytes)):
                return None
            position = int(index)
            current = current[position] if position < len(current) else _MISSING
        if current is _MISSING:
            return None
    return current


def extract_items(
    document: Any, items_path: str | None, *, max_items: int
) -> tuple[list[Any], bool]:
    """Locate the item list; returns ``(items, truncated)``."""
    container = resolve_path(document, items_path) if items_path else document
    if isinstance(container, Mapping):
        container = [container]
    if not isinstance(container, list):
        raise InvalidInputError(
            "The payload does not contain an item list.", code="items_not_found"
        )
    return container[:max_items], len(container) > max_items


def map_fields(item: Any, mapping: Mapping[str, str]) -> dict[str, Any]:
    """Project an item onto dataset fields; unmapped attributes are dropped."""
    if not isinstance(item, Mapping):
        return {}
    projected: dict[str, Any] = {}
    for target, path in mapping.items():
        value = resolve_path(item, path)
        if isinstance(value, (Mapping, list)):
            continue  # only scalar values are mapped onto dataset fields
        projected[target] = value
    return projected
