"""HTML item extraction with CSS selectors (BeautifulSoup + soupsieve).

Scraped HTML is hostile input: it is parsed (never rendered or executed) in the
isolated sandbox worker, only text and selected attributes are extracted, and
link attributes are resolved to absolute http(s) URLs only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

import soupsieve
from bs4 import BeautifulSoup, Tag

from nexusflow.core.errors import InvalidInputError
from nexusflow.domain.sources.model import WebsiteConfig

_URL_ATTRIBUTES = frozenset({"href", "src", "data-src", "action"})
MAX_VALUE_CHARS = 10_000


def validate_selector(selector: str) -> None:
    """Compile a CSS selector; raises ``InvalidInputError`` if it is invalid."""
    try:
        soupsieve.compile(selector)
    except (soupsieve.SelectorSyntaxError, ValueError, TypeError) as exc:
        raise InvalidInputError(
            f"Invalid CSS selector: {selector[:80]!r}", code="invalid_selector"
        ) from exc


def _attribute_value(element: Tag, attribute: str, base_url: str) -> str | None:
    raw: Any = element.get(attribute)
    if raw is None:
        return None
    value = " ".join(raw) if isinstance(raw, list) else str(raw)
    if attribute in _URL_ATTRIBUTES:
        absolute = urljoin(base_url, value.strip())
        if urlsplit(absolute).scheme not in ("http", "https"):
            return None  # drop javascript:, data:, file: and friends
        return absolute
    return value


def extract_items(
    html: str, config: WebsiteConfig, *, base_url: str, max_items: int
) -> tuple[list[dict[str, Any]], bool]:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    containers = soup.select(config.item_selector, limit=max_items + 1)
    items: list[dict[str, Any]] = []
    for container in containers[:max_items]:
        item: dict[str, Any] = {}
        for name, spec in config.fields.items():
            element = container.select_one(spec.selector)
            if element is None:
                continue
            if spec.attribute in (None, "text"):
                value: str | None = element.get_text(" ", strip=True)
            else:
                value = _attribute_value(element, spec.attribute, base_url)
            if value:
                item[name] = value[:MAX_VALUE_CHARS]
        if item:
            items.append(item)
    return items, len(containers) > max_items
