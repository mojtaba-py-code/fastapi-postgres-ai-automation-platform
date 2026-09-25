"""HTML item extraction (``infrastructure.scraping.extraction``).

Scraped markup is hostile input: only text and the configured attributes leave
the parser, executable/hidden markup is discarded, link attributes become
absolute http(s) URLs (anything else is dropped), values are capped, and hitting
the item cap is reported as truncation. Selector validation guards source
configuration.
"""

from __future__ import annotations

from typing import Any

import pytest

from nexusflow.core.errors import InvalidInputError
from nexusflow.domain.sources.model import FieldExtraction, WebsiteConfig
from nexusflow.infrastructure.scraping.extraction import (
    MAX_VALUE_CHARS,
    extract_items,
    validate_selector,
)

PAGE_URL = "https://shop.example.com/catalog/page-2"


def _field(selector: str, attribute: str | None = None) -> FieldExtraction:
    return FieldExtraction(selector=selector, attribute=attribute)


def _config(item_selector: str = "li.product", **fields: FieldExtraction) -> WebsiteConfig:
    return WebsiteConfig(
        url="https://shop.example.com/catalog", item_selector=item_selector, fields=fields
    )


def _extract(
    html: str, config: WebsiteConfig, *, max_items: int = 50
) -> tuple[list[dict[str, Any]], bool]:
    return extract_items(html, config, base_url=PAGE_URL, max_items=max_items)


def _products(count: int) -> str:
    rows = "".join(f'<li class="product"><h2>Item {n}</h2></li>' for n in range(count))
    return f"<html><body><ul>{rows}</ul></body></html>"


class TestValidateSelector:
    @pytest.mark.parametrize(
        "selector",
        [
            "li.product",
            "li.product > a[href]",
            "div:nth-child(2n+1)",
            "a:not(.sponsored)",
            "ul li:has(> span.price)",
            "[data-sku]",
            "table tr td:nth-of-type(3)",
        ],
    )
    def test_valid_selectors_are_accepted(self, selector: str) -> None:
        validate_selector(selector)

    @pytest.mark.parametrize(
        "selector",
        ["li[", "::", "a >>> b", ":unknown-pseudo", "div:nth-child(", "", "a,", "#", "<script>"],
    )
    def test_invalid_selectors_are_rejected_as_invalid_input(self, selector: str) -> None:
        with pytest.raises(InvalidInputError) as exc:
            validate_selector(selector)
        assert exc.value.code == "invalid_selector"
        assert repr(selector) in exc.value.message

    def test_error_message_quotes_a_bounded_prefix_of_the_selector(self) -> None:
        selector = "[" + "a" * 500
        with pytest.raises(InvalidInputError) as exc:
            validate_selector(selector)
        assert "a" * 79 in exc.value.message
        assert "a" * 80 not in exc.value.message
        assert len(exc.value.message) < 120


class TestExtractItems:
    def test_extracts_text_and_attributes_for_each_item(self) -> None:
        html = """
        <ul>
          <li class="product" data-sku="A-1">
            <h2>  Blue <b>Widget</b>  </h2>
            <span class="price">EUR 9.99</span>
            <a href="/p/a-1?ref=list">details</a>
            <img src="img/a-1.png" data-src="//cdn.example.net/a-1.webp" alt="Blue widget">
          </li>
          <li class="product">
            <h2>Red Widget</h2>
            <a href="https://cdn.example.net/p/b-2">details</a>
          </li>
        </ul>
        """
        config = _config(
            title=_field("h2"),
            price=_field(".price"),
            link=_field("a", "href"),
            image=_field("img", "src"),
            lazy_image=_field("img", "data-src"),
            alt=_field("img", "alt"),
        )

        items, truncated = _extract(html, config)

        assert items == [
            {
                "title": "Blue Widget",
                "price": "EUR 9.99",
                "link": "https://shop.example.com/p/a-1?ref=list",
                "image": "https://shop.example.com/catalog/img/a-1.png",
                "lazy_image": "https://cdn.example.net/a-1.webp",
                "alt": "Blue widget",
            },
            {"title": "Red Widget", "link": "https://cdn.example.net/p/b-2"},
        ]
        assert truncated is False

    def test_text_attribute_is_the_same_as_no_attribute(self) -> None:
        html = '<div class="card"><p class="name"> Blue\n  <i>Widget</i> </p></div>'
        implicit = _extract(html, _config("div.card", name=_field("p.name")))
        explicit = _extract(html, _config("div.card", name=_field("p.name", "text")))
        assert implicit == explicit == ([{"name": "Blue Widget"}], False)

    @pytest.mark.security
    def test_script_style_noscript_and_template_content_never_leaks_into_values(self) -> None:
        html = """
        <div class="card">
          <p class="name">Visible<script>document.cookie</script><style>.x{}</style>
          <noscript>enable javascript</noscript><template><b>hidden</b></template></p>
          <script class="payload">steal()</script>
        </div>
        """
        config = _config("div.card", name=_field("p.name"), payload=_field("script.payload"))
        assert _extract(html, config) == ([{"name": "Visible"}], False)

    @pytest.mark.security
    def test_only_text_is_kept_from_nested_markup(self) -> None:
        html = '<div class="card"><h2><img src=x onerror="alert(1)"><a href="#">Name</a></h2></div>'
        [item], _ = _extract(html, _config("div.card", name=_field("h2")))
        assert item == {"name": "Name"}

    @pytest.mark.security
    @pytest.mark.parametrize(
        "href",
        [
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "  javascript:alert(1)",
            "java&#9;script:alert(1)",
            "&#x6a;avascript:alert(1)",
            "vbscript:msgbox(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "file:///etc/passwd",
            "mailto:sales@example.com",
            "ftp://files.example.com/price-list.csv",
        ],
    )
    def test_non_http_links_are_dropped(self, href: str) -> None:
        html = f'<div class="card"><h2>Widget</h2><a href="{href}">buy</a></div>'
        config = _config("div.card", title=_field("h2"), link=_field("a", "href"))
        assert _extract(html, config) == ([{"title": "Widget"}], False)

    @pytest.mark.parametrize(
        ("markup", "attribute", "expected"),
        [
            ('<a href="../sale/7">x</a>', "href", "https://shop.example.com/sale/7"),
            ('<a href="?page=3">x</a>', "href", "https://shop.example.com/catalog/page-2?page=3"),
            ('<a href="//cdn.example.net/x">x</a>', "href", "https://cdn.example.net/x"),
            ('<a href=" item/7 ">x</a>', "href", "https://shop.example.com/catalog/item/7"),
            ('<img src="/i/7.png">', "src", "https://shop.example.com/i/7.png"),
            (
                '<img data-src="lazy/7.png">',
                "data-src",
                "https://shop.example.com/catalog/lazy/7.png",
            ),
            ('<form action="/cart/add"></form>', "action", "https://shop.example.com/cart/add"),
        ],
    )
    def test_url_attributes_are_resolved_against_the_page_url(
        self, markup: str, attribute: str, expected: str
    ) -> None:
        html = f'<div class="card">{markup}</div>'
        tag = markup[1 : markup.index(" ")]
        config = _config("div.card", value=_field(tag, attribute))
        assert _extract(html, config) == ([{"value": expected}], False)

    def test_other_attributes_are_returned_verbatim(self) -> None:
        html = """
        <div class="card">
          <span class="badge  new sale" title="In stock (3 left)" data-sku="SKU-001"
                data-price="19.90">x</span>
        </div>
        """
        config = _config(
            "div.card",
            classes=_field("span", "class"),
            title=_field("span", "title"),
            sku=_field("span", "data-sku"),
            price=_field("span", "data-price"),
        )
        assert _extract(html, config) == (
            [
                {
                    "classes": "badge new sale",
                    "title": "In stock (3 left)",
                    "sku": "SKU-001",
                    "price": "19.90",
                }
            ],
            False,
        )

    def test_missing_and_blank_fields_are_omitted_and_empty_items_skipped(self) -> None:
        html = """
        <ul>
          <li class="product"><h2>Only a title</h2></li>
          <li class="product"><h2>   </h2><span class="price"></span></li>
          <li class="product"><span class="price">5.00</span><a>no href</a></li>
        </ul>
        """
        config = _config(title=_field("h2"), price=_field(".price"), link=_field("a", "href"))
        assert _extract(html, config) == (
            [{"title": "Only a title"}, {"price": "5.00"}],
            False,
        )

    def test_values_are_capped(self) -> None:
        long_text = "x" * (MAX_VALUE_CHARS + 500)
        long_attribute = "y" * (MAX_VALUE_CHARS * 2)
        html = f'<div class="card"><p data-note="{long_attribute}">{long_text}</p></div>'
        config = _config("div.card", text=_field("p"), note=_field("p", "data-note"))
        [item], _ = _extract(html, config)
        assert item == {"text": "x" * MAX_VALUE_CHARS, "note": "y" * MAX_VALUE_CHARS}

    @pytest.mark.parametrize(
        ("available", "max_items", "expected_count", "truncated"),
        [(3, 5, 3, False), (3, 3, 3, False), (5, 3, 3, True), (1, 1, 1, False), (2, 1, 1, True)],
    )
    def test_item_cap_and_truncation_flag(
        self, available: int, max_items: int, expected_count: int, truncated: bool
    ) -> None:
        items, was_truncated = _extract(
            _products(available), _config(title=_field("h2")), max_items=max_items
        )
        assert items == [{"title": f"Item {n}"} for n in range(expected_count)]
        assert was_truncated is truncated

    def test_malformed_markup_is_tolerated(self) -> None:
        html = '<ul><li class="product"><h2>Alpha<li class="product"><h2>Beta</ul><p>tail'
        items, _ = _extract(html, _config(title=_field("h2")))
        assert items == [{"title": "Alpha"}, {"title": "Beta"}]

    def test_no_matching_containers_yields_nothing(self) -> None:
        assert _extract(
            "<html><body><p>Closed for inventory</p></body></html>", _config(title=_field("h2"))
        ) == ([], False)
