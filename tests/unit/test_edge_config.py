"""Static checks of the nginx edge configuration.

nginx refuses to start when a directive that takes one value appears twice in
the same block - including once directly and once through an ``include``d
snippet. CI also runs ``nginx -t``; this check needs no Docker, so it runs
everywhere, and it pins the edge's security invariants.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pytest

NGINX = Path(__file__).resolve().parents[2] / "deploy" / "nginx"

# Directives nginx accepts more than once in one block (the rest take one value).
_REPEATABLE = {
    "access_log", "add_header", "allow", "deny", "error_log", "error_page", "include",
    "limit_conn", "limit_conn_zone", "limit_req", "limit_req_zone", "listen", "location",
    "log_format", "map", "proxy_hide_header", "proxy_set_header", "server", "set",
    "ssl_certificate", "ssl_certificate_key", "upstream",
}  # fmt: skip
_TOKEN = re.compile(r"""'[^']*'|"[^"]*"|[{};]|[^\s{};'"]+""")


@dataclass
class Block:
    name: str
    directives: list[list[str]] = field(default_factory=list)
    children: list[Block] = field(default_factory=list)


def _tokens(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    text = "\n".join(line.split("#", 1)[0] for line in lines)
    return _TOKEN.findall(text)


def _parse(path: Path) -> Block:
    """Parse ``path`` into nested blocks, expanding the edge's own snippets."""
    root = Block("main")
    stack = [root]
    words: list[str] = []
    pending = list(_tokens(path))
    while pending:
        token = pending.pop(0)
        if token == "{":
            child = Block(" ".join(words))
            stack[-1].children.append(child)
            stack.append(child)
            words = []
        elif token == "}":
            stack.pop()
        elif token == ";":
            if words[0] == "include" and words[1].startswith("/etc/nginx/snippets/"):
                pending[:0] = _tokens(NGINX / "snippets" / Path(words[1]).name)
            else:
                stack[-1].directives.append(words)
            words = []
        else:
            words.append(token)
    assert stack == [root], "unbalanced braces"
    return root


def _blocks(block: Block) -> list[Block]:
    return [block, *(b for child in block.children for b in _blocks(child))]


@pytest.fixture(scope="module")
def config() -> Block:
    return _parse(NGINX / "nginx.conf")


def test_no_single_value_directive_is_repeated_in_a_block(config: Block) -> None:
    for block in _blocks(config):
        if block.name.startswith(("map ", "types")):
            continue  # key-value tables, not directives
        counts = Counter(d[0] for d in block.directives if d[0] not in _REPEATABLE)
        repeated = sorted(name for name, n in counts.items() if n > 1)
        assert not repeated, f"'{block.name}' repeats {repeated}: nginx would refuse to start"


def test_every_api_location_proxies_through_the_shared_snippet(config: Block) -> None:
    [api] = [b for b in _blocks(config) if any(d[:2] == ["listen", "8443"] for d in b.directives)]
    for location in api.children:
        directives = {d[0]: d[1:] for d in location.directives}
        if "return" in directives:
            continue  # the paths the edge never exposes
        assert directives.get("proxy_pass") == ["http://api"], location.name
        # The snippet overwrites X-Forwarded-For: a client cannot choose its own address.
        assert ["proxy_set_header", "X-Forwarded-For", "$remote_addr"] in location.directives
        assert "proxy_read_timeout" in directives or any(
            d[0] == "proxy_read_timeout" for d in api.directives
        )


def test_internal_and_diagnostic_paths_are_never_exposed(config: Block) -> None:
    [api] = [b for b in _blocks(config) if any(d[:2] == ["listen", "8443"] for d in b.directives)]
    hidden = {
        location.name for location in api.children if ["return", "404"] in location.directives
    }
    assert hidden >= {
        "location = /metrics",
        "location ^~ /internal/",
        "location ^~ /docs",
        "location = /openapi.json",
    }


def test_snippets_are_checked_as_part_of_the_block_that_includes_them(tmp_path: Path) -> None:
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "http { server { location / { proxy_read_timeout 300s;"
        " include /etc/nginx/snippets/proxy.conf; } } }",
        encoding="utf-8",
    )
    [location] = [b for b in _blocks(_parse(conf)) if b.name == "location /"]
    names = [d[0] for d in location.directives]
    assert "proxy_pass" in names  # expanded from the snippet
    # A location may raise the read timeout: the shared snippet does not set it.
    assert names.count("proxy_read_timeout") == 1
