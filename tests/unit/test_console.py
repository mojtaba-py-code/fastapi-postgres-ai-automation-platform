"""Static checks of the web console (./web).

Its behaviour is tested with Node's own test runner (tests/web/*.test.mjs) and
in a real browser against the running stack (tests/e2e/test_console.py). These
checks need neither: they pin what must hold for every change -

* no code path turns data into HTML or script (no HTML sinks, no eval, no
  inline handlers, no inline script or style in the document), and nothing is
  loaded from another origin - the edge's Content-Security-Policy (with
  Trusted Types) would break the page if it were;
* every API call the console makes names a route the API has, with a method
  it accepts;
* the role matrix the console shows or hides pages by is the API's own;
* the pages e-mails and identity providers link to are the ones the console,
  the edge and the development server serve.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fakeredis import FakeAsyncRedis

from nexusflow.apps.api.main import create_app
from nexusflow.domain.authorization.roles import ROLE_PERMISSIONS
from tests.conftest import make_settings

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
SCRIPTS = sorted((WEB / "assets" / "js").rglob("*.js"))


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(path: Path) -> str:
    """The script without its comments (a comment may name a sink it avoids)."""
    text = re.sub(r"/\*.*?\*/", "", _source(path), flags=re.DOTALL)
    return "\n".join(re.sub(r"(^|[^:\"'`])//.*$", r"\1", line) for line in text.splitlines())


def test_the_console_is_all_there() -> None:
    assert (WEB / "index.html").is_file()
    assert (WEB / "assets" / "css" / "console.css").is_file()
    names = {path.name for path in SCRIPTS}
    assert {
        "main.js",
        "api.js",
        "dom.js",
        "router.js",
        "session.js",
        "webauthn.js",
        "qr.js",
    } <= names


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda path: path.name)
def test_no_script_turns_data_into_html_or_code(path: Path) -> None:
    code = _code(path)
    forbidden = {
        "innerHTML": r"\.innerHTML\b",
        "outerHTML": r"\.outerHTML\b",
        "insertAdjacentHTML": r"insertAdjacentHTML",
        "document.write": r"document\.write",
        "eval": r"\beval\s*\(",
        "new Function": r"new\s+Function\s*\(",
        "string timers": r"set(?:Timeout|Interval)\(\s*['\"`]",
        "style attribute": r"setAttribute\(\s*['\"]style['\"]",
        "on* attribute": r"setAttribute\(\s*['\"]on",
        "javascript: URL": r"""["'`]\s*javascript:""",
        "DOMParser / createContextualFragment": r"DOMParser|createContextualFragment",
    }
    found = [name for name, pattern in forbidden.items() if re.search(pattern, code)]
    assert not found, f"{path.name}: {found}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda path: path.name)
def test_failures_are_shown_with_the_consoles_guidance(path: Path) -> None:
    # errorMessage() says what to do (rate limits, passkey policies, a lost
    # connection); a section that showed error.message told a person only that
    # the edge had had "too many requests".
    assert not re.search(r"notice\(\s*error\.message\b", _code(path)), path.name


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda path: path.name)
def test_scripts_import_only_the_consoles_own_modules(path: Path) -> None:
    for target in re.findall(
        r"""^\s*(?:import|export)\b[^;]*?from\s+["']([^"']+)["']""",
        _source(path),
        flags=re.MULTILINE,
    ):
        assert target.startswith(("./", "../")), f"{path.name} imports {target}"
    assert not re.search(r"\bimport\s*\(", _code(path)), f"{path.name}: dynamic import"


def test_the_document_has_no_inline_code_or_foreign_resources() -> None:
    html = _source(WEB / "index.html")
    assert re.findall(r"<script\b[^>]*>", html) == [
        '<script type="module" src="/assets/js/main.js">'
    ]
    assert "<style" not in html
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler"
    assert not re.search(r"""(?:src|href)\s*=\s*["'](?:https?:)?//""", html), (
        "a resource from another origin"
    )
    css = _source(WEB / "assets" / "css" / "console.css")
    assert not re.search(r"@import|url\(\s*['\"]?(?:https?:)?//", css), (
        "a stylesheet resource from another origin"
    )


def test_the_role_matrix_is_the_apis() -> None:
    source = _source(WEB / "assets" / "js" / "permissions.js")
    literal = source.split("export const ROLE_PERMISSIONS = ", 1)[1].split(";\n", 1)[0]
    console = {role: set(permissions) for role, permissions in json.loads(literal).items()}
    api = {
        role.value: {p.value for p in permissions} for role, permissions in ROLE_PERMISSIONS.items()
    }
    assert console == api


# ------------------------------------------------------------------ API calls

_CALL = re.compile(
    r"""api\.(get|post|put|patch|delete|download|upload)\(\s*(`[^`]*`|"[^"]*")"""
    r"""|api\.request\(\s*"(GET|POST|PUT|PATCH|DELETE)",\s*(`[^`]*`|"[^"]*")"""
)
_METHOD = {
    "get": "get",
    "download": "get",
    "post": "post",
    "upload": "post",
    "put": "put",
    "patch": "patch",
    "delete": "delete",
}


def _calls() -> list[tuple[str, str, str]]:
    calls = []
    for path in SCRIPTS:
        for match in _CALL.finditer(_source(path)):
            verb, literal = (
                (match.group(1), match.group(2))
                if match.group(1)
                else (match.group(3).lower(), match.group(4))
            )
            route = re.sub(r"\$\{[^}]+\}", "{param}", literal.strip('`"'))
            calls.append((path.name, _METHOD[verb], route))
    return calls


@pytest.fixture(scope="module")
def api_routes() -> dict[str, set[str]]:
    app = create_app(make_settings(), configure_logs=False, redis=FakeAsyncRedis())
    routes: dict[str, set[str]] = {}
    for path, operations in app.openapi()["paths"].items():
        if path.startswith("/api/v1/"):
            routes[re.sub(r"\{[^}]+\}", "{param}", path.removeprefix("/api/v1"))] = set(operations)
    return routes


def test_the_console_calls_the_api() -> None:
    assert len(_calls()) > 60  # the pattern still finds the calls


def test_every_api_call_names_a_route_and_method_the_api_has(
    api_routes: dict[str, set[str]],
) -> None:
    missing = [
        f"{name}: {method.upper()} {route}"
        for name, method, route in _calls()
        if method not in api_routes.get(route, set())
    ]
    assert not missing, missing


# ------------------------------------------------------------------ entry points


def _router_entry_paths() -> list[str]:
    source = _source(WEB / "assets" / "js" / "router.js")
    block = source.split("export const ENTRY_PATHS = Object.freeze([", 1)[1].split("]);", 1)[0]
    return re.findall(r'"([^"]+)"', block)


def test_every_page_the_platform_links_to_is_served_by_the_console() -> None:
    linked = set(
        re.findall(
            r'f"\{self\._base\}(/[a-z/-]+)#token=',
            _source(ROOT / "src" / "nexusflow" / "domain" / "identity" / "security_emails.py"),
        )
    )
    assert linked == {"/reset-password", "/complete-signup", "/accept-invitation"}
    assert '"/sso/callback"' in _source(
        ROOT / "src" / "nexusflow" / "domain" / "identity" / "sso_service.py"
    )
    entries = set(_router_entry_paths())
    assert entries == linked | {"/sso/callback"}
    # The edge serves the console's document on each of them...
    conf = _source(ROOT / "deploy" / "nginx" / "nginx.conf")
    [alternatives] = re.findall(
        r"location ~ \^/\(([^)]+)\)\$ \{\s*include /etc/nginx/snippets/console\.conf;", conf
    )
    assert {f"/{path}" for path in alternatives.split("|")} == entries
    # ...and so does the development server.
    dev = _source(ROOT / "scripts" / "dev_console.py")
    [listed] = re.findall(r"ENTRY_PATHS = \(([^)]+)\)", dev)
    assert set(re.findall(r'"([^"]+)"', listed)) == entries


def test_the_development_server_sends_the_edges_console_headers() -> None:
    from scripts.dev_console import console_headers  # it adjusts sys.path on import

    headers = console_headers()
    assert "require-trusted-types-for 'script'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" not in headers  # plain http on localhost
