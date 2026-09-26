"""The web console as the edge serves it: one document with a strict policy
of its own, its assets, and the pages e-mails and identity providers link to.
(tests/e2e/console_smoke.py drives the same console in a real browser.)"""

from __future__ import annotations

import re

import httpx2
import pytest

ENTRY_PATHS = ["/", "/complete-signup", "/reset-password", "/accept-invitation", "/sso/callback"]


def _policy(response: httpx2.Response) -> dict[str, str]:
    header = response.headers["content-security-policy"]
    return dict(part.strip().split(" ", 1) for part in header.split(";"))


@pytest.mark.parametrize("path", ENTRY_PATHS)
def test_every_entry_point_serves_the_console_with_its_policy(
    client: httpx2.Client, path: str
) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert '<script type="module" src="/assets/js/main.js">' in response.text
    policy = _policy(response)
    assert policy["default-src"] == "'none'"
    assert policy["script-src"] == policy["style-src"] == policy["connect-src"] == "'self'"
    assert policy["require-trusted-types-for"] == "'script'"
    assert policy["trusted-types"] == "'none'"
    assert policy["frame-ancestors"] == "'none'"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    for name in (
        "content-security-policy",
        "x-frame-options",
        "cache-control",
        "strict-transport-security",
    ):
        assert len(response.headers.get_list(name)) == 1, name  # set once, not stacked


def test_assets_are_served_with_their_types_and_revalidated(client: httpx2.Client) -> None:
    script = client.get("/assets/js/main.js")
    assert script.status_code == 200
    assert re.match(r"(application|text)/javascript", script.headers["content-type"])
    assert script.headers["cache-control"] == "no-cache"
    etag = script.headers["etag"]
    assert client.get("/assets/js/main.js", headers={"If-None-Match": etag}).status_code == 304
    style = client.get("/assets/css/console.css")
    assert style.headers["content-type"].startswith("text/css")
    assert client.get("/assets/js/no-such-module.js").status_code == 404


def test_the_console_needs_nothing_from_another_origin(client: httpx2.Client) -> None:
    html = client.get("/").text
    assert not re.search(r"""(?:src|href)=["'](?:https?:)?//""", html)
    main = client.get("/assets/js/main.js").text
    assert not re.search(r"""from\s+["'](?:https?:)?//""", main)


def test_the_api_stays_json_next_to_the_console(client: httpx2.Client) -> None:
    response = client.get("/api/v1/projects")  # proxied as before
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/json")
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert client.get("/nothing-here").json()["error"] == "not_found"
