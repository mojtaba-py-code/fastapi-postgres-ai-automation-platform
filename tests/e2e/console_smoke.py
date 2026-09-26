"""The web console in a real browser (Chromium, through Playwright) against the
running stack: sign up from the e-mailed link, feed the stack a small partner
catalogue through its signed webhook (the workers turn it into records, changes
and alerts), use the main pages, sign out and in again - with not one console
error, uncaught exception or blocked resource. The console runs under a strict
Content-Security-Policy with Trusted Types, so a violation would break it.

CI runs it in the Playwright image the browser service is built on:

    docker run --rm --network host -v "$PWD:/work:ro" -w /work -e NEXUSFLOW_E2E_... \
        <playwright image> python3 tests/e2e/console_smoke.py

It needs only the standard library and Playwright. Environment:
NEXUSFLOW_E2E_BASE_URL, NEXUSFLOW_E2E_MAILPIT_URL, NEXUSFLOW_E2E_CA_BUNDLE (the
stack's development CA, for the requests made from here), and CONSOLE_SCREENSHOTS
(a directory for screenshots of a few pages, light and dark).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from playwright.sync_api import Page, expect, sync_playwright

BASE = os.environ["NEXUSFLOW_E2E_BASE_URL"].rstrip("/")
MAILPIT = os.environ["NEXUSFLOW_E2E_MAILPIT_URL"].rstrip("/")
CA_BUNDLE = os.environ.get("NEXUSFLOW_E2E_CA_BUNDLE")
SHOTS = Path(os.environ["CONSOLE_SCREENSHOTS"]) if os.environ.get("CONSOLE_SCREENSHOTS") else None
PASSWORD = "a console passphrase for CI 1"  # a throwaway CI account  # nosec B105
TLS = ssl.create_default_context(cafile=CA_BUNDLE) if CA_BUNDLE else ssl.create_default_context()
# API answers the pages expect and handle (the browser still logs them as failed loads).
EXPECTED_ERRORS = {"/api/v1/organizations/current/sso"}  # 404 sso_not_configured

SCHEMA = {
    "fields": [
        {"name": "sku", "type": "string", "required": True, "description": "Product SKU"},
        {"name": "title", "type": "string", "required": True},
        {"name": "price", "type": "decimal", "description": "Price in EUR"},
        {"name": "in_stock", "type": "boolean"},
        {"name": "url", "type": "url"},
    ],
    "key_field": "sku",
    "change_policy": {
        "numeric_thresholds": {"price": {"medium_pct": 5, "high_pct": 10, "critical_pct": 25}}
    },
}
MAPPING = {"sku": "sku", "title": "name", "price": "price.amount", "in_stock": "stock.available"}
CATALOGUE = [
    ("NX-100", "Aurora Desk Lamp", "49.90", "55.90", True),
    ("NX-101", "Nimbus Office Chair", "219.00", "199.00", True),
    ("NX-102", "Vertex Standing Desk", "499.00", "649.00", True),
    ("NX-103", "Pulse Wireless Mouse", "29.90", "29.90", True),
    ("NX-104", "Echo Noise-Cancelling Headset", "149.00", "149.00", False),
    ("NX-105", "Atlas Monitor Arm", "89.00", "92.50", True),
]


def request(
    path: str, *, data: Any = None, token: str | None = None, headers: dict[str, str] | None = None
) -> Any:
    body = (
        data
        if isinstance(data, bytes)
        else (json.dumps(data).encode() if data is not None else None)
    )
    sent = {"Content-Type": "application/json", "Accept": "application/json", **(headers or {})}
    if token:
        sent["Authorization"] = f"Bearer {token}"
    url = path if path.startswith("http") else BASE + path
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"not an http(s) URL: {url}")
    method = "POST" if body is not None else "GET"
    call = urllib.request.Request(url, data=body, headers=sent, method=method)  # noqa: S310 - http(s) only
    context = TLS if url.startswith("https://") else None
    with urllib.request.urlopen(call, context=context, timeout=30) as response:  # noqa: S310  # nosec B310
        raw = response.read()
        return json.loads(raw) if raw else None


def signup_link(email: str) -> str:
    """The path of the sign-up link mailed to ``email`` (read from Mailpit)."""
    deadline = time.monotonic() + 90
    query = urllib.parse.quote(f'to:"{email}"')
    while time.monotonic() < deadline:
        for message in request(f"{MAILPIT}/api/v1/search?query={query}").get("messages", []):
            text = request(f"{MAILPIT}/api/v1/message/{message['ID']}").get("Text", "")
            match = re.search(r"(/complete-signup#token=[A-Za-z0-9_-]+)", text)
            if match:
                return match[1]
        time.sleep(1)
    raise SystemExit(f"no sign-up e-mail for {email} in Mailpit")


def until(check: Any, what: str, timeout: float = 90) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(1)
    raise SystemExit(f"timed out waiting for {what}")


def feed_the_stack(email: str) -> None:
    """A partner catalogue through the stack's signed webhook, twice: the workers
    create the records, then detect the changes and raise the alerts."""
    token = request("/api/v1/auth/login", data={"email": email, "password": PASSWORD})[
        "access_token"
    ]
    project = request(
        "/api/v1/projects",
        data={"name": "Competitor pricing", "description": "Office furniture competitors"},
        token=token,
    )
    dataset = request(
        "/api/v1/datasets",
        data={
            "project_id": project["id"],
            "name": "Competitor catalogue",
            "schema": SCHEMA,
            "classification": "internal",
            "retention_days": 365,
        },
        token=token,
    )
    source = request(
        "/api/v1/sources",
        data={
            "project_id": project["id"],
            "dataset_id": dataset["id"],
            "name": "Partner feed",
            "config": {"kind": "webhook", "items_path": "products", "field_mapping": MAPPING},
        },
        token=token,
    )
    endpoint = request(
        "/api/v1/webhook-endpoints",
        data={"source_id": source["id"], "name": "partner-feed"},
        token=token,
    )
    for name, severity, condition in (
        (
            "Price up 10 % or more",
            "critical",
            {"type": "numeric_change", "field": "price", "direction": "increase", "min_pct": 10},
        ),
        ("Availability changed", "warning", {"type": "field_changed", "field": "in_stock"}),
    ):
        request(
            "/api/v1/alert-rules",
            data={
                "project_id": project["id"],
                "dataset_id": dataset["id"],
                "name": name,
                "condition": condition,
                "severity": severity,
            },
            token=token,
        )

    path = urllib.parse.urlsplit(endpoint["url"]).path
    for snapshot in (0, 1):
        products = [
            {
                "sku": sku,
                "name": name,
                "price": {"amount": (first, second)[snapshot], "currency": "EUR"},
                "stock": {"available": in_stock or snapshot == 0},
            }
            for sku, name, first, second, in_stock in CATALOGUE
        ]
        body = json.dumps({"products": products}).encode()
        delivery, stamp = f"console-{uuid.uuid4().hex}", int(time.time())
        mac = hmac.new(
            endpoint["secret"].encode(), f"{stamp}.{delivery}.".encode() + body, hashlib.sha256
        ).hexdigest()
        request(
            path,
            data=body,
            headers={
                "X-NexusFlow-Delivery": delivery,
                "X-NexusFlow-Signature": f"t={stamp},v1={mac}",
            },
        )
        expected = len(CATALOGUE) if snapshot == 0 else len(CATALOGUE) + 4
        until(
            lambda n=expected: len(request("/api/v1/changes?limit=50", token=token)["items"]) >= n,
            "the changes",
        )
    until(lambda: request("/api/v1/alerts?status=open", token=token)["items"], "the alerts")


def shot(page: Page, name: str) -> None:
    if SHOTS:
        SHOTS.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(SHOTS / f"{name}.png"), full_page=True)


def nav(page: Page, label: str) -> None:
    page.get_by_role("navigation", name="Main").get_by_role("link", name=label, exact=True).click()
    expect(page.get_by_role("heading", level=1)).to_be_visible()


def overview(page: Page, org: str) -> None:
    nav(page, "Overview")
    expect(page.get_by_role("heading", level=1, name=org)).to_be_visible()
    page.get_by_label("Project", exact=True).select_option(label="Competitor pricing")
    expect(page.locator(".chart-bar[d^='M']").first).to_be_attached()
    expect(page.get_by_role("main").get_by_text("Price up 10 % or more").first).to_be_visible()


def sign_in(page: Page, email: str, org: str) -> None:
    page.get_by_label("E-mail address").fill(email)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.get_by_role("heading", level=1, name=org)).to_be_visible()


def run(page: Page, org: str, email: str) -> None:
    # Sign up the way a person does: the address first, then the e-mailed link.
    assert request("/api/v1/auth/register", data={"email": email})["status"] == "check_email"
    page.goto(BASE + signup_link(email))
    expect(page.get_by_role("heading", name="Finish creating your account")).to_be_visible()
    assert "token" not in page.url, "the token must leave the address bar at once"
    page.get_by_label("Your name").fill("Console Owner")
    page.get_by_label("Organization name").fill(org)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_label("Repeat the password").fill(PASSWORD)
    page.get_by_role("button", name="Create the account").click()
    expect(page.get_by_role("heading", level=1, name=org)).to_be_visible()

    feed_the_stack(email)
    overview(page, org)
    shot(page, "overview")

    nav(page, "Datasets")
    page.get_by_role("link", name="Competitor catalogue").click()
    expect(page.get_by_role("heading", level=1, name="Competitor catalogue")).to_be_visible()
    expect(page.get_by_role("main").get_by_text("Vertex Standing Desk")).to_be_visible()
    shot(page, "dataset")

    nav(page, "Projects")
    page.get_by_label("Name").fill("Browser test")
    page.get_by_role("button", name="Create the project").click()
    expect(page.get_by_role("link", name="Browser test")).to_be_visible()

    nav(page, "Datasets")
    page.get_by_label("Project", exact=True).select_option(label="Browser test")
    page.get_by_label("Name", exact=True).fill("Prices")
    page.get_by_role("button", name="Create the dataset").click()
    expect(page.get_by_role("heading", level=1, name="Prices")).to_be_visible()

    nav(page, "Alerts")
    expect(page.get_by_role("main").get_by_text("Price up 10 % or more").first).to_be_visible()
    shot(page, "alerts")

    nav(page, "Members")
    expect(page.get_by_role("main").get_by_text(email)).to_be_visible()

    nav(page, "API keys")
    page.get_by_label("Name", exact=True).fill("CI key")
    page.get_by_label("Projects: read").check()
    page.get_by_role("button", name="Create the key").click()
    expect(page.get_by_role("dialog").locator(".secret-value")).to_have_text(re.compile(r"^nxf_"))
    page.get_by_role("button", name="I have stored it").click()
    expect(page.get_by_role("main").get_by_text("CI key")).to_be_visible()

    nav(page, "Audit log")
    page.get_by_role("button", name="Verify the chain").click()
    expect(page.get_by_text(re.compile(r"The chain is intact"))).to_be_visible()
    shot(page, "audit")

    nav(page, "Settings")
    expect(page.get_by_role("heading", name="Security policy")).to_be_visible()
    nav(page, "Single sign-on")
    expect(page.get_by_role("heading", name="Connect a provider")).to_be_visible()

    page.goto(f"{BASE}/#/account?tab=security")
    expect(page.get_by_role("heading", name="Passkeys")).to_be_visible()
    page.get_by_role("button", name="Set up an authenticator app").click()
    page.get_by_role("dialog").get_by_label("Your password").fill(PASSWORD)
    page.get_by_role("dialog").get_by_role("button", name="Continue").click()
    expect(page.get_by_role("img", name="QR code for your authenticator app")).to_be_visible()
    page.get_by_role("button", name="Cancel").click()

    page.goto(f"{BASE}/#/account?tab=sessions")
    expect(page.get_by_role("main").get_by_text("this session")).to_be_visible()

    # Out, and in again with the password.
    page.get_by_label("Your account").click()
    page.get_by_role("button", name="Sign out").click()
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
    sign_in(page, email, org)


def record(message: Any, problems: list[str]) -> None:
    """A console error is a problem - unless it is a load the page expects to fail."""
    if message.type != "error":
        return
    url = (message.location or {}).get("url", "")
    expected = urllib.parse.urlsplit(url).path in EXPECTED_ERRORS
    if expected and message.text.startswith("Failed to load resource"):
        return
    problems.append(f"console: {message.text} ({url})")


def failed_request(failed: Any, problems: list[str]) -> None:
    """A request that did not complete - unless the browser aborted it on purpose
    (a navigation leaving a page while its requests were still in flight)."""
    if "ERR_ABORTED" not in (failed.failure or ""):
        problems.append(f"failed request: {failed.url} ({failed.failure})")


def main() -> int:
    problems: list[str] = []
    suffix = uuid.uuid4().hex[:8]
    org, email = f"Console {suffix}", f"console+{suffix}@nexusflow.example.com"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for scheme in ("light", "dark"):
            # The development CA is not in the browser's store (the requests made
            # from here verify it); the policy and the flows are what is tested.
            context = browser.new_context(
                ignore_https_errors=True,
                color_scheme=scheme,
                viewport={"width": 1280, "height": 860},
            )
            context.add_init_script(
                "document.addEventListener('securitypolicyviolation', e => "
                "console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`));"
            )
            page = context.new_page()
            page.on("console", lambda message: record(message, problems))
            page.on("pageerror", lambda error: problems.append(f"uncaught: {error}"))
            page.on("requestfailed", lambda failed: failed_request(failed, problems))
            if scheme == "light":
                run(page, org, email)
            else:  # the same account in the dark theme
                page.goto(f"{BASE}/#/sign-in")
                sign_in(page, email, org)
                overview(page, org)
                shot(page, "overview-dark")
            context.close()
        browser.close()
    for problem in problems:
        sys.stderr.write(problem + "\n")
    outcome = "FAILED" if problems else "passed"
    sys.stdout.write(f"console smoke test: {outcome} ({len(problems)} problems)\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
