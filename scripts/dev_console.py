"""Run the web console against a real API on this machine - no Docker.

    uv run --group localdb python scripts/dev_console.py [--port 8765]

It starts an embedded PostgreSQL (pgserver, as the integration tests do),
migrates it with the production roles, builds the platform with the test
keys and an in-memory Redis, seeds an owner, and serves the console from
./web with the same security headers as the edge (deploy/nginx/snippets/
console.conf) next to the API. The worker tasks run in-process (the
integration tests' bus), so webhook deliveries become runs, changes and
alerts as on a live stack. It seeds a month of a competitor-pricing demo
(pass --empty for none) and prints the owner's credentials and a fresh
sign-up link.

E-mails are not sent: a local mailbox keeps them, prints the links of those
that carry one (sign-up, password reset, invitation), and serves them through
a small Mailpit-compatible API under /_dev/mail - so the browser test runs
against this server as against the stack (docs/CONSOLE.md). Development only:
it listens on 127.0.0.1, and everything is gone when it stops.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
import sys
import tempfile
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import fakeredis  # noqa: E402
import httpx2  # noqa: E402
import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import FileResponse, JSONResponse, Response  # noqa: E402
from starlette.staticfiles import StaticFiles  # noqa: E402
from tests.conftest import make_settings  # noqa: E402
from tests.support.bus import InProcessBus  # noqa: E402
from tests.support.database import create_database, drop_database  # noqa: E402

from nexusflow.apps.api.main import create_app  # noqa: E402
from nexusflow.bootstrap.container import build_container  # noqa: E402
from nexusflow.domain.shared.context import RequestMeta  # noqa: E402
from nexusflow.domain.webhooks.signatures import build_signature_header  # noqa: E402
from nexusflow.infrastructure.database.engine import create_engine  # noqa: E402

WEB = ROOT / "web"
ENTRY_PATHS = ("/complete-signup", "/reset-password", "/accept-invitation", "/sso/callback")
OWNER_EMAIL = "owner@example.com"
OWNER_PASSWORD = "correct horse battery staple 42"  # noqa: S105 - a local demo account  # nosec B105
META = RequestMeta(request_id="dev-console", ip="127.0.0.1", user_agent="dev-console")


class ShiftableClock:
    """The system clock, moved back while the demo's past days are delivered."""

    def __init__(self) -> None:
        self.offset = timedelta(0)

    def now(self) -> datetime:
        return datetime.now(UTC) + self.offset


# The demo's catalogue (scripts/demo.py uses the same schema and feed mapping).
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
FEED_MAPPING = {
    "sku": "sku",
    "title": "name",
    "price": "price.amount",
    "in_stock": "stock.available",
    "url": "link",
}
CATALOGUE = {
    "NX-100": ("Aurora Desk Lamp", 49.90),
    "NX-101": ("Nimbus Office Chair", 219.00),
    "NX-102": ("Vertex Standing Desk", 499.00),
    "NX-103": ("Pulse Wireless Mouse", 29.90),
    "NX-104": ("Echo Noise-Cancelling Headset", 149.00),
    "NX-105": ("Atlas Monitor Arm", 89.00),
    "NX-107": ("Summit Ergonomic Keyboard", 79.00),
    "NX-108": ("Halo Webcam 4K", 129.00),
    "NX-109": ("Drift Laptop Stand", 45.00),
    "NX-110": ("Canopy Desk Organiser", 24.90),
    "NX-111": ("Ridge Footrest", 39.00),
}


def _product(sku: str, name: str, price: float, in_stock: bool) -> dict[str, Any]:
    return {
        "sku": sku,
        "name": name,
        "price": {"amount": f"{price:.2f}", "currency": "EUR"},
        "stock": {"available": in_stock},
        "link": f"https://shop.example.com/p/{sku.lower()}",
    }


async def seed_demo(base_url: str, clock: ShiftableClock, bus: InProcessBus) -> None:
    """A month of a partner feed: small daily moves, a sale, stock-outs, a new listing."""
    async with httpx2.AsyncClient(base_url=base_url, timeout=60) as client:
        login = await client.post(
            "/api/v1/auth/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD}
        )
        login.raise_for_status()
        auth = {"Authorization": f"Bearer {login.json()['access_token']}"}

        async def post(path: str, body: dict[str, Any]) -> dict[str, Any]:
            response = await client.post(f"/api/v1{path}", json=body, headers=auth)
            response.raise_for_status()
            result: dict[str, Any] = response.json()
            return result

        project = await post(
            "/projects",
            {"name": "Competitor pricing", "description": "Office furniture competitors"},
        )
        dataset = await post(
            "/datasets",
            {
                "project_id": project["id"],
                "name": "Competitor catalogue",
                "schema": SCHEMA,
                "classification": "internal",
                "retention_days": 365,
            },
        )
        source = await post(
            "/sources",
            {
                "project_id": project["id"],
                "dataset_id": dataset["id"],
                "name": "Partner feed",
                "config": {
                    "kind": "webhook",
                    "items_path": "products",
                    "field_mapping": FEED_MAPPING,
                },
            },
        )
        endpoint = await post(
            "/webhook-endpoints", {"source_id": source["id"], "name": "partner-feed"}
        )
        channel = await post(
            "/channels",
            {
                "name": "Pricing team",
                "config": {"kind": "email", "recipients": ["pricing-team@example.com"]},
            },
        )
        rules = (
            (
                "Price up 10 % or more",
                "critical",
                {
                    "type": "numeric_change",
                    "field": "price",
                    "direction": "increase",
                    "min_pct": 10,
                },
            ),
            ("Availability changed", "warning", {"type": "field_changed", "field": "in_stock"}),
        )
        for name, severity, condition in rules:
            await post(
                "/alert-rules",
                {
                    "project_id": project["id"],
                    "dataset_id": dataset["id"],
                    "name": name,
                    "condition": condition,
                    "severity": severity,
                    "channel_ids": [channel["id"]],
                },
            )
        await post(
            "/projects",
            {"name": "Supplier onboarding", "description": "Catalogues from new suppliers"},
        )

        path, secret = urlsplit(endpoint["url"]).path, endpoint["secret"]
        rng = random.Random(7)  # deterministic demo prices, not a secret  # nosec B311
        prices = {sku: price for sku, (_, price) in CATALOGUE.items()}
        stock = dict.fromkeys(CATALOGUE, True)
        on_sale = list(prices)[:8]
        for days_ago in range(29, -1, -1):
            clock.offset = -timedelta(days=days_ago)
            for sku, price in prices.items():
                if rng.random() < 0.12:
                    prices[sku] = round(price * rng.uniform(0.93, 1.08), 2)
            if days_ago == 17:  # a competitor's sale: many prices at once
                for sku in on_sale:
                    prices[sku] = round(prices[sku] * 0.8, 2)
            if days_ago == 14:  # and back, a little higher
                for sku in on_sale:
                    prices[sku] = round(prices[sku] / 0.8 * 1.02, 2)
            if days_ago in (21, 6):
                flipped = rng.choice(list(stock))
                stock[flipped] = not stock[flipped]
            products = [
                _product(sku, CATALOGUE[sku][0], price, stock[sku]) for sku, price in prices.items()
            ]
            if days_ago <= 9:
                products.append(_product("NX-106", "Orbit USB-C Dock", 119.00, True))
            body = json.dumps({"products": products}).encode()
            delivery = f"dlv-{days_ago:02d}-{rng.getrandbits(32):08x}"
            signature = build_signature_header(
                secret.encode(),
                timestamp=int(clock.now().timestamp()),
                delivery_id=delivery,
                body=body,
            )
            headers = {
                "Content-Type": "application/json",
                "X-NexusFlow-Delivery": delivery,
                "X-NexusFlow-Signature": signature,
            }
            response = await client.post(path, content=body, headers=headers)
            response.raise_for_status()
            for _ in range(6):  # ingestion, detection, alert evaluation, deliveries
                await bus.work()
        clock.offset = timedelta(0)
        today = datetime.now(UTC).date()
        await post(
            "/reports",
            {
                "project_id": project["id"],
                "title": "Competitor prices, last 30 days",
                "format": "pdf",
                "period_start": f"{today - timedelta(days=30)}T00:00:00Z",
                "period_end": f"{today}T23:59:59Z",
            },
        )
        for _ in range(4):
            await bus.work()


async def keep_working(bus: InProcessBus) -> None:
    """The worker pools: run whatever is due, as a live stack would."""
    while True:
        await bus.work()
        await asyncio.sleep(0.5)


def console_headers() -> dict[str, str]:
    """The headers console.conf sets at the edge (parsed from it, so they agree)."""
    headers: dict[str, str] = {}
    snippet = ROOT / "deploy" / "nginx" / "snippets" / "console.conf"
    for raw in snippet.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("add_header "):
            name, _, rest = line.removeprefix("add_header ").partition(" ")
            headers[name] = rest.rsplit(" always;", 1)[0].strip().strip('"')
    headers.pop("Strict-Transport-Security", None)  # plain http on localhost
    return headers


class ConsoleHeaders(BaseHTTPMiddleware):
    def __init__(self, app, headers: dict[str, str]) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._headers = headers

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        path = request.url.path
        if path == "/" or path in ENTRY_PATHS or path.startswith("/assets/"):
            for name, value in self._headers.items():
                response.headers[name] = value
        return response


class DevMailbox:
    """The platform's e-mail transport here: messages are kept, not sent. Those
    with a link into the console are printed with it."""

    def __init__(self) -> None:
        self.messages: deque[dict[str, Any]] = deque(maxlen=500)
        self._next_id = 1

    async def send_email(self, recipients: list[str], subject: str, body: str) -> None:
        message = {
            "ID": str(self._next_id),
            "Created": datetime.now(UTC).isoformat(),
            "To": [{"Name": "", "Address": address} for address in recipients],
            "Subject": subject,
            "Text": body,
        }
        self._next_id += 1
        self.messages.append(message)
        links = [
            link for link in re.findall(r"https?://\S+", body) if urlsplit(link).path in ENTRY_PATHS
        ]
        if links:
            lines = [f"  Mail to {', '.join(recipients)}: {subject}", *(f"    {x}" for x in links)]
            print("\n".join(lines), flush=True)

    def search(self, query: str) -> list[dict[str, Any]]:
        """Newest first; ``to:"address"`` (Mailpit's syntax) or everything."""
        wanted = re.fullmatch(r'\s*to:"([^"]+)"\s*', query)
        address = wanted[1].lower() if wanted else None
        return [
            message
            for message in reversed(self.messages)
            if address is None or any(to["Address"].lower() == address for to in message["To"])
        ]

    def get(self, message_id: str) -> dict[str, Any] | None:
        return next((m for m in self.messages if m["ID"] == message_id), None)


def _summary(message: dict[str, Any]) -> dict[str, Any]:
    return {key: message[key] for key in ("ID", "Created", "To", "Subject")}


def serve_console(api: FastAPI, mailbox: DevMailbox) -> FastAPI:
    """Add the console to the API application itself (so the API's own start-up
    still runs), outermost of all: its headers replace the API's on its paths.
    The mailbox's read API (a subset of Mailpit's) sits under /_dev/mail."""

    async def index(_: Request) -> FileResponse:
        return FileResponse(WEB / "index.html", media_type="text/html")

    async def mail_search(request: Request) -> JSONResponse:
        found = mailbox.search(request.query_params.get("query", ""))
        summaries = [_summary(message) for message in found]
        return JSONResponse({"messages": summaries, "messages_count": len(found)})

    async def mail_message(request: Request) -> JSONResponse:
        message = mailbox.get(request.path_params["message_id"])
        if message is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(message)

    api.add_route("/", index, include_in_schema=False)
    for path in ENTRY_PATHS:
        api.add_route(path, index, include_in_schema=False)
    api.add_route("/_dev/mail/api/v1/messages", mail_search, include_in_schema=False)
    api.add_route("/_dev/mail/api/v1/search", mail_search, include_in_schema=False)
    api.add_route("/_dev/mail/api/v1/message/{message_id}", mail_message, include_in_schema=False)
    api.mount("/assets", StaticFiles(directory=WEB / "assets"), name="console-assets")
    api.add_middleware(ConsoleHeaders, headers=console_headers())
    return api


async def main(port: int, *, empty: bool) -> None:
    try:
        import pgserver  # noqa: PLC0415 - optional: the localdb dependency group
    except ImportError:
        raise SystemExit(
            "PostgreSQL is not available: uv sync --group localdb (pgserver)."
        ) from None
    # A server of its own: never the one a test run may be starting or stopping.
    server = pgserver.get_server(
        Path(tempfile.gettempdir()) / "nexusflow-console-pg", cleanup_mode=None
    )
    database = await create_database(server.get_uri())
    storage = Path(tempfile.mkdtemp(prefix="nexusflow-console-"))
    base_url = f"http://localhost:{port}"
    settings = make_settings(
        storage,
        database={"url": database.app_url},
        app={"public_base_url": base_url, "allowed_hosts": ["localhost", "127.0.0.1"]},
        # E-mail on, into the mailbox (the host is never contacted: .invalid).
        notifications={"smtp_host": "mailbox.dev.invalid"},
    )
    clock = ShiftableClock()
    engine = create_engine(settings.database, application_name="nexusflow-dev-console")
    mailbox = DevMailbox()
    container = build_container(
        settings,
        application_name="nexusflow-dev-console",
        clock=clock,
        engine=engine,
        redis=fakeredis.FakeAsyncRedis(),
        email=mailbox,
    )
    bus = InProcessBus(container)
    container.uow_factory._publisher = bus  # type: ignore[attr-defined]  # the worker pools, in-process
    tasks: list[asyncio.Task[None]] = []
    try:
        token, _ = await container.auth.issue_signup_link(email=OWNER_EMAIL, meta=META)
        await container.auth.complete_signup(
            token=token,
            password=OWNER_PASSWORD,
            full_name="Olivia Owner",
            organization_name="Acme Retail",
            meta=META,
        )
        fresh, _ = await container.auth.issue_signup_link(email="new.person@example.com", meta=META)
        api = create_app(settings, container=container, configure_logs=False)
        web = uvicorn.Server(
            uvicorn.Config(
                serve_console(api, mailbox), host="127.0.0.1", port=port, log_level="warning"
            )
        )
        tasks.append(asyncio.create_task(web.serve()))
        while not web.started:  # noqa: ASYNC110 - uvicorn exposes a flag, not an event
            await asyncio.sleep(0.1)
        if not empty:
            print("  Seeding a month of demo data...", flush=True)
            await seed_demo(f"http://127.0.0.1:{port}", clock, bus)
        tasks.append(asyncio.create_task(keep_working(bus)))
        print(f"\n  Console:  {base_url}/")
        print(f"  Owner:    {OWNER_EMAIL} / {OWNER_PASSWORD}")
        print(f"  Sign-up:  {base_url}/complete-signup#token={fresh}\n", flush=True)
        await tasks[0]
    finally:
        for task in tasks:
            task.cancel()
        await container.aclose()
        await drop_database(database)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--empty", action="store_true", help="seed no demo data")
    arguments = parser.parse_args()
    asyncio.run(main(arguments.port, empty=arguments.empty))
