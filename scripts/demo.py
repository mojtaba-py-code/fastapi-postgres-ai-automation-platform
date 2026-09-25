"""Scripted walkthrough of NexusFlow AI against a running stack.

    make secrets dev-certs demo-up     # once: the stack with the demo overlay
    make demo                          # this script

It plays one realistic competitive-intelligence scenario end to end, through
the public API only (exactly what a customer integration would do):

 1. sign up an organization owner;
 2. model a competitor catalogue: project, typed dataset, change thresholds;
 3. connect a partner feed: a webhook source and its signed endpoint;
 4. route alerts: an e-mail channel and two alert rules;
 5. receive the first catalogue snapshot (signed webhook) - 6 products;
 6. receive a second snapshot: price moves, a stock-out, a new product and a
    campaign-tagged URL that the pipeline's Clean stage recognises as noise;
 7. change detection and alerting run automatically; the alert e-mails land
    in Mailpit (http://127.0.0.1:8025);
 8. analyse the changes (offline analyser unless the tenant opted in to AI);
 9. produce PDF and Excel reports and verify their integrity digests;
10. read the audit trail and verify its hash chain.

The same class is driven by the end-to-end tests (tests/e2e). Only the
standard library and the platform's own HTTP client are used.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import ssl
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2

API = "/api/v1"

SCHEMA: dict[str, Any] = {
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


def _product(
    sku: str, name: str, price: str, *, in_stock: bool = True, query: str = ""
) -> dict[str, Any]:
    return {
        "sku": sku,
        "name": name,
        "price": {"amount": price, "currency": "EUR"},
        "stock": {"available": in_stock},
        "link": f"https://shop.example.com/p/{sku.lower()}{query}",
    }


FIRST_SNAPSHOT = [
    _product("NX-100", "Aurora Desk Lamp", "49.90"),
    _product("NX-101", "Nimbus Office Chair", "219.00"),
    _product("NX-102", "Vertex Standing Desk", "499.00"),
    _product("NX-103", "Pulse Wireless Mouse", "29.90"),
    _product("NX-104", "Echo Noise-Cancelling Headset", "149.00"),
    _product("NX-105", "Atlas Monitor Arm", "89.00"),
]
SECOND_SNAPSHOT = [
    _product("NX-100", "Aurora Desk Lamp", "55.90"),  # +12.0 %: alert rule fires
    _product("NX-101", "Nimbus Office Chair", "199.00"),  # -9.1 %
    _product("NX-102", "Vertex Standing Desk", "649.00"),  # +30.1 %: critical
    _product("NX-103", "Pulse Wireless Mouse", "29.90", query="?utm_source=newsletter"),  # noise
    _product("NX-104", "Echo Noise-Cancelling Headset", "149.00", in_stock=False),  # stock-out
    _product("NX-105", "Atlas Monitor Arm", "89.00"),
    _product("NX-106", "Orbit USB-C Dock", "119.00"),  # new listing
]
EXPECTED_SECOND_RUN = {"NX-100", "NX-101", "NX-102", "NX-104", "NX-106"}  # NX-103: cleaned noise
EXPECTED_ALERTS = 3  # price up >= 10 %: NX-100 and NX-102; availability: NX-104


class DemoError(RuntimeError):
    """A step failed; the message says which and why."""


@dataclass
class DemoResult:
    organization_id: str = ""
    project_id: str = ""
    dataset_id: str = ""
    run_statuses: list[str] = field(default_factory=list)
    changes: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    insight: dict[str, Any] = field(default_factory=dict)
    analytics: dict[str, Any] = field(default_factory=dict)
    reports: dict[str, Path] = field(default_factory=dict)
    audit_actions: list[str] = field(default_factory=list)
    audit_ok: bool = False
    audit_checked: int = 0
    emails: int | None = None  # None: Mailpit not reachable (not a demo stack)


class Walkthrough:
    def __init__(
        self,
        base_url: str,
        *,
        verify: ssl.SSLContext | bool = True,
        output_dir: Path = Path("demo-output"),
        mailpit_url: str | None = "http://127.0.0.1:8025",
        timeout: float = 120.0,
        echo: Callable[[str], None] = print,
        client: httpx2.Client | None = None,
    ) -> None:
        self._client = client or httpx2.Client(
            base_url=base_url.rstrip("/"), verify=verify, timeout=30.0
        )
        self._mailpit = mailpit_url
        self._output = output_dir
        self._timeout = timeout
        self._echo = echo
        self._bearer: str | None = None  # the owner's access token, in memory only
        self._step = 0

    # ----------------------------------------------------------------- flow

    def run(self) -> DemoResult:
        result = DemoResult()
        try:
            self._check_health()
            self._sign_up(result)
            webhook = self._model_catalogue(result)
            self._route_alerts(result)
            self._receive(result, webhook, FIRST_SNAPSHOT, "first catalogue snapshot")
            self._receive(result, webhook, SECOND_SNAPSHOT, "second snapshot (a day later)")
            self._await_changes(result)
            self._await_alerts(result)
            self._analyse(result)
            self._report(result)
            self._audit(result)
        finally:
            self._client.close()
        return result

    def _check_health(self) -> None:
        self._title("Platform health")
        ready = self._client.get("/health/ready")
        self._expect(ready, 200, "the platform is not ready")
        self._say(f"ready: {ready.json().get('checks', {})}")

    def _sign_up(self, result: DemoResult) -> None:
        self._title("Sign up an organization owner")
        email = f"owner+{uuid.uuid4().hex[:8]}@nexusflow.example.com"
        created = self._client.post(
            f"{API}/auth/register",
            json={
                "email": email,
                "password": secrets.token_urlsafe(18),  # never printed or stored
                "full_name": "Demo Owner",
                "organization_name": "Acme Retail Intelligence",
            },
        )
        body = self._expect(created, 201, "sign-up failed")
        self._bearer = body["access_token"]
        organization = self._get(f"{API}/organizations/current")
        result.organization_id = organization["id"]
        self._say(f"{email} owns organization {organization['name']!r}")

    def _model_catalogue(self, result: DemoResult) -> tuple[str, str]:
        self._title("Model the competitor catalogue")
        project = self._post(
            f"{API}/projects",
            {"name": "Competitor pricing", "description": "Office furniture competitors"},
        )
        result.project_id = project["id"]
        dataset = self._post(
            f"{API}/datasets",
            {
                "project_id": project["id"],
                "name": "Competitor catalogue",
                "schema": SCHEMA,
                "classification": "internal",
                "retention_days": 365,
            },
        )
        result.dataset_id = dataset["id"]
        self._say("typed schema: sku (key), title, price (decimal), in_stock, url")
        self._say("price thresholds: medium 5 %, high 10 %, critical 25 %")
        source = self._post(
            f"{API}/sources",
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
        endpoint = self._post(
            f"{API}/webhook-endpoints", {"source_id": source["id"], "name": "partner-feed"}
        )
        self._say("signed webhook endpoint created (the secret is shown once, kept in memory)")
        return urlsplit(endpoint["url"]).path, endpoint["secret"]

    def _route_alerts(self, result: DemoResult) -> None:
        self._title("Route alerts to the pricing team")
        channel = self._post(
            f"{API}/channels",
            {
                "name": "Pricing team",
                "config": {"kind": "email", "recipients": ["pricing-team@nexusflow.example.com"]},
            },
        )
        price_up = {
            "type": "numeric_change",
            "field": "price",
            "direction": "increase",
            "min_pct": 10,
        }
        rules = [
            ("Price up 10 % or more", "critical", price_up),
            ("Availability changed", "warning", {"type": "field_changed", "field": "in_stock"}),
        ]
        for name, severity, condition in rules:
            self._post(
                f"{API}/alert-rules",
                {
                    "project_id": result.project_id,
                    "dataset_id": result.dataset_id,
                    "name": name,
                    "condition": condition,
                    "severity": severity,
                    "channel_ids": [channel["id"]],
                },
            )
            self._say(f"rule {name!r} ({severity}) -> e-mail")

    def _receive(
        self,
        result: DemoResult,
        webhook: tuple[str, str],
        products: list[dict[str, Any]],
        label: str,
    ) -> None:
        self._title(f"Partner pushes the {label}")
        path, secret = webhook
        body = json.dumps({"products": products}, separators=(",", ":")).encode()
        delivery = f"dlv-{uuid.uuid4().hex}"
        timestamp = int(time.time())
        mac = hmac.new(
            secret.encode(), f"{timestamp}.{delivery}.".encode() + body, hashlib.sha256
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-NexusFlow-Delivery": delivery,
            "X-NexusFlow-Signature": f"t={timestamp},v1={mac}",
        }
        receipt = self._client.post(path, content=body, headers=headers)
        run_id = self._expect(receipt, 202, "the webhook was not accepted")["run_id"]
        replay = self._client.post(path, content=body, headers=headers)  # a partner retry
        replayed = replay.json().get("status") if replay.status_code == 200 else replay.status_code
        self._say(f"{len(products)} products accepted; the same delivery again -> {replayed}")
        run = self._wait(
            lambda: self._get(f"{API}/runs/{run_id}"),
            lambda r: r["status"] in ("succeeded", "failed"),
            "the collection run to finish",
        )
        result.run_statuses.append(run["status"])
        if run["status"] != "succeeded":
            raise DemoError(f"collection run failed: {run.get('error_code')}")
        stats = run.get("stats", {})
        self._say(
            f"run {run['status']}: received {stats.get('received')}, valid {stats.get('valid')}, "
            f"invalid {stats.get('invalid')}"
        )

    def _await_changes(self, result: DemoResult) -> None:
        self._title("Change detection (automatic)")
        changes = self._wait(
            lambda: self._items(f"{API}/changes", dataset_id=result.dataset_id, limit=200),
            lambda items: {c["record_key"] for c in second_run(items)} >= EXPECTED_SECOND_RUN,
            "the changes of the second snapshot",
        )
        result.changes = changes
        for change in sorted(second_run(changes), key=lambda c: -int(c["score"])):
            self._say(
                f"{change['record_key']:<7} {change['change_type']:<8} "
                f"{change['significance']:<8} {_describe(change)}"
            )
        self._say("NX-103: a campaign-tagged URL is noise, removed by the Clean stage - no change")

    def _await_alerts(self, result: DemoResult) -> None:
        self._title("Alerting (automatic)")
        alerts = self._wait(
            lambda: self._items(f"{API}/alerts", limit=50),
            lambda items: len(items) >= EXPECTED_ALERTS,
            "the alerts",
        )
        result.alerts = alerts
        for alert in alerts:
            self._say(alert["title"])
        result.emails = self._mailpit_messages()
        if result.emails is None:
            self._say("(Mailpit not reachable: e-mail delivery is not shown)")
        else:
            self._say(f"{result.emails} alert e-mail(s) in Mailpit: {self._mailpit}")

    def _analyse(self, result: DemoResult) -> None:
        self._title("Analyse the changes")
        queued = self._post(f"{API}/intelligence/analyses", {"dataset_id": result.dataset_id})
        insight = self._wait(
            lambda: self._get(f"{API}/intelligence/insights/{queued['id']}"),
            lambda i: i["status"] in ("completed", "failed", "rejected"),
            "the analysis",
        )
        result.insight = insight
        self._say(
            f"{insight['status']} by {insight.get('provider')} - risk {insight.get('risk_level')}"
        )
        self._say(str(insight.get("summary") or ""))
        for recommendation in insight.get("recommendations") or []:
            self._say(f"  - {recommendation}")

    def _report(self, result: DemoResult) -> None:
        self._title("Reports")
        # Counted by the database over every change of the period, however many.
        analytics = self._get(f"{API}/analytics/changes", project_id=result.project_id)
        result.analytics = analytics
        totals = analytics["totals"]
        self._say(
            f"last 30 days: {totals['changes']} changes ({totals['created']} new, "
            f"{totals['updated']} updated, {totals['deleted']} removed); "
            f"{analytics['trend_note']}"
        )
        now = datetime.now(UTC)
        self._output.mkdir(parents=True, exist_ok=True)
        for fmt in ("pdf", "xlsx"):
            queued = self._post(
                f"{API}/reports",
                {
                    "project_id": result.project_id,
                    "dataset_id": result.dataset_id,
                    "title": "Competitor pricing - daily brief",
                    "format": fmt,
                    "period_start": (now - timedelta(days=1)).isoformat(),
                    "period_end": (now + timedelta(minutes=5)).isoformat(),
                },
            )
            self._wait(
                partial(self._get, f"{API}/reports/{queued['id']}"),
                lambda r: r["status"] in ("ready", "failed"),
                f"the {fmt} report",
            )
            download = self._client.get(
                f"{API}/reports/{queued['id']}/download", headers=self._auth()
            )
            self._check(download, 200, f"the {fmt} report could not be downloaded")
            digest = base64.b64encode(hashlib.sha256(download.content).digest()).decode()
            if download.headers.get("repr-digest") != f"sha-256=:{digest}:":
                raise DemoError(f"the {fmt} report failed its integrity check")
            target = self._output / f"competitor-brief.{fmt}"
            target.write_bytes(download.content)
            result.reports[fmt] = target
            self._say(f"{target} ({len(download.content):,} bytes, SHA-256 verified)")

    def _audit(self, result: DemoResult) -> None:
        self._title("Audit trail")
        entries = self._items(f"{API}/audit", limit=100)
        result.audit_actions = [entry["action"] for entry in entries]
        self._say(
            f"{len(entries)} entries, e.g. {', '.join(sorted(set(result.audit_actions))[:8])}"
        )
        verification = self._get(f"{API}/audit/verify")
        result.audit_ok, result.audit_checked = verification["ok"], verification["checked"]
        self._say(
            f"hash chain: {'intact' if verification['ok'] else 'BROKEN'} "
            f"({verification['checked']} entries recomputed)"
        )

    # ---------------------------------------------------------------- helpers

    def _mailpit_messages(self) -> int | None:
        if not self._mailpit:
            return None
        deadline = time.monotonic() + min(self._timeout, 60)
        count = 0
        while time.monotonic() < deadline:
            try:
                response = httpx2.get(f"{self._mailpit}/api/v1/messages", timeout=5.0)
            except httpx2.HTTPError:
                return None
            if response.status_code != 200:
                return None
            count = int(response.json().get("total", 0))
            if count >= 3:
                break
            time.sleep(2)
        return count

    def _auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._bearer}"}

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        response = self._client.get(path, params=params or None, headers=self._auth())
        body: dict[str, Any] = self._expect(response, 200, f"GET {path}")
        return body

    def _items(self, path: str, **params: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = self._get(path, **params)["items"]
        return items

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(path, json=body, headers=self._auth())
        if response.status_code not in (200, 201, 202):
            self._expect(response, 201, f"POST {path}")
        created: dict[str, Any] = response.json()
        return created

    def _expect(self, response: httpx2.Response, status: int, what: str) -> Any:
        """Check the status, then return the JSON body."""
        self._check(response, status, what)
        return response.json()

    @staticmethod
    def _check(response: httpx2.Response, status: int, what: str) -> None:
        if response.status_code != status:
            try:
                detail = response.json()
            except ValueError:
                detail = response.text[:300]
            raise DemoError(f"{what}: HTTP {response.status_code} {detail}")

    def _wait(self, fetch: Callable[[], Any], done: Callable[[Any], bool], what: str) -> Any:
        deadline = time.monotonic() + self._timeout
        delay = 0.5
        while True:
            value = fetch()
            if done(value):
                return value
            if time.monotonic() > deadline:
                raise DemoError(f"timed out after {self._timeout:.0f}s waiting for {what}")
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)

    def _title(self, text: str) -> None:
        self._step += 1
        self._echo(f"\n[{self._step:>2}] {text}")

    def _say(self, text: str) -> None:
        self._echo(f"     {text}")


def second_run(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The first snapshot only creates records; the second updates and adds NX-106."""
    return [c for c in changes if c["change_type"] != "created" or c["record_key"] == "NX-106"]


def _describe(change: dict[str, Any]) -> str:
    diff: dict[str, Any] = change.get("diff") or {}
    if change.get("change_type") == "created":
        title = (diff.get("title") or {}).get("new")
        price = (diff.get("price") or {}).get("new")
        return f"new listing: {title}, {price} EUR"
    parts = []
    for name, entry in diff.items():
        if isinstance(entry, dict):
            pct = entry.get("pct")
            suffix = f" ({pct:+.1f} %)" if isinstance(pct, (int, float)) else ""
            parts.append(f"{name}: {entry.get('old')} -> {entry.get('new')}{suffix}")
    return "; ".join(parts)


def _verify(base_url: str, ca_file: str | None) -> ssl.SSLContext | bool:
    """Certificates and host names are always verified; a development CA can be added."""
    if urlsplit(base_url).scheme != "https":
        return True
    return ssl.create_default_context(cafile=ca_file)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NexusFlow AI walkthrough against a running stack")
    parser.add_argument("--base-url", default="https://localhost")
    parser.add_argument(
        "--ca-file", help="CA bundle for a development certificate (make dev-certs)"
    )
    parser.add_argument("--mailpit-url", default="http://127.0.0.1:8025")
    parser.add_argument("--output-dir", type=Path, default=Path("demo-output"))
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds per waiting step")
    args = parser.parse_args(argv)
    walkthrough = Walkthrough(
        args.base_url,
        verify=_verify(args.base_url, args.ca_file),
        output_dir=args.output_dir,
        mailpit_url=args.mailpit_url or None,
        timeout=args.timeout,
    )
    started = time.monotonic()
    try:
        result = walkthrough.run()
    except (DemoError, httpx2.HTTPError) as exc:
        print(f"\nDemo stopped: {exc}", file=sys.stderr)
        return 1
    print(
        f"\nDone in {time.monotonic() - started:.0f}s: {len(result.changes)} changes, "
        f"{len(result.alerts)} alerts, insight {result.insight.get('status')}, "
        f"{len(result.reports)} reports in {args.output_dir}/, audit chain "
        f"{'intact' if result.audit_ok else 'BROKEN'}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
