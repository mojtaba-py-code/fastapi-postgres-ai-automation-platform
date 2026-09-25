"""The monitoring stack end to end, as an operator reaches it: Grafana behind
the admin port with its provisioned dashboard and data source, and Prometheus
- through that data source - with every alert rule loaded, every platform
target scraped and Alertmanager connected. An image upgrade that breaks one of
them fails here, not during the first incident.

Needs ``secrets/grafana_admin_password`` (``make secrets``) and Grafana on
``NEXUSFLOW_E2E_GRAFANA_URL`` (default http://127.0.0.1:3000, the edge's
admin port); otherwise the tests are skipped.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from typing import Any

import httpx2
import pytest
import yaml

from tests.e2e.conftest import ROOT, LiveStack

GRAFANA_URL = os.environ.get("NEXUSFLOW_E2E_GRAFANA_URL", "http://127.0.0.1:3000").rstrip("/")
PASSWORD_FILE = ROOT / "secrets" / "grafana_admin_password"
ALERT_RULES = ROOT / "deploy" / "prometheus" / "alerts.yml"
SCRAPED_JOBS = {"api", "api-internal", "workers", "rabbitmq", "prometheus"}


@pytest.fixture(scope="module")
def grafana(live: LiveStack) -> Iterator[httpx2.Client]:
    if not PASSWORD_FILE.exists():
        pytest.skip("secrets/grafana_admin_password not found (make secrets)")
    password = PASSWORD_FILE.read_text(encoding="utf-8").strip()
    with httpx2.Client(base_url=GRAFANA_URL, auth=("admin", password), timeout=30.0) as client:
        try:
            client.get("/api/health")
        except httpx2.TransportError:
            pytest.skip(f"Grafana is not reachable on {GRAFANA_URL}")
        yield client


def _prometheus(grafana: httpx2.Client, path: str) -> Any:
    """Prometheus's HTTP API through the provisioned data source."""
    routes = (
        f"/api/datasources/uid/prometheus/resources/{path}",
        f"/api/datasources/proxy/uid/prometheus/{path}",
    )
    answers = []
    for route in routes:
        response = grafana.get(route)
        answers.append(f"{route}: {response.status_code}")
        if response.status_code == 200 and response.json().get("status") == "success":
            return response.json()["data"]
    pytest.fail("Prometheus unreachable through Grafana - " + "; ".join(answers))


def test_grafana_is_healthy_and_serves_the_provisioned_dashboard(
    grafana: httpx2.Client,
) -> None:
    health = grafana.get("/api/health")
    assert health.status_code == 200
    assert health.json()["database"] == "ok"
    dashboard = grafana.get("/api/dashboards/uid/nexusflow-overview")
    assert dashboard.status_code == 200, dashboard.text
    body = dashboard.json()
    assert body["dashboard"]["title"] == "NexusFlow AI - Overview"
    assert body["meta"]["provisioned"] is True
    assert body["dashboard"]["panels"]


def test_grafana_refuses_anonymous_access() -> None:
    with httpx2.Client(base_url=GRAFANA_URL, timeout=30.0) as anonymous:
        try:
            response = anonymous.get("/api/dashboards/uid/nexusflow-overview")
        except httpx2.TransportError:
            pytest.skip(f"Grafana is not reachable on {GRAFANA_URL}")
    assert response.status_code == 401


def test_prometheus_loaded_every_alert_rule_and_reaches_alertmanager(
    grafana: httpx2.Client,
) -> None:
    expected = {
        rule["alert"]
        for group in yaml.safe_load(ALERT_RULES.read_text(encoding="utf-8"))["groups"]
        for rule in group["rules"]
        if "alert" in rule
    }
    loaded = {
        rule["name"]
        for group in _prometheus(grafana, "api/v1/rules")["groups"]
        for rule in group["rules"]
        if rule["type"] == "alerting"
    }
    assert expected, "no alert rules in deploy/prometheus/alerts.yml"
    assert expected <= loaded, f"not loaded: {sorted(expected - loaded)}"
    alertmanagers = _prometheus(grafana, "api/v1/alertmanagers")["activeAlertmanagers"]
    assert [a["url"] for a in alertmanagers] == ["http://alertmanager:9093/api/v2/alerts"]


def test_prometheus_scrapes_every_platform_target(grafana: httpx2.Client) -> None:
    # Targets are scraped every 15 s: allow a freshly started stack two rounds.
    deadline = time.monotonic() + 60
    while True:
        targets = _prometheus(grafana, "api/v1/targets")["activeTargets"]
        down = {
            f"{t['labels']['job']} {t['scrapeUrl']}: {t['health']} {t.get('lastError', '')}"
            for t in targets
            if t["health"] != "up"
        }
        jobs = {t["labels"]["job"] for t in targets}
        if (not down and jobs >= SCRAPED_JOBS) or time.monotonic() > deadline:
            break
        time.sleep(5)
    assert jobs >= SCRAPED_JOBS, f"not scraped: {sorted(SCRAPED_JOBS - jobs)}"
    assert not down, sorted(down)
