"""Alerts and dashboards watch series the platform actually exports.

A rule over a misspelt metric or label never fires - it fails silently, which
for a security alert (a broken audit chain, credential stuffing) is the worst
way to fail. These tests tie every NexusFlow series in the Prometheus rules and
Grafana dashboards to a metric defined in ``observability.metrics``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from prometheus_client.metrics import MetricWrapperBase

from nexusflow.infrastructure.observability import metrics

DEPLOY = Path(__file__).resolve().parents[3] / "deploy"
_SAMPLE_SUFFIXES = ("_total", "_bucket", "_count", "_sum", "_created")
_SELECTOR = re.compile(r"\b(nexusflow_[a-z0-9_]+)\s*(?:\{([^}]*)\})?")
_MATCHER = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=~|!~|!=|=)")


def _exported() -> dict[str, set[str]]:
    """Every metric family the platform defines, with its label names."""
    families: dict[str, set[str]] = {}
    for value in vars(metrics).values():
        if isinstance(value, MetricWrapperBase):
            for family in value.describe():
                families[family.name] = set(getattr(value, "_labelnames", ()))
    return families


def _family(series: str, families: dict[str, set[str]]) -> str | None:
    if series in families:
        return series
    for suffix in _SAMPLE_SUFFIXES:
        if series.endswith(suffix) and series.removesuffix(suffix) in families:
            return series.removesuffix(suffix)
    return None


def _alert_rules() -> list[dict[str, Any]]:
    document = yaml.safe_load((DEPLOY / "prometheus" / "alerts.yml").read_text(encoding="utf-8"))
    return [rule for group in document["groups"] for rule in group["rules"]]


def _dashboard_exprs(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "expr" and isinstance(value, str):
                yield value
            else:
                yield from _dashboard_exprs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _dashboard_exprs(item)


def _queries() -> list[tuple[str, str]]:
    queries = [(f"alert {rule['alert']}", str(rule["expr"])) for rule in _alert_rules()]
    for path in sorted((DEPLOY / "grafana" / "dashboards").glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        queries += [(f"dashboard {path.name}", expr) for expr in _dashboard_exprs(document)]
    return queries


def test_the_rule_and_dashboard_files_are_found() -> None:
    assert len(_alert_rules()) >= 15
    assert any(where.startswith("dashboard") for where, _ in _queries())


@pytest.mark.parametrize(("where", "expr"), _queries())
def test_every_series_and_label_exists(where: str, expr: str) -> None:
    families = _exported()
    for series, selector in _SELECTOR.findall(expr):
        family = _family(series, families)
        assert family is not None, f"{where}: {series} is not exported"
        unknown = set(_MATCHER.findall(selector)) - {"le", "job", "instance"} - families[family]
        assert not unknown, f"{where}: {series} has no label {sorted(unknown)}"


def test_every_alert_is_named_once_and_says_what_it_means() -> None:
    names = [rule["alert"] for rule in _alert_rules()]
    assert len(names) == len(set(names))
    for rule in _alert_rules():
        assert rule["labels"]["severity"] in {"critical", "warning", "info"}, rule["alert"]
        assert rule["annotations"]["summary"].strip(), rule["alert"]
