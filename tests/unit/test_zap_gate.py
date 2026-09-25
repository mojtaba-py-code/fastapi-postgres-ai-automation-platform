"""The DAST gate fails CI on Medium or High ZAP alerts, and only on those."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("zap_gate", ROOT / "scripts" / "zap_gate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _report(tmp_path: Path, *risks: tuple[str, int]) -> str:
    alerts: list[dict[str, Any]] = [
        {"pluginid": plugin, "riskcode": str(risk), "riskdesc": f"risk {risk}", "name": plugin}
        for plugin, risk in risks
    ]
    path = tmp_path / "zap-report.json"
    path.write_text(json.dumps({"site": [{"@name": "https://localhost", "alerts": alerts}]}))
    return str(path)


def test_informational_and_low_alerts_pass(gate: ModuleType, tmp_path: Path) -> None:
    assert gate.main(["zap_gate.py", _report(tmp_path, ("10036", 0), ("10021", 1))]) == 0


@pytest.mark.parametrize("risk", [2, 3])
def test_a_medium_or_high_alert_fails(gate: ModuleType, tmp_path: Path, risk: int) -> None:
    assert gate.main(["zap_gate.py", _report(tmp_path, ("10021", 1), ("40012", risk))]) == 1


def test_an_accepted_alert_needs_a_reason_and_then_passes(
    gate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "ACCEPTED", {"90004": "documented false positive"})
    assert gate.main(["zap_gate.py", _report(tmp_path, ("90004", 2))]) == 0
    assert all(reason.strip() for reason in gate.ACCEPTED.values())


def test_an_empty_report_passes_and_a_bad_invocation_does_not(
    gate: ModuleType, tmp_path: Path
) -> None:
    assert gate.main(["zap_gate.py", _report(tmp_path)]) == 0
    assert gate.main(["zap_gate.py"]) == 2
