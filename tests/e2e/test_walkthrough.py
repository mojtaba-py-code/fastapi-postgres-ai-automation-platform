"""The full business scenario on a live stack: every worker pool, the broker, the
scheduler, the edge and (with the demo overlay) real SMTP delivery to Mailpit."""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

from tests.e2e.conftest import LiveStack


def test_the_business_scenario_runs_end_to_end(
    live: LiveStack, demo: ModuleType, tmp_path: Path
) -> None:
    narration: list[str] = []
    result = demo.Walkthrough(
        live.base_url,
        verify=live.verify,
        output_dir=tmp_path,
        mailpit_url=live.mailpit_url,
        timeout=180,
        echo=narration.append,
    ).run()

    assert result.run_statuses == ["succeeded", "succeeded"], narration
    assert {c["record_key"] for c in demo.second_run(result.changes)} == demo.EXPECTED_SECOND_RUN
    assert len(result.alerts) >= demo.EXPECTED_ALERTS
    assert result.insight["status"] == "completed"
    assert set(result.reports) == {"pdf", "xlsx"}
    assert result.audit_ok
    if live.mailpit_url:
        assert result.emails is not None and result.emails >= demo.EXPECTED_ALERTS
