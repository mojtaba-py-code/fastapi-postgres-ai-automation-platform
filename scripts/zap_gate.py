"""Gate on an OWASP ZAP JSON report: fail on any Medium or High alert.

    python scripts/zap_gate.py zap-report.json

Prints every alert (risk, plugin, name, instances) and exits 1 when an alert of
Medium risk or higher remains that is not accepted below. An accepted alert
needs a written reason - a false positive, or a risk the threat model accepts -
so the exception is reviewed like code. Standard library only: CI runs it with
the runner's own Python.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

MEDIUM = 2

# ZAP plugin ID -> why an alert of Medium risk or higher is accepted.
ACCEPTED: dict[str, str] = {}


def alerts(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [alert for site in report.get("site", []) for alert in site.get("alerts", [])]


def blocking(found: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        alert
        for alert in found
        if int(alert.get("riskcode", 0)) >= MEDIUM and str(alert.get("pluginid")) not in ACCEPTED
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: zap_gate.py <zap-report.json>\n")
        return 2
    found = alerts(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
    for alert in sorted(found, key=lambda a: -int(a.get("riskcode", 0))):
        note = " (accepted)" if str(alert.get("pluginid")) in ACCEPTED else ""
        sys.stdout.write(
            f"{alert.get('riskdesc', '?'):<28} {alert.get('pluginid', '?'):>6}  "
            f"{alert.get('name', '?')} - {alert.get('count', '?')} instance(s){note}\n"
        )
    failed = blocking(found)
    sys.stdout.write(
        f"{len(found)} alert type(s); {len(failed)} of Medium risk or higher not accepted\n"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
