"""The single sign-on overlay gives the public API internet access - and nothing else."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _compose(name: str) -> Any:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def test_the_overlay_only_adds_the_public_api_to_the_egress_network() -> None:
    overlay = _compose("docker-compose.sso.yml")
    base = _compose("docker-compose.yml")
    assert set(overlay) == {"services"}  # no new networks, volumes or secrets
    assert set(overlay["services"]) == {"api"}  # not the internal API, not a worker
    api = overlay["services"]["api"]
    assert set(api) == {"networks"}  # no image, command, environment or ports
    assert api["networks"] == [*base["services"]["api"]["networks"], "egress"]


def test_the_egress_network_isolates_the_containers_on_it() -> None:
    # Internet access only: the containers on it (the sandbox, the browser, the
    # integrations worker, ClamAV - and, with the overlay, the public API) cannot
    # reach each other through it.
    egress = _compose("docker-compose.yml")["networks"]["egress"]
    assert egress["driver_opts"]["com.docker.network.bridge.enable_icc"] == "false"
    assert not egress.get("internal", False)
