"""docs/CONFIGURATION.md is generated from the settings classes and must not drift."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from nexusflow.core.config import BrowserServiceSettings, SandboxSettings, Settings

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_config_reference", ROOT / "scripts" / "gen_config_reference.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_reference_matches_the_settings(generator: ModuleType) -> None:
    committed = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    assert generator.render() == committed, "run `make config-docs`"


def test_every_setting_is_documented(generator: ModuleType) -> None:
    document = generator.render()
    for section, field in Settings.model_fields.items():
        model = field.annotation
        assert model is not None
        for name in model.model_fields:  # type: ignore[union-attr]
            assert f"`NEXUSFLOW_{section.upper()}__{name.upper()}`" in document


def test_secret_defaults_are_never_printed(generator: ModuleType) -> None:
    document = generator.render()
    assert "change-me" not in document  # the development database password
    assert "guest:guest" not in document  # the development broker credentials


SETTINGS_CLASSES = (Settings, SandboxSettings, BrowserServiceSettings)
# Variables read by the container harness, not by a settings class: the health
# probe and heartbeat (docker/healthcheck.py) and nginx's server-name template.
HARNESS_VARIABLES = {
    "NEXUSFLOW_HEALTHCHECK",
    "NEXUSFLOW_HEALTHCHECK_PORT",
    "NEXUSFLOW_HEARTBEAT_PATH",
    "NEXUSFLOW_DOMAIN",
}


def _setting_paths() -> set[tuple[str, str]]:
    paths: set[tuple[str, str]] = set()
    for settings in SETTINGS_CLASSES:
        for section, field in settings.model_fields.items():
            model = field.annotation
            assert model is not None
            paths.update((section, name) for name in model.model_fields)  # type: ignore[union-attr]
    return paths


def test_no_setting_ends_in_file() -> None:
    # "<VARIABLE>_FILE" means "read <VARIABLE> from this file" to the loader, so a
    # setting named "..._file" could never be set, and its variable would be read
    # as a secret file (a CA bundle once broke worker start-up exactly like this).
    assert not [path for path in _setting_paths() if path[1].endswith("_file")]


@pytest.mark.parametrize("compose_file", ["docker-compose.yml", "docker-compose.demo.yml"])
def test_every_compose_variable_is_a_real_setting(compose_file: str) -> None:
    document = yaml.safe_load((ROOT / compose_file).read_text(encoding="utf-8"))
    known = _setting_paths()
    unknown: list[str] = []
    for service in document["services"].values():
        environment = service.get("environment") or {}
        for variable in environment:
            if not variable.startswith("NEXUSFLOW_"):
                continue
            if "__" not in variable:
                if variable not in HARNESS_VARIABLES:
                    unknown.append(variable)
                continue
            dotted = variable.removeprefix("NEXUSFLOW_").lower().removesuffix("_file")
            section, _, name = dotted.partition("__")
            if (section, name) not in known:
                unknown.append(variable)
    assert unknown == []
