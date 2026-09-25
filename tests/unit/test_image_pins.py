"""Every image is pinned by digest, in a form Dependabot can update (review F-6).

Base images were ARG defaults used as ``FROM ${...}`` and Compose images read
``repo:${VAR:-tag@digest}``; Dependabot parses neither (it resolves a Compose
default only when the whole value is ``${VAR:-...}``), so no base or
third-party image would ever have been proposed an update.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64


@pytest.fixture(scope="module")
def pins() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pin_images", ROOT / "scripts" / "pin_images.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_every_reference_in_the_repository_is_pinned(pins: ModuleType) -> None:
    references = [
        ref
        for path in pins._files()
        for ref in pins.scan(path.read_text(encoding="utf-8"), path.name)
    ]
    assert len(references) >= 15
    assert [f"{r.path}:{r.line}" for r in references if r.digest is None] == []


COMPOSE_FILES = ["docker-compose.yml", "docker-compose.dev.yml", "docker-compose.demo.yml"]


@pytest.mark.parametrize("name", COMPOSE_FILES)
def test_compose_images_are_whole_value_defaults(name: str) -> None:
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        if not line.strip().startswith("image:"):
            continue
        value = line.split("image:", 1)[1].split(" #", 1)[0].strip()  # YAML drops comments
        assert re.fullmatch(r"\$\{\w+_IMAGE:-[^}]+\}", value), line  # Dependabot's form
        assert "@sha256:" in value or ":latest}" in value, line  # third-party or built here


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.browser"])
def test_dockerfiles_use_literal_pinned_from_lines(name: str) -> None:
    text = (ROOT / "docker" / name).read_text(encoding="utf-8")
    assert "FROM ${" not in text
    assert re.match(r"# syntax=docker/dockerfile:[\d.]+@sha256:[0-9a-f]{64}\n", text)
    froms = re.findall(r"^FROM (\S+)", text, re.MULTILINE)
    assert froms and all("@sha256:" in image for image in froms)


def test_the_weekly_scan_covers_every_image_that_runs_as_it_is(pins: ModuleType) -> None:
    images = pins.runtime_images()
    repos = {image.split("@")[0].rsplit(":", 1)[0] for image in images}
    assert all(re.fullmatch(r"[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}", image) for image in images)
    compose = {
        match[1]
        for name in COMPOSE_FILES
        for match in re.finditer(r"\$\{\w+_IMAGE:-([^:}]+):", (ROOT / name).read_text("utf-8"))
    }
    assert compose - pins.LOCAL_IMAGES <= repos
    # Base images are scanned as part of the images built from them (CI).
    assert not repos & {"python", "ghcr.io/astral-sh/uv", "mcr.microsoft.com/playwright/python"}
    assert not any(repo.endswith("/dockerfile") for repo in repos)


def test_scan_and_pin_cover_every_form_and_skip_the_images_built_here(pins: ModuleType) -> None:
    text = "\n".join(
        [
            "# syntax=docker/dockerfile:1.7",
            "FROM python:3.12-slim AS builder",
            "FROM ghcr.io/astral-sh/uv:0.12.18",
            "    image: ${POSTGRES_IMAGE:-postgres:17-alpine}",
            "    image: ${NEXUSFLOW_IMAGE:-nexusflow-ai:latest}",
            "    image: postgres:17-alpine  # a CI service container",
            "",
        ]
    )
    found = pins.scan(text, "sample")
    assert [(r.repo, r.tag, r.digest) for r in found] == [
        ("docker/dockerfile", "1.7", None),
        ("python", "3.12-slim", None),
        ("ghcr.io/astral-sh/uv", "0.12.18", None),
        ("postgres", "17-alpine", None),
        ("postgres", "17-alpine", None),
    ]
    pinned = pins.pin(text, lambda repo, tag: DIGEST)
    assert pinned.splitlines() == [
        f"# syntax=docker/dockerfile:1.7@{DIGEST}",
        f"FROM python:3.12-slim@{DIGEST} AS builder",
        f"FROM ghcr.io/astral-sh/uv:0.12.18@{DIGEST}",
        f"    image: ${{POSTGRES_IMAGE:-postgres:17-alpine@{DIGEST}}}",
        "    image: ${NEXUSFLOW_IMAGE:-nexusflow-ai:latest}",
        f"    image: postgres:17-alpine@{DIGEST}  # a CI service container",
    ]
    assert pins.pin(pinned, lambda repo, tag: DIGEST) == pinned  # idempotent
