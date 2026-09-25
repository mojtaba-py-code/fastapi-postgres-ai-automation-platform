#!/usr/bin/env python3
"""Security lint for the n8n workflow definitions in ``workflows/n8n``.

n8n workflows are code that runs with credentials, so they are reviewed like
code. This check fails (exit 1) when a workflow:

* uses a node type that can execute code, run commands, touch files or open
  arbitrary connections (Code, Function, Execute Command, SSH, FTP, ...);
* sends HTTP requests anywhere but the platform's internal automation API -
  or, with its dedicated credential only, n8n's own execution-retry endpoint -
  or follows redirects;
* waits for anything but a time interval (a webhook/form "resume" would open
  an unauthenticated URL);
* authenticates with inline headers instead of stored credentials, or embeds
  anything that looks like a secret;
* exposes a webhook without JWT authentication;
* stores successful execution data (tenant identifiers would accumulate in
  n8n's database), has no execution timeout, or no error workflow;
* has connections that reference unknown nodes.

Usage: ``python scripts/validate_n8n_workflows.py [directory]``
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

INTERNAL_API = "http://api-internal:8001/internal/v1/"
# n8n's own public API: workflow 5 may retry a failed execution, nothing else.
# The only dynamic part allowed is the error trigger's execution id, stripped to
# [A-Za-z0-9_-] - no slashes or dots, so no other API path can be reached.
N8N_RETRY_API = "http://127.0.0.1:5678/api/v1/executions/"
N8N_API_CREDENTIAL = "NexusFlow n8n API key"
_N8N_RETRY_URL = re.compile(
    r"\{\{ '"
    + re.escape(N8N_RETRY_API)
    + r"' \+ String\(\$\('[A-Za-z0-9 ._()-]+'\)\.item\.json\.execution\.id\)"
    + re.escape(".replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64)")
    + r" \+ '/retry' \}\}"
)
ALLOWED_NODE_TYPES = frozenset(
    {
        "n8n-nodes-base.scheduleTrigger",
        "n8n-nodes-base.webhook",
        "n8n-nodes-base.errorTrigger",
        "n8n-nodes-base.httpRequest",
        "n8n-nodes-base.if",
        "n8n-nodes-base.splitOut",
        "n8n-nodes-base.wait",
        "n8n-nodes-base.noOp",
    }
)
SECRET_PATTERNS = (
    re.compile(r"\bnx[fs]_[a-z2-7]{12}_[A-Za-z0-9_-]{20,}"),  # NexusFlow keys / service tokens
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWTs
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
REQUIRED_SETTINGS = {"saveDataSuccessExecution": "none", "saveManualExecutions": False}


def _problems(path: Path, workflow: dict[str, Any]) -> list[str]:
    raw = json.dumps(workflow)
    problems = [
        f"possible secret matching {pattern.pattern[:30]!r}"
        for pattern in SECRET_PATTERNS
        if pattern.search(raw)
    ]
    problems += [
        f"missing {key!r}"
        for key in ("name", "nodes", "connections", "settings")
        if key not in workflow
    ]
    if problems:
        return problems
    return (
        _settings_problems(workflow)
        + [problem for node in workflow["nodes"] for problem in _node_problems(node)]
        + _connection_problems(workflow)
    )


def _settings_problems(workflow: dict[str, Any]) -> list[str]:
    settings = workflow["settings"]
    problems = [
        f"settings.{key} must be {expected!r}"
        for key, expected in REQUIRED_SETTINGS.items()
        if settings.get(key) != expected
    ]
    timeout = settings.get("executionTimeout")
    if not isinstance(timeout, int) or timeout <= 0:
        problems.append("settings.executionTimeout must be a positive number of seconds")
    types = {node.get("type") for node in workflow["nodes"]}
    if "n8n-nodes-base.errorTrigger" not in types and not settings.get("errorWorkflow"):
        problems.append("settings.errorWorkflow must point to the failure-recovery workflow")
    return problems


def _node_problems(node: dict[str, Any]) -> list[str]:
    label = f"node {node.get('name')!r}"
    node_type = node.get("type")
    parameters = node.get("parameters", {})
    if node_type not in ALLOWED_NODE_TYPES:
        return [f"{label}: node type {node_type!r} is not allowed"]
    if node_type == "n8n-nodes-base.webhook" and parameters.get("authentication") != "jwtAuth":
        return [f"{label}: webhooks must use JWT authentication"]
    if node_type == "n8n-nodes-base.wait" and parameters.get("resume") != "timeInterval":
        return [f"{label}: waits may only resume after a time interval"]
    if node_type == "n8n-nodes-base.httpRequest":
        return [f"{label}: {issue}" for issue in _http_problems(node, parameters)]
    return []


def _connection_problems(workflow: dict[str, Any]) -> list[str]:
    names = {node.get("name") for node in workflow["nodes"]}
    problems = [
        f"connection from unknown node {source!r}"
        for source in workflow["connections"]
        if source not in names
    ]
    problems += [
        f"connection to unknown node {target.get('node')!r}"
        for outputs in workflow["connections"].values()
        for branch in outputs.get("main", [])
        for target in branch or []
        if target.get("node") not in names
    ]
    return problems


def _target_problem(node: dict[str, Any], url: str) -> str | None:
    literal = url.removeprefix("=")
    credential = node.get("credentials", {}).get("httpHeaderAuth", {}).get("name")
    if literal.startswith(INTERNAL_API) or f"'{INTERNAL_API}" in literal:
        if credential == N8N_API_CREDENTIAL:
            return f"the {N8N_API_CREDENTIAL!r} credential is only for n8n's retry endpoint"
        return None
    if _N8N_RETRY_URL.fullmatch(literal):
        if credential != N8N_API_CREDENTIAL:
            return f"n8n's retry endpoint requires the {N8N_API_CREDENTIAL!r} credential"
        return None
    return f"requests may only target {INTERNAL_API} (got {url[:60]!r})"


def _http_problems(node: dict[str, Any], parameters: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    target_problem = _target_problem(node, str(parameters.get("url", "")))
    if target_problem:
        problems.append(target_problem)
    if parameters.get("authentication") != "genericCredentialType" or not node.get("credentials"):
        problems.append("must authenticate with a stored credential")
    if parameters.get("sendHeaders") or parameters.get("headerParameters"):
        problems.append("inline headers are not allowed (credentials carry authentication)")
    redirect = parameters.get("options", {}).get("redirect", {}).get("redirect", {})
    if redirect.get("followRedirects", True):
        problems.append("redirects must not be followed")
    return problems


def main(argv: list[str]) -> int:
    directory = Path(argv[1]) if len(argv) > 1 else Path("workflows/n8n")
    files = sorted(directory.glob("*.json"))
    if not files:
        print(f"no workflow files in {directory}", file=sys.stderr)
        return 1
    failed = False
    for path in files:
        try:
            workflow = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"{path}: invalid JSON ({exc})")
            failed = True
            continue
        problems = _problems(path, workflow)
        for problem in problems:
            print(f"{path}: {problem}")
        failed = failed or bool(problems)
        if not problems:
            print(f"{path}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
