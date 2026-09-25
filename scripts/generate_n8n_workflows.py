"""Generate the five n8n workflow definitions in ``workflows/n8n``.

    uv run python scripts/generate_n8n_workflows.py [output-directory]

The JSON files are committed; this script is their source of truth. A unit test
fails when the committed files and the generator disagree, and
``scripts/validate_n8n_workflows.py`` lints the result.

Design: n8n orchestrates, Python executes. Every node either triggers (schedule,
JWT-authenticated webhook, error trigger), branches, waits, or calls the
platform's internal automation API with a per-workflow service token. The one
exception is workflow 5, which may ask n8n's own API to retry a failed
execution - with a dedicated credential that can do nothing else by policy.
Node and webhook ids are deterministic (UUIDv5), so re-running is a no-op.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any

API = "http://api-internal:8001/internal/v1/automation"
# n8n's own public API, used only to retry a failed execution (workflow 5).
N8N_EXECUTIONS_API = "http://127.0.0.1:5678/api/v1/executions/"
N8N_API_CREDENTIAL = "NexusFlow n8n API key"
ERROR_WORKFLOW = "REPLACE_WITH_FAILURE_RECOVERY_WORKFLOW_ID"
_NS = uuid.UUID("5f0c6f55-7d7c-4c7e-9a52-2f3d6f1a9e10")

EQUALS = {"type": "string", "operation": "equals"}
TRUE = {"type": "boolean", "operation": "true", "singleValue": True}
NOT_EMPTY = {"type": "string", "operation": "notEmpty", "singleValue": True}
# Keeps n8n-supplied names inside the platform's accepted character set.
SAFE = ".replace(/[^A-Za-z0-9 ._:()-]/g, '').slice(0, 80)"
SAFE_ID = ".replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64)"

type Node = dict[str, Any]


def nid(workflow: str, name: str) -> str:
    return str(uuid.uuid5(_NS, f"{workflow}/{name}"))


def settings(*, error_workflow: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "executionOrder": "v1",
        "saveDataErrorExecution": "all",
        "saveDataSuccessExecution": "none",
        "saveManualExecutions": False,
        "saveExecutionProgress": False,
        "executionTimeout": 300,
        "timezone": "UTC",
        "callerPolicy": "workflowsFromSameOwner",
    }
    if error_workflow:
        result["errorWorkflow"] = ERROR_WORKFLOW
    return result


def credential(kind: str, name: str) -> dict[str, Any]:
    return {kind: {"id": name.lower().replace(" ", "-"), "name": name}}


def schedule(wf: str, name: str, minutes: int, position: list[int]) -> Node:
    return {
        "id": nid(wf, name),
        "name": name,
        "type": "n8n-nodes-base.scheduleTrigger",
        "typeVersion": 1.2,
        "position": position,
        "parameters": {"rule": {"interval": [{"field": "minutes", "minutesInterval": minutes}]}},
    }


def webhook(wf: str, name: str, path: str, position: list[int]) -> Node:
    return {
        "id": nid(wf, name),
        "name": name,
        "type": "n8n-nodes-base.webhook",
        "typeVersion": 2,
        "position": position,
        "webhookId": nid(wf, "webhook:" + path),
        "parameters": {
            "httpMethod": "POST",
            "path": path,
            "authentication": "jwtAuth",
            "responseMode": "onReceived",
            "responseCode": 202,
            "options": {},
        },
        "credentials": credential("jwtAuth", "NexusFlow events JWT"),
    }


def http(
    wf: str,
    name: str,
    method: str,
    path: str,
    body: str | None,
    token: str,
    position: list[int],
) -> Node:
    parameters: dict[str, Any] = {
        "method": method,
        "url": path if path.startswith("=") else f"{API}{path}",
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "options": {"timeout": 30000, "redirect": {"redirect": {"followRedirects": False}}},
    }
    if body is not None:
        parameters.update({"sendBody": True, "specifyBody": "json", "jsonBody": body})
    return {
        "id": nid(wf, name),
        "name": name,
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.2,
        "position": position,
        "parameters": parameters,
        "credentials": credential("httpHeaderAuth", token),
        "retryOnFail": True,
        "maxTries": 3,
        "waitBetweenTries": 5000,
    }


def condition(
    wf: str, name: str, left: str, operator: dict[str, Any], right: object, position: list[int]
) -> Node:
    return {
        "id": nid(wf, name),
        "name": name,
        "type": "n8n-nodes-base.if",
        "typeVersion": 2,
        "position": position,
        "parameters": {
            "conditions": {
                "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose"},
                "conditions": [
                    {
                        "id": nid(wf, name + ":c"),
                        "leftValue": left,
                        "rightValue": right,
                        "operator": operator,
                    }
                ],
                "combinator": "and",
            },
            "options": {},
        },
    }


def link(*pairs: tuple[str, str, int]) -> dict[str, Any]:
    """``(source, target, output)`` triples -> n8n's connections structure."""
    connections: dict[str, Any] = {}
    for source, target, output in pairs:
        outputs = connections.setdefault(source, {"main": []})["main"]
        while len(outputs) <= output:
            outputs.append([])
        outputs[output].append({"node": target, "type": "main", "index": 0})
    return connections


def workflow(
    name: str, nodes: list[Node], connections: dict[str, Any], *, error_workflow: bool = True
) -> dict[str, Any]:
    return {
        "name": name,
        "nodes": nodes,
        "connections": connections,
        "settings": settings(error_workflow=error_workflow),
        "active": False,
        "pinData": {},
        "meta": {"templateCredsSetupCompleted": False},
        "tags": [{"name": "nexusflow"}],
    }


def collection_workflow() -> dict[str, Any]:
    wf = "collection"
    return workflow(
        "NexusFlow 1 - Data Collection",
        [
            schedule(wf, "Every minute", 1, [0, 0]),
            http(
                wf,
                "Dispatch due workflows",
                "POST",
                "/dispatch",
                "={{ JSON.stringify({ limit: 100 }) }}",
                "NexusFlow token - data collection",
                [260, 0],
            ),
            {
                "id": nid(wf, "One item per run"),
                "name": "One item per run",
                "type": "n8n-nodes-base.splitOut",
                "typeVersion": 1,
                "position": [520, 0],
                "parameters": {"fieldToSplitOut": "dispatched", "options": {}},
            },
        ],
        link(
            ("Every minute", "Dispatch due workflows", 0),
            ("Dispatch due workflows", "One item per run", 0),
        ),
    )


def detection_workflow() -> dict[str, Any]:
    wf = "detection"
    event = "$('Collection completed').item.json.body"
    return workflow(
        "NexusFlow 2 - Change Detection",
        [
            webhook(wf, "Collection completed", "nexusflow/collection-completed", [0, 0]),
            condition(wf, "Succeeded?", "={{ $json.body.status }}", EQUALS, "succeeded", [260, 0]),
            http(
                wf,
                "Detect changes",
                "POST",
                "/detect",
                f"={{{{ JSON.stringify({{ org_id: {event}.org_id, "
                f"dataset_id: {event}.dataset_id }}) }}}}",
                "NexusFlow token - change detection",
                [520, -100],
            ),
            condition(
                wf,
                "Part of a workflow run?",
                f"={{{{ {event}.workflow_run_id }}}}",
                NOT_EMPTY,
                "",
                [780, 0],
            ),
            http(
                wf,
                "Advance workflow run",
                "POST",
                f"={{{{ '{API}/organizations/' + {event}.org_id + '/workflow-runs/' + "
                f"{event}.workflow_run_id + '/advance' }}}}",
                None,
                "NexusFlow token - change detection",
                [1040, -100],
            ),
            schedule(wf, "Every 5 minutes", 5, [0, 300]),
            http(
                wf,
                "Sweep pending versions",
                "POST",
                "/detect/sweep",
                "={{ JSON.stringify({ limit: 200 }) }}",
                "NexusFlow token - change detection",
                [260, 300],
            ),
        ],
        link(
            ("Collection completed", "Succeeded?", 0),
            ("Succeeded?", "Detect changes", 0),
            ("Succeeded?", "Part of a workflow run?", 1),
            ("Detect changes", "Part of a workflow run?", 0),
            ("Part of a workflow run?", "Advance workflow run", 0),
            ("Every 5 minutes", "Sweep pending versions", 0),
        ),
    )


def analysis_workflow() -> dict[str, Any]:
    wf = "analysis"
    event = "$('Changes detected').item.json.body"
    return workflow(
        "NexusFlow 3 - AI Analysis",
        [
            webhook(wf, "Changes detected", "nexusflow/changes-detected/analysis", [0, 0]),
            condition(wf, "Analysis requested?", "={{ $json.body.analyze }}", TRUE, "", [260, 0]),
            http(
                wf,
                "Queue analysis",
                "POST",
                "/analyze",
                f"={{{{ JSON.stringify({{ org_id: {event}.org_id, "
                f"dataset_id: {event}.dataset_id }}) }}}}",
                "NexusFlow token - ai analysis",
                [520, -100],
            ),
        ],
        link(
            ("Changes detected", "Analysis requested?", 0),
            ("Analysis requested?", "Queue analysis", 0),
        ),
    )


def alerting_workflow() -> dict[str, Any]:
    wf = "alerting"
    return workflow(
        "NexusFlow 4 - Alerting",
        [
            webhook(wf, "Changes detected", "nexusflow/changes-detected/alerting", [0, 0]),
            http(
                wf,
                "Evaluate alert rules",
                "POST",
                "/alerts/evaluate",
                "={{ JSON.stringify({ org_id: $json.body.org_id }) }}",
                "NexusFlow token - alerting",
                [260, 0],
            ),
        ],
        link(("Changes detected", "Evaluate alert rules", 0)),
    )


def recovery_workflow() -> dict[str, Any]:
    """Workflow failure -> capture -> retry with exponential backoff -> dead letter -> page.

    The platform decides: it counts the failures of the execution's retry chain
    itself (n8n only reports ``retryOf``) and answers "retry after N seconds"
    or records a dead letter. n8n waits and asks its own API for the retry.
    """
    wf = "recovery"
    failed = "$('A workflow failed').item.json"
    job = "$('Platform job failed').item.json.body"
    credential_name = "NexusFlow token - failure recovery"  # a credential name, not a secret
    return workflow(
        "NexusFlow 5 - Failure Recovery",
        [
            {
                "id": nid(wf, "A workflow failed"),
                "name": "A workflow failed",
                "type": "n8n-nodes-base.errorTrigger",
                "typeVersion": 1,
                "position": [0, 0],
                "parameters": {},
            },
            http(
                wf,
                "Record failure",
                "POST",
                "/failures",
                "={{ JSON.stringify({ "
                f"workflow: String($json.workflow.name || 'unknown'){SAFE}, "
                f"node: String($json.execution.lastNodeExecuted || 'unknown'){SAFE}, "
                f"execution_id: String($json.execution.id || 'unknown'){SAFE_ID}, "
                f"retry_of: $json.execution.retryOf ? String($json.execution.retryOf){SAFE_ID} "
                ": null, "
                "error_message: "
                "String(($json.execution.error || {}).message || '').slice(0, 4000), "
                "idempotent: true }) }}",
                credential_name,
                [260, 0],
            ),
            condition(wf, "Retry allowed?", "={{ $json.retry }}", TRUE, "", [520, 0]),
            {
                "id": nid(wf, "Exponential backoff"),
                "name": "Exponential backoff",
                "type": "n8n-nodes-base.wait",
                "typeVersion": 1.1,
                "position": [780, -100],
                "webhookId": nid(wf, "webhook:backoff"),
                "parameters": {
                    "resume": "timeInterval",
                    "amount": "={{ $('Record failure').item.json.delay_seconds }}",
                    "unit": "seconds",
                },
            },
            http(
                wf,
                "Retry the execution",
                "POST",
                f"={{{{ '{N8N_EXECUTIONS_API}' + String({failed}.execution.id){SAFE_ID} "
                "+ '/retry' }}",
                "={{ JSON.stringify({ loadWorkflow: true }) }}",
                N8N_API_CREDENTIAL,
                [1040, -100],
            ),
            http(
                wf,
                "Page operators (n8n)",
                "POST",
                "/operator-alerts",
                "={{ JSON.stringify({ severity: 'warning', summary: ('n8n workflow ' + "
                f"String({failed}.workflow.name) + ' failed; dead letter ' + "
                "String($('Record failure').item.json.dead_letter_id)).slice(0, 500) }) }}",
                credential_name,
                [780, 100],
            ),
            webhook(wf, "Platform job failed", "nexusflow/job-failed", [0, 300]),
            # Defence in depth against paging loops: failures of the paging path
            # itself are never paged again (the platform also suppresses them).
            condition(
                wf,
                "Not a paging failure?",
                "={{ !['nexusflow.operators.alert', 'nexusflow.events.route', "
                "'nexusflow.events.forward'].includes(String($json.body.task)) }}",
                TRUE,
                "",
                [260, 300],
            ),
            http(
                wf,
                "Page operators (platform)",
                "POST",
                "/operator-alerts",
                "={{ JSON.stringify({ severity: 'warning', summary: ('Platform job ' + "
                f"String({job}.task) + ' failed: ' + String({job}.error_code) + "
                f"' (dead letter ' + String({job}.dead_letter_id) + ')').slice(0, 500) }}) }}}}",
                credential_name,
                [520, 300],
            ),
        ],
        link(
            ("A workflow failed", "Record failure", 0),
            ("Record failure", "Retry allowed?", 0),
            ("Retry allowed?", "Exponential backoff", 0),
            ("Exponential backoff", "Retry the execution", 0),
            ("Retry allowed?", "Page operators (n8n)", 1),
            ("Platform job failed", "Not a paging failure?", 0),
            ("Not a paging failure?", "Page operators (platform)", 0),
        ),
        error_workflow=False,
    )


def build() -> dict[str, dict[str, Any]]:
    """File name -> workflow document."""
    return {
        "01-data-collection.json": collection_workflow(),
        "02-change-detection.json": detection_workflow(),
        "03-ai-analysis.json": analysis_workflow(),
        "04-alerting.json": alerting_workflow(),
        "05-failure-recovery.json": recovery_workflow(),
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2) + "\n"


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else Path("workflows/n8n")
    out.mkdir(parents=True, exist_ok=True)
    for filename, document in build().items():
        (out / filename).write_text(render(document), encoding="utf-8", newline="\n")
        print("wrote", out / filename)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
