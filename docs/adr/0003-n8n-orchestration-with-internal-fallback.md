# 0003. n8n orchestrates through a narrow internal API; internal fallback mode

* Status: accepted
* Date: 2026-09-24

## Context
The product requires n8n as the central orchestrator so operators can see and
adapt flows visually. n8n is powerful (code nodes, credentials, arbitrary HTTP),
which makes it a high-value target and a potential single point of failure.

## Decision
* n8n decides **when**; Python decides **what is allowed**. n8n calls a dedicated
  internal API (private network only) with **one service token per workflow**, scoped
  to that workflow's steps.
* Internal endpoints return identifiers and counters only, never tenant content.
  Each step is idempotent and honours the tenant freeze and the global kill switch.
* The platform pushes domain events to n8n webhooks signed with a 60-second HS256 JWT.
* Workflows are code-reviewed JSON. A CI lint forbids code, command and file nodes,
  external URLs, redirects, inline credentials and unsigned webhooks.
* `NEXUSFLOW_N8N__ORCHESTRATION=internal` runs the same pipeline without n8n, for
  development and for incidents that require cutting n8n off.

## Consequences
* A compromised n8n can trigger work but cannot read tenant data through the API.
* Some logic exists in two places (n8n JSON and the event router); tests cover the
  internal router, and the lint covers the JSON.

## Alternatives considered
n8n with direct database access or with tenant API keys, rejected for blast radius.
Celery beat only, rejected because it does not meet the requirement for visual
orchestration.
