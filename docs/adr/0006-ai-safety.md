# 0006. AI: offline by default, tenant consent, tool gateway, strict output validation

* Status: accepted
* Date: 2026-09-24

## Context
Change analysis benefits from an LLM, but collected data is attacker-influenced
(indirect prompt injection) and may contain personal or confidential information
that must not leave the platform without consent.

## Decision
* A provider port with an **offline heuristic analyzer** as the default. The
  Anthropic provider (default model `claude-opus-5`, structured output, timeouts,
  circuit breaker) is used only for organizations that set `ai_external_processing`.
* Input hygiene:
  * schema-sensitive fields are removed;
  * free text is redacted (credentials, emails, cards, IBANs, phone numbers, IPs);
  * the context is bounded;
  * data is spotlighted inside a random boundary, with rules stating that it is data,
    not instructions.
* A **tool gateway** exposes two read-only, tenant- and dataset-scoped tools. Every
  call is checked against the allowlist, a strict argument schema, the principal's
  permission and a per-analysis budget. Results are redacted and size-capped.
* **Output validation**:
  * a strict schema;
  * no echo of the boundary;
  * cited change IDs must be real;
  * links are allowed only to hosts present in the data.

  Violations mark the insight `rejected` instead of storing it.
* Metrics on tool decisions feed a prompt-injection alert.

## Consequences
* Tenants control whether any data reaches a third party.
* The model can still be misled within valid outputs, so insights are advisory and
  labelled as AI-generated.

## Alternatives considered
Unrestricted agent tools (write access, URL fetching), rejected. Sending raw
records, rejected for privacy.
