# 0010. A modular monolith with a planned extraction path

* Status: accepted
* Date: 2026-09-24

## Context
The specification asks for a modular design that can later move to
independently deployable services. Splitting into services on day one would
multiply the operational surface (deployments, networks, distributed
transactions, versioned contracts) before any part has a reason to scale or
change on its own - and every extra network hop is another trust boundary to
secure.

## Decision
* One code base and one PostgreSQL database, deployed as **several processes with
  different privileges**: public API, internal API, pipeline, integrations and
  sandbox worker pools, the browser service and beat. Isolation is by process,
  network and credentials already, where security needs it.
* Business modules (`identity`, `organizations`, `catalog`, `sources`,
  `pipeline`, `records`, `intelligence`, `alerts`, `notifications`, `reports`,
  `automation`, `webhooks`, `uploads`, `audit`) live in `domain/` and depend on
  ports, never on infrastructure; import-linter enforces the layers in CI.
* Modules communicate through **identifiers and events on the transactional
  outbox**, not through shared in-memory state. The outbox messages are the
  contracts a future service boundary would keep.
* Extraction, when a module needs it (independent scaling, release cadence or a
  separate team), follows the same recipe: give the module its own schema and
  database role (its tables already carry `org_id` and RLS), move its outbox
  consumers into a new deployable, and replace the in-process calls into it with
  the existing message contracts or a narrow internal API such as the one n8n
  and the sandbox already use.
* The first candidates are the ones with different resource profiles:
  collection (the sandbox and browser already run separately), AI analysis
  (provider latency and cost) and report rendering (CPU, memory).

## Consequences
* One transaction covers a state change and its follow-up work; there are no
  distributed transactions and no saga machinery to secure.
* The shared unit of work exposes every module's repositories, so a module can
  reach another module's tables in code; the layering contract does not prevent
  that, code review does. Extraction starts by removing those reads.
* Horizontal scaling is by process pool today; the database is the shared core
  and must be scaled vertically or with read replicas until a module moves out.

## Alternatives considered
* **Microservices from the start**: rejected - more attack surface and
  operational cost than the problem needs, and contracts would freeze before the
  domain settles.
* **A single process**: rejected - hostile content (web pages, uploads) must be
  parsed where no database or secret is reachable, which needs separate
  processes with separate credentials anyway.
