# 0005. A secret-less sandbox pool with per-run HMAC tickets

* Status: accepted
* Date: 2026-09-24

## Context
Parsing attacker-controlled HTML and spreadsheets with C-backed libraries (lxml,
zip, XML) is the most likely place for remote code execution. If the process doing
it holds database credentials or keys, one parser bug compromises every tenant.

## Decision
* A **sandbox** worker pool does all fetching and parsing of untrusted content. It has
  internet egress but no database, no storage mount, no key material and no provider
  credentials. Its settings class cannot even express those values.
* The pipeline dispatcher gives each run a ticket,
  `HMAC(pepper, "sandbox-ticket:v1:{org}:{run}:{attempt}")`. The ticket is the
  sandbox's only credential for:
  * downloading the input of that run (uploads);
  * submitting the result (or error code) of that run.
* The internal gateway verifies the ticket **before reading the body**, requires the
  run to be `RUNNING`, caps the body per run (derived from the input size or item
  limit), parses it off the event loop with structural bounds - large bodies one
  at a time - and stages it.
  Ingestion then validates it against the dataset schema. A retry increments
  `attempt` and invalidates old tickets. An upload's input can be downloaded once
  per attempt, so a copied ticket is worthless after the owning job fetched it.
* The sandbox's broker account cannot declare anything (`configure ^$`); it reads
  only the pre-declared `sandbox` queue and publishes only to its own exchange, so
  it can neither tap other queues nor forge work for other pools. The queue is
  bounded with `reject-publish`. Each job runs in a fresh process
  (`max_tasks_per_child=1`).
* The sandbox gets its own disposable Redis (`redis-sandbox`) for robots and
  throttle state; it has no account on the platform Redis.
* JavaScript rendering happens in a separate browser service reachable only from the
  sandbox.

## Consequences
* A code-execution bug triggered by one hostile page or file is contained to that
  job's process. A compromise of the whole sandbox container is contained to the
  *collected data of runs in flight*: with the pool's broker credentials it can
  drain the sandbox queue and submit falsified results for those runs (accepted
  residual risk, see THREAT_MODEL 4.3). It cannot read stored files, other runs,
  secrets or the database, and it cannot exhaust the platform Redis or queues.
* An extra hop (gateway) and staging per run. The result size is bounded by
  configuration.

## Alternatives considered
Parsing inside the database-connected workers, rejected for blast radius. A
per-run container or a Firecracker microVM gives stronger isolation at higher
operational cost; it is a natural next step.
