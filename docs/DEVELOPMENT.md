# Development

## Setup

Requirements: Python 3.12+ and [uv](https://docs.astral.sh/uv/). Docker is only
needed for the full stack.

```bash
uv sync --group dev --group localdb
```

The `localdb` group installs `pgserver`, an embedded PostgreSQL, so integration tests
run without Docker. Alternatively, point `NEXUSFLOW_TEST_DATABASE_URL` at a superuser
URL of a disposable server, as CI does.

To run the application against real infrastructure, see `docker-compose.dev.yml`
and the *local development* block in `.env.example`.

## Quality gates

| Command | What it checks |
|---|---|
| `make lint` | Ruff lint and format, mypy `--strict`, import-linter architecture contracts |
| `make security` | Bandit, pip-audit against the hash-locked export, n8n workflow lint |
| `make test` | Unit tests |
| `make test-all` | Unit, integration, security, worker and CLI tests against real PostgreSQL |
| `make check` | All of the above, as CI runs them |
| `make e2e` | End-to-end tests against the running demo stack (`make demo-up` first) |
| `make demo` | The scripted walkthrough against the running demo stack ([DEMO.md](DEMO.md)) |
| `make config-docs` | Regenerate [CONFIGURATION.md](CONFIGURATION.md) from the settings classes |

CI also runs Semgrep, Gitleaks, CodeQL, the image builds, Trivy and SBOM generation
for both images, and the end-to-end suite against the full Compose stack behind the
TLS edge. Third-party actions are pinned to commit SHAs.

## Test strategy

* **Unit** (`tests/unit`):
  * crypto primitives, tokens and signatures, log redaction, the core utilities;
  * the SSRF guard (DNS rebinding, IPv6-embedded addresses, redirects, response
    truncation, decompression bombs);
  * the adapters: HTML extraction, robots.txt (RFC 9309 precedence, wildcards,
    redirects), host throttling, the website and REST collectors (pagination,
    credentials, truncation), notification senders (Slack, Telegram, signed
    webhooks, SMTP failure classes), the Anthropic provider (request shape,
    error mapping, circuit breaker) and the ClamAV client;
  * the core chain: change detection (thresholds, golden records, property-based
    tests), alert rule matching and de-duplication, the offline analyser;
  * each pipeline stage, report analytics and rendering;
  * the worker failure policy, liveness heartbeats, the browser guard, the n8n
    workflow generator and lint, and configuration consistency (the generated
    reference is current, every Compose variable is a real setting).
* **Integration** (`tests/integration`): real PostgreSQL with production-like roles.
  The tests connect as the `NOBYPASSRLS` application role, so row-level security is
  really exercised. They cover:
  * identity flows (lockout, MFA replay, refresh reuse);
  * database security (RLS, privilege escalation, audit immutability, migration
    drift);
  * the business API end to end;
  * the core chain end to end - a signed webhook through detection, alerting,
    notification delivery (retries, throttling, dead letters) and reports - with
    every outbox message run by the real worker handlers;
  * crash recovery by the reaper, and the fencing of late results;
  * the sandbox gateway and ticket boundary;
  * event routing and the operator CLI;
  * the presenter's walkthrough (`scripts/demo.py`) over real HTTP against the API
    served by uvicorn.
* **Security** (`tests/security`): HTTP-level regression tests for authentication,
  authorization, tenant isolation, input handling, error leakage, headers and rate
  limits.

* **End to end** (`tests/e2e`, marker `e2e`): the business scenario and the edge's
  security properties (published paths, headers, tenant isolation, forged webhooks,
  body limits) against a running stack through nginx and TLS. Skipped unless
  `NEXUSFLOW_E2E_BASE_URL` is set; CI runs them against the Compose stack.

Below the end-to-end suite, Redis is replaced by `fakeredis` (with Lua for the GCRA
limiter), and the broker by an in-process bus (`tests/support/bus.py`) that runs
every committed outbox message through the real worker handlers.

## Conventions

* **Layers**: `apps → bootstrap → infrastructure → domain → core`. The domain never
  imports a framework, and CI enforces this.
* **Every service method** starts with `principal.require(Permission.…)` and
  `principal.require_org()`, then opens a unit of work with `TenantScope.of(principal)`.
  Routes add `Depends(require(...))` as well: defence in depth.
* **Errors**: raise `NexusFlowError` subclasses. `message` is client-safe; put
  internals in `internal_detail`, which is only logged.
* **Idempotency**: anything a worker, n8n or a retry can repeat must be safe to repeat
  (state machines, unique constraints, `Idempotency-Key`).
* **Outbound HTTP**: always use `SafeHttpClient` with a `UrlPolicy`. Never create a
  raw client for user-influenced URLs.
* **Messages and events** carry identifiers only.
* **Secrets**: `SecretStr` in configuration, `*_FILE` in deployments, never in logs
  or responses. The `_FILE` suffix is reserved for that indirection: never name a
  setting or another `NEXUSFLOW_*` variable `..._file` (a test enforces it).
* **Configuration**: a new setting needs `make config-docs`; a test fails while
  CONFIGURATION.md is stale.

## Adding a tenant table

1. Add the table to `infrastructure/database/tables/data.py` with an `org_id` column.
2. Map the entity in `mapping.py` and add a repository that filters by `org_id`.
3. Create a migration (`uv run alembic revision -m "..."`) that enables and forces
   RLS, adds the tenant policy and grants the application role only the privileges
   it needs. Follow `0002_business_data.py`.
4. Nothing to add to the tests: `test_database_security.py` enumerates every table
   in the schema and fails for one without forced RLS and a policy (unless it is a
   documented exception), and the migration-drift test fails if the ORM and the
   migrations disagree.

## Security review checklist for pull requests

The specification's checklist (section 39), applied to every change. Tick an item
only after reading the implementation; record findings in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).

- [ ] **Authentication / authorization**: new endpoints have a permission
      dependency *and* a service-level check; tests for 401, 403 and a cross-tenant
      404 (extend `tests/security/test_idor_sweep.py`).
- [ ] **Input validation**: strict request model (`extra="forbid"`); every input
      bounded (length, count, depth, size).
- [ ] **Output encoding**: nothing tenant-controlled reaches CSV, XLSX, PDF or logs
      unescaped; downloads are attachments.
- [ ] **Injection**: bound parameters only; no string-built SQL, shell or code.
- [ ] **SSRF**: outbound calls go through `SafeHttpClient` with a `UrlPolicy`.
- [ ] **CSRF / XSS**: no cookie-based authentication; JSON responses only.
- [ ] **Secrets**: encrypted at rest, never logged or returned after creation; new
      settings never named `..._file`.
- [ ] **Logging**: no secrets or personal data in log fields; errors keep internals in
      `internal_detail`.
- [ ] **Rate limiting and resource exhaustion**: a rate-limit scope; timeouts and caps
      on anything that can grow.
- [ ] **Tenant isolation**: `org_id` filter in the repository; RLS on new tables.
- [ ] **Race conditions, replay, idempotency**: repeated or concurrent execution is
      safe (state machines, unique constraints, row locks, `Idempotency-Key`).
- [ ] **Error leakage**: uniform error schema; no stack traces or SQL in responses.
- [ ] **Dependencies**: new packages pinned in `uv.lock`; `make security` is clean.
- [ ] **Audit**: security-relevant actions recorded.
- [ ] **Documentation**: threat model and docs updated when a trust boundary changes;
      `make config-docs` when settings change.
