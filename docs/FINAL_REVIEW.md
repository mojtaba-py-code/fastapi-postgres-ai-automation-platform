# Final review

The specification asks for a final architecture, security, dependency, test and
deployment review, and an honest list of remaining limitations. This is that
review, as of 2026-09-25.

**Verdict.** NexusFlow AI is a complete, well-tested reference implementation of
a secure automation and intelligence platform, ready for a pilot. It is not yet
production-proven: the container stack has not been run outside CI (its startup
was reviewed statically, and the CI end-to-end job has not run yet), no
independent penetration test has been done, and enterprise features such as SSO,
high availability and an admin UI are on the roadmap (section 7).

## 1. Architecture review

| Aspect | Assessment |
|---|---|
| Layering | Clean architecture `apps -> bootstrap -> infrastructure -> domain -> core`, enforced in CI by import-linter; the domain imports no framework (no FastAPI, SQLAlchemy, Celery, Redis, HTTP or AI SDK) |
| Size | 196 modules, about 29,000 lines of Python; 6 migrations (the initial schema in two parts, and four additive ones); 10 ADRs |
| Components | Public API, internal API (n8n and sandbox), pipeline and integrations workers, sandbox worker, headless browser, beat, n8n (optional), PostgreSQL, Redis (two instances), RabbitMQ, nginx, Prometheus, Alertmanager, Grafana |
| Trust boundaries | Edge (TLS, limits); tenant isolation (forced RLS plus `org_id` filters); sandbox (no DB, no secrets, per-run tickets); browser (pinning egress proxy); n8n (per-workflow service tokens, signed events). Every entry point is enumerated in the [threat model](THREAT_MODEL.md) (section 3.1) |
| Reliability | Transactional outbox; idempotent workers; quorum queues with dead-lettering, delayed retries held by the broker; reaper with bounded attempts and fencing; heartbeat health; one request ID from the API into every job it causes |
| Extensibility | Ports and adapters for providers (AI, storage, scanning, notifications); new source kinds and channels are adapters; the domain services are independent of the transport |
| Scaling path | Stateless APIs and workers scale horizontally; per-pool queues; the database is the shared core, and reports and analytics aggregate in it. Single-host Compose is the reference topology. The modular monolith has a documented extraction path to services ([ADR-0010](adr/0010-modular-monolith-and-service-extraction.md)); see section 7 |

Findings of the review were fixed in place (for example the explicit pipeline
stages, report analytics aggregated in the database and the data-lifecycle
audit); see [ARCHITECTURE.md](ARCHITECTURE.md).

## 2. Security review

Nine AI-assisted review passes (adversarial code review, due diligence,
traceability, test-driven reviews of the adapters, the core chain and of hostile
uploads and rate limits, a deployment startup review, and two completion
reviews) produced 76 numbered findings plus smaller observations. All are fixed
with regression tests (or, for configuration, in the file named as evidence),
except one accepted risk (sign-up reveals registered e-mails; it is
rate-limited). The full record, including the specification's security
checklist, is in [SECURITY_REVIEW.md](SECURITY_REVIEW.md); residual risks are in
the [threat model](THREAT_MODEL.md). A self-assessed mapping to the seventeen
chapters of OWASP ASVS 5.0 (target Level 2, with selected Level 3 controls),
with evidence and the remaining gaps, is in [ASVS.md](ASVS.md).

## 3. Dependency and supply-chain audit

* Dependencies are locked with hashes (`uv.lock`) and installed with
  `--frozen`; CI audits the locked export with `pip-audit --require-hashes`.
* `pip-audit` over the complete development environment on 2026-09-25:
  **no known vulnerabilities**.
* CI also runs Bandit, Semgrep (pinned), CodeQL and Gitleaks, and scans both
  images with Trivy (fail on fixable High/Critical) and produces an SBOM for each.
* CI actions are pinned to commit SHAs; base images (Dockerfiles) and
  third-party images (Compose, CI) are pinned to digests, and CI fails if one
  loses its digest (`make pin-images` refreshes them); Dependabot proposes updates
  weekly.
* The workflows themselves are audited by zizmor (pedantic persona, with online
  checks for impostor commits and known-vulnerable actions): no findings. Once
  the repository is public, dependency review blocks a pull request that adds a
  vulnerable (moderate or worse) or GPL/AGPL-3.0 dependency, and OpenSSF Scorecard
  grades the repository weekly; both are skipped on the private repository, like
  CodeQL.
* A version tag runs the release workflow: both images are scanned, pushed to
  GHCR with SBOM and provenance attestations, and signed keyless with cosign.
  No release has been published yet.

## 4. Test review

| Layer | Tests | What they exercise |
|---|---|---|
| Unit | 1,214 | Crypto, tokens, SSRF guard, log redaction, all adapters (scraping, robots.txt, collectors, senders, AI provider, ClamAV, n8n client), the core chain (detection, alert rules, offline analysis, property-based tests), pipeline stages, reports and analytics, sign-in risk, request correlation, hostile uploads (hand-built zip bombs, traversal, macros, XXE, sparse sheets), the rate limiter, TLS client configuration, worker policy and liveness, n8n generator and lint, configuration and broker consistency |
| Integration | 139 | Real PostgreSQL with production roles (RLS really enforced): identity and sign-in risk, database security, the business API and change analytics, the core chain end to end with the real worker handlers, crash recovery, data lifecycle, workflows, request correlation, backup and restore (`pg_dump`/`pg_restore` with the production roles), the CLI, and the demo walkthrough over real HTTP |
| Security | 87 | Authentication, authorization, an IDOR sweep over every resource route, API-key lifecycle, login locking, every rate-limit scope and its failure policy, hostile uploads through the API, input handling, headers, error leakage |
| End to end | 11 | The business scenario and the edge's security properties against the running Compose stack (CI), followed by a backup, restore and audit verification; skipped without a stack |

* The last full run: 1,440 passed (the 11 end-to-end tests are skipped without a
  stack); line and branch coverage 87 %, with a CI floor of 80 %.
* Defects found by writing tests were pinned as strict expected failures first,
  then fixed.
* Not covered by automated tests: a real n8n instance, a real Chromium, real
  SMTP/Slack/Telegram endpoints (all tested against faithful fakes at the
  protocol boundary), and a real Redis and RabbitMQ outside the end-to-end job
  (`fakeredis` with Lua elsewhere).

## 5. Deployment review

| Checked | How |
|---|---|
| Startup | Reviewed statically (R7): the Compose files resolved with the example environment; settings and application objects of all 8 application roles built with exactly the variables and secrets Compose gives them; every image tag resolved in its registry; nginx, Prometheus, RabbitMQ, Docker DNS, Grafana and Mailpit behaviour checked against their sources. The one certain startup failure (Prometheus) and 14 further findings are fixed |
| Compose configuration | Every `NEXUSFLOW_*` variable in the Compose files is a real setting; every mounted secret is generated; settings refuse insecure production values |
| Images | Non-root and read-only for the platform's own containers; no capabilities, `no-new-privileges` and memory limits everywhere (the exceptions of upstream images are named in the Compose header); built and scanned in CI; pinned by digest |
| Networks | Only nginx publishes ports (admin UIs on 127.0.0.1); internal networks everywhere else; egress only for the pools that need it, without inter-container traffic |
| Secrets | Files under `/run/secrets`, each mounted only into the containers that use it |
| Health | HTTP probes for the APIs; event-loop heartbeats for workers and beat |
| Operations | Backups (encrypted; the restore procedure tested against PostgreSQL with the production roles, and end to end in CI), key rotation procedures, runbooks, audit anchoring |

**Not verified in the development environment:** the stack itself was never
started there (no Docker). CI's end-to-end job builds the images, starts the
stack with the demo overlay behind TLS, runs the end-to-end suite, then backs the
stack up, changes it, restores it and verifies the audit chains; its first run,
and a clean-host dry run, are the gate before any production use. The release
workflow has not run either.

## 6. Specification coverage

A traceability audit mapped the specification's 551 requirements to the code.
At audit time 461 were implemented, 72 partial and 7 missing. All 7 missing
items were closed: the end-to-end suite, auditing of automation steps, adapter
tests, a full-chain test, and the final architecture, test and deployment
reviews (this document). The partial items that mattered were completed (for
example the explicit pipeline stages, trends and anomalies in reports, enforced
data classification, the platform audit chain, workflow 5's retry with backoff,
`/api/v1/users`, worker tracing and metrics, request correlation and the
configuration reference). The remaining partial items are listed as limitations
below.

## 7. Known limitations and roadmap

**Before a production deployment**
1. Get the first CI run green, including the end-to-end job and its backup and
   restore, and do a clean-host dry run.
2. Commission an independent penetration test.
3. Publish the first signed release (tag `v0.1.0`) and deploy it by digest.

**Enterprise features**
4. SSO (OIDC, SAML), SCIM provisioning and phishing-resistant MFA (WebAuthn,
   passkeys); today: local passwords with TOTP, per-organization network
   allowlists, and API keys that follow their creator's membership.
5. An admin web UI; today the product is API-first (Swagger is disabled in
   production).
6. High availability and disaster recovery: managed PostgreSQL with
   point-in-time recovery, a RabbitMQ cluster, managed Redis, object storage for
   uploads and reports, Kubernetes manifests, and stated RPO/RTO. Today: one
   host, encrypted and tested backups.
7. Privacy tooling: subject-access export and per-person erasure inside tenant
   datasets, a retention policy for audit logs (the purge function exists),
   data-residency controls for the AI provider, and DPA/ROPA templates.

**Hardening and operations**
8. TLS on internal hops (database, Redis, broker) for multi-host deployments: the
   clients verify servers against a private CA (tested) and the server-side steps
   are documented, but the Compose file does not ship that configuration; on one
   host the traffic stays on internal networks and startup logs a warning.
9. The application encrypts sensitive field values, staged payloads, uploads and
   reports at rest; the other fields of tenant data are plaintext in PostgreSQL so
   they can be queried - use disk or volume encryption, and mark personal data
   `sensitive`. Keys live in files mounted as Docker secrets; a hardware or cloud
   KMS is on the roadmap.
10. Sign-in risk uses devices, networks and failures, not geolocation
    (impossible-travel checks need a GeoIP database).
11. The sandbox's delayed retries (at most three, 20-100 s apart) still occupy a
    worker slot while they wait: its exchange must stay direct, so that its
    broker account cannot reach the shared delay exchanges.
12. n8n orchestration is exercised statically (generator, lint) and through the
    internal API; an n8n container in CI with provisioned workflows would test it
    end to end. The platform runs fully without n8n (the default).
13. The offline analyser is a transparent heuristic; the external AI provider
    needs an API key and each tenant's opt-in.
