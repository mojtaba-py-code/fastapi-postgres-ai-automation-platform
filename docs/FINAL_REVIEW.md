# Final review

The specification asks for a final architecture, security, dependency, test and
deployment review, and an honest list of remaining limitations. This is that
review, as of 2026-09-26.

**Verdict.** NexusFlow AI is a complete, well-tested reference implementation of
a secure automation and intelligence platform, ready for a pilot. The whole stack
runs in CI on every change - end-to-end tests behind the TLS edge, a
backup-and-restore round trip and a passive DAST scan - but it is not yet
production-proven: it has not run on a customer-like host, no independent
penetration test has been done, single sign-on and passkeys have not yet been
tried with real identity providers, browsers and authenticators, and high
availability and an admin UI are on the roadmap (section 7).

## 1. Architecture review

| Aspect | Assessment |
|---|---|
| Layering | Clean architecture `apps -> bootstrap -> infrastructure -> domain -> core`, enforced in CI by import-linter; the domain imports no framework (no FastAPI, SQLAlchemy, Celery, Redis, HTTP or AI SDK) |
| Size | 220 modules, about 40,500 lines of Python; 11 migrations (the initial schema in two parts, and nine additive ones); 10 ADRs |
| Components | Public API, internal API (n8n and sandbox), pipeline and integrations workers, sandbox worker, headless browser, beat, n8n (optional), PostgreSQL, Redis (two instances), RabbitMQ, nginx, Prometheus, Alertmanager, Grafana |
| Trust boundaries | Edge (TLS, limits); tenant isolation (forced RLS plus `org_id` filters); sandbox (no DB, no secrets, per-run tickets); browser (pinning egress proxy); n8n (per-workflow service tokens, signed events); identity providers (trusted only for proven domains, sessions bound to their organization). Every entry point is enumerated in the [threat model](THREAT_MODEL.md) (section 3.1) |
| Reliability | Transactional outbox; idempotent workers; quorum queues with dead-lettering, delayed retries held by the broker; reaper with bounded attempts and fencing; heartbeat health; one request ID from the API into every job it causes |
| Extensibility | Ports and adapters for providers (AI, storage, scanning, notifications); new source kinds and channels are adapters; the domain services are independent of the transport |
| Scaling path | Stateless APIs and workers scale horizontally; per-pool queues; the database is the shared core, and reports and analytics aggregate in it. Single-host Compose is the reference topology. The modular monolith has a documented extraction path to services ([ADR-0010](adr/0010-modular-monolith-and-service-extraction.md)); see section 7 |

Findings of the review were fixed in place (for example the explicit pipeline
stages, report analytics aggregated in the database and the data-lifecycle
audit); see [ARCHITECTURE.md](ARCHITECTURE.md).

## 2. Security review

Twelve AI-assisted review passes (adversarial code review, due diligence,
traceability, test-driven reviews of the adapters, the core chain and of hostile
uploads and rate limits, a deployment startup review, two completion reviews, an
adversarial review of the day's new code, six parallel reviews of the whole
platform - identity, pipeline and data lifecycle, workers and sandbox, alerting
and AI, the database, the deployment - and a review of single sign-on and SCIM
before release), the first run of the full stack in CI, and what fixing the
reviews surfaced produced 144 numbered findings plus smaller observations. All
are fixed with regression tests (or, for configuration, in the file named as
evidence), except one accepted risk: a member who may read records can page
through a whole dataset, where exports are audited and budgeted (D-n2). The full
record, including the specification's security checklist, is in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md); residual risks are in the [threat
model](THREAT_MODEL.md). A self-assessed mapping to the seventeen chapters of
OWASP ASVS 5.0 (target Level 2, with selected Level 3 controls), with evidence
and the remaining gaps, is in [ASVS.md](ASVS.md).

## 3. Dependency and supply-chain audit

* Dependencies are locked with hashes (`uv.lock`) and installed with
  `--frozen`; CI audits the locked export with `pip-audit --require-hashes`.
* `pip-audit` over the complete development environment on 2026-09-25:
  **no known vulnerabilities**.
* CI also runs Bandit, Semgrep (pinned), CodeQL and Gitleaks, and scans both
  images with Trivy (fail on fixable High/Critical) and produces an SBOM for each.
* CI actions are pinned to commit SHAs; base images (literal `FROM` lines) and
  third-party images (Compose, CI) are pinned to digests in forms Dependabot reads,
  and CI fails if one loses its digest (`make pin-images` refreshes them);
  Dependabot proposes updates weekly.
* Every week CI rebuilds and scans the platform's images and runs the whole stack,
  and Trivy scans every third-party image. The first such scan failed seven
  images: three ran on lines upstream no longer maintained (Grafana's old
  repository, Prometheus 3.5, nginx 1.29) and moved; RabbitMQ 4.1, out of
  community support, moved to 4.3. What the newest upstream releases still carry
  is accepted only when it cannot be reached here, with its reason and an expiry
  date (`.trivyignore.yaml`); n8n's own dependencies are reported, not failed on.
* The workflows themselves are audited by zizmor (pedantic persona, with online
  checks for impostor commits and known-vulnerable actions): no findings. Once
  the repository is public, dependency review blocks a pull request that adds a
  vulnerable (moderate or worse) or GPL/AGPL-3.0 dependency, and OpenSSF Scorecard
  grades the repository weekly; both are skipped on the private repository, like
  CodeQL.
* A version tag runs the release workflow: both images are scanned, pushed to
  GHCR with SBOM and provenance attestations, and signed keyless with cosign.
  No release has been published yet.
* Every CI run ends with a dynamic scan: OWASP ZAP (pinned by digest) requests
  every API operation of the running stack as a signed-in owner and scans the
  responses passively; any alert of Medium risk or higher fails the build unless
  it is accepted with a written reason (none is). The first scan found one
  Medium and three Low alert types, all on responses the edge generated itself
  (R11-3, fixed); the current scan raises no warning of any level (118 rules
  pass), only informational notes (client errors for placeholder identifiers,
  and the deliberate `no-store`).

## 4. Test review

| Layer | Tests | What they exercise |
|---|---|---|
| Unit | 1,915 | Crypto, tokens, the WebAuthn verifier and its CBOR decoder, the OpenID Connect client (discovery, key sets, ID tokens) and single sign-on rules, Vault transit wrapping, SSRF guard, log redaction, network allowlists, the edge configuration (nginx), alert rules against the exported metrics, the DAST gate, script modes in git, all adapters (scraping, robots.txt, collectors, senders, AI provider, ClamAV, n8n client), the core chain (detection, alert rules, offline analysis, property-based tests), pipeline stages, reports and analytics, sign-in risk, request correlation, hostile uploads (hand-built zip bombs, traversal, macros, XXE, sparse sheets), the rate limiter, TLS client configuration, worker policy and liveness, n8n generator and lint, configuration and broker consistency |
| Integration | 320 | Real PostgreSQL with production roles (RLS really enforced): identity and sign-in risk, e-mail-verified sign-up, privacy (export, erasure, retention), single sign-on against an in-process identity provider, SCIM provisioning, migrations down and up again, database security, the business API and change analytics, the core chain end to end with the real worker handlers, crash recovery, data lifecycle, workflows, request correlation, backup and restore (`pg_dump`/`pg_restore` with the production roles), the CLI, and the demo walkthrough over real HTTP |
| Security | 212 | Authentication, passkeys, second-factor guessing, single sign-on enforcement (organization-bound sessions, `sso_required`), authorization, an IDOR sweep over every resource route, API-key lifecycle, login locking, session management, network allowlists (members, API keys, sign-in, anti-lockout, operator recovery), every rate-limit scope and its failure policy, hostile uploads through the API, input handling, headers, error leakage |
| End to end | 18 | The business scenario, the monitoring stack and the edge's security properties (headers on every response, JSON errors, hidden paths, body limits, tenant isolation) against the running Compose stack (CI), followed by a backup, restore and audit verification and a DAST scan; skipped without a stack |

* The last full run: 2,446 passed (the 18 end-to-end tests run in CI against the
  stack); line and branch coverage 90 %, with a CI floor of 80 %.
* Defects found by writing tests were pinned as strict expected failures first,
  then fixed.
* Not covered by automated tests: the workflows running inside a real n8n (CI
  starts n8n with the stack; the workflows are generated and linted), real
  Slack/Telegram endpoints and a real mail provider (tested against faithful fakes
  at the protocol boundary; CI's stack delivers mail to Mailpit), and a real Redis
  and RabbitMQ outside the end-to-end job (`fakeredis` with Lua elsewhere). The
  real headless Chromium renders a public page in the end-to-end job.

## 5. Deployment review

| Checked | How |
|---|---|
| Startup | Started in CI on every change (R11: the first run found a startup failure the static review had missed). Before that, reviewed statically (R7): the Compose files resolved with the example environment; settings and application objects of all 8 application roles built with exactly the variables and secrets Compose gives them; every image tag resolved in its registry; nginx, Prometheus, RabbitMQ, Docker DNS, Grafana and Mailpit behaviour checked against their sources. The one certain startup failure (Prometheus) and 14 further findings are fixed |
| Compose configuration | Every `NEXUSFLOW_*` variable in the Compose files is a real setting; every mounted secret is generated; settings refuse insecure production values |
| Images | Non-root and read-only for the platform's own containers; no capabilities, `no-new-privileges` and memory limits everywhere (the exceptions of upstream images are named in the Compose header); built and scanned in CI; pinned by digest |
| Networks | Only nginx publishes ports (IPv4; admin UIs on 127.0.0.1); internal networks everywhere else, with TLS on every internal hop verified against the stack's private CA; egress only for the pools that need it, without inter-container traffic |
| Secrets | Files under `/run/secrets`, each mounted only into the containers that use it |
| Health | HTTP probes for the APIs; event-loop heartbeats for workers and beat |
| Operations | Backups (encrypted; the restore procedure tested against PostgreSQL with the production roles, and end to end in CI), key rotation procedures, runbooks, audit anchoring |

**Verified in CI, not yet on a customer-like host:** there is no Docker in the
development environment. CI's end-to-end job builds the images, starts the stack
with the demo overlay behind TLS, runs the end-to-end suite, backs the stack up,
changes it, restores it and verifies the audit chains, and scans every API
operation with OWASP ZAP; it passes. A clean-host dry run remains the gate before
production use, and the release workflow has not run yet.

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
1. Do a clean-host dry run (CI already runs the full stack, its backup and
   restore, and a DAST scan on every change).
2. Commission an independent penetration test.
3. Publish the first signed release (tag `v0.1.0`) and deploy it by digest.

**Enterprise features**
4. Single sign-on and provisioning: OpenID Connect and SCIM 2.0 are in
   ([SSO.md](SSO.md)) but not yet tried against real identity providers (Okta,
   Microsoft Entra ID, Google Workspace); no SAML, no front- or back-channel logout.
   Passkeys still need an interop pass with real browsers and authenticators, and
   organizations cannot yet require them specifically.
5. An admin web UI; today the product is API-first (Swagger is disabled in
   production).
6. High availability and disaster recovery: managed PostgreSQL with
   point-in-time recovery, a RabbitMQ cluster, managed Redis, object storage for
   uploads and reports, Kubernetes manifests, and stated RPO/RTO. Today: one
   host, encrypted and tested backups.
7. Privacy: the account side is covered - a person's copy of their data,
   erasure on request, a daily identity retention, audit retention run by the
   migrator, [PRIVACY.md](PRIVACY.md) with a record-of-processing template and
   [DPA_TEMPLATE.md](DPA_TEMPLATE.md). Still missing: finding and erasing one
   person across tenant datasets (the organization answers from its data), a
   self-service change of e-mail address, and data-residency controls for the AI
   provider.

**Hardening and operations**
8. The application encrypts sensitive field values, staged payloads, uploads and
   reports at rest; the other fields of tenant data are plaintext in PostgreSQL so
   they can be queried - use disk or volume encryption, and mark personal data
   `sensitive`. The key-encryption keys are files mounted as Docker secrets, or
   Vault ciphertexts unwrapped at start-up (HashiCorp Vault's transit engine); a
   running process holds them in memory either way, and there is no HSM.
9. Sign-in risk uses devices, networks and failures, not geolocation
   (impossible-travel checks need a GeoIP database).
10. The sandbox's delayed retries (at most three, 20-100 s apart) still occupy a
    worker slot while they wait: its exchange must stay direct, so that its
    broker account cannot reach the shared delay exchanges.
11. n8n orchestration is exercised statically (generator, lint), through the
    internal API, and by starting n8n in CI's stack; provisioned workflows in CI
    would test it end to end. The platform runs fully without n8n (the default).
12. The offline analyser is a transparent heuristic; the external AI provider
    needs an API key and each tenant's opt-in.
