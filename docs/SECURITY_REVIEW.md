# Security review record

This document records how NexusFlow AI was reviewed, what the reviews found and
how each finding was resolved. It complements the [threat model](THREAT_MODEL.md)
(what could go wrong, by design) with evidence (what did go wrong, and how it was
fixed and pinned by a test).

## 1. Method and its limits

All reviews were **AI-assisted**: they were carried out with Claude Code
(Anthropic) during development, as separate review passes with explicit scopes.
They are thorough and adversarial, and every finding below was verified by a
test or a reproduction before it was fixed, but they are **not** a substitute
for an independent assessment:

* no third-party penetration test or professional code audit has been done;
* the container stack, a real n8n and a real Chromium were never run in the
  development environment (Docker was not available there). CI's end-to-end job
  runs the full Compose stack behind the TLS edge; a clean-host dry run should
  precede any production use.

| # | Review | Scope | Output |
|---|---|---|---|
| R1 | Adversarial code review | The implementation: sandbox boundary, gateway, workers, broker, Redis, browser, webhooks, uploads, pagination | 1 High, 5 Medium, 4 Low |
| R2 | Due-diligence review | Enterprise readiness: identity, claims vs code, tests, CI, deployment | 2 High, 3 Medium, 1 Low security-relevant |
| R3 | Specification traceability audit | 551 requirements of the specification | Gaps listed and closed (see [FINAL_REVIEW.md](FINAL_REVIEW.md)) |
| R4 | Test-driven review: adapters | Scraping, robots.txt, collectors, notification senders, AI provider, ClamAV - 342 tests | 7 defects (strict failing tests first) |
| R5 | Test-driven review: core chain | Detection, alert rules, offline analysis, delivery, AI analysis - 238 tests | 9 defects |
| R6 | Completion review | Configuration, deployment wiring, data lifecycle, audit coverage, classification, IDOR sweep | 14 findings |
| R7 | Deployment startup review | Every Compose, nginx, Dockerfile and configuration file; the settings and application objects of all 8 application roles built with their Compose environment and secrets; upstream behaviour checked against the upstream sources | 1 certain startup failure, 14 further findings |
| R8 | Test-driven review: hostile uploads and rate limits | Hand-built hostile CSV/XLSX files (zip bombs, traversal names, encrypted parts, macros, XXE, entity expansion, sparse sheets, invalid UTF-8) through intake, the parser and the API; every rate-limit scope, its budget and its failure policy - 143 tests | 6 defects (strict failing tests first), 3 gaps closed |
| R9 | Second completion pass | Reports at scale, backup and restore, request correlation, sign-in risk | 6 findings |
| R10 | Adversarial review of the day's new code | Change analytics, sign-in risk, password change, request correlation, rate limiting, uploads, operations and CI workflows | 1 finding |
| R11 | First run of the full stack (CI) | The Compose stack built and started behind the TLS edge on a CI runner | 1 High (startup) |

In R4 and R5, every defect was first committed as a *strict expected failure*
(the test fails because of the bug), then fixed, which turned the test into a
permanent regression test.

## 2. Findings and resolutions

Severities in R1 and R2 are the reviewers'; in R4-R11 they were assigned when the defect was fixed. "Test" names the regression test that pins the fix.

### R1 - adversarial code review

| ID | Sev | Finding | Resolution | Test |
|---|---|---|---|---|
| R1-1 | High | A compromised sandbox could obtain every tenant's run tickets: job messages on a shared queue, and the sandbox broker user could declare a queue that taps the sandbox exchange; one parser process served up to 500 jobs | Sandbox broker user can configure nothing (`^$`), reads only its queue, writes only its exchange; upload input downloadable once per attempt; one process per job (`max_tasks_per_child=1`). Residual risk documented (THREAT_MODEL 4.3) | `tests/unit/workers/test_routing.py`, `tests/integration/test_workers.py` |
| R1-2 | Medium | The gateway parsed up to 80 MiB of JSON before checking the ticket | Ticket and run state checked before the body is read; per-run body caps; large results parsed one at a time (`503 gateway_busy`) | `test_workers.py` (large-result slot) |
| R1-3 | Medium | The sandbox could exhaust the shared Redis and RabbitMQ | Its own disposable Redis (`redis-sandbox`, LRU, no persistence); bounded sandbox queue with `reject-publish` | `test_routing.py` |
| R1-4 | Medium | Infinite `job.failed` loop when operator paging itself failed | Failure-handling tasks never emit `job.failed`; workflow 5 ignores them; operator alerts de-duplicated for 15 minutes | `tests/unit/test_operator_alerts.py`, `test_n8n_workflows.py` |
| R1-5 | Medium | Internal orchestration mode ignored the kill switch and the tenant freeze | Enforced in the event handlers and services, not only in the HTTP router | `test_workers.py` (paused events) |
| R1-6 | Medium | DNS-rebinding SSRF in the browser renderer | Chromium connects only through a pinning egress proxy (resolve once, all answers public, connect to the checked address); QUIC and non-proxied WebRTC disabled | `tests/unit/security/test_egress_proxy.py` |
| R1-7 | Low | Flat egress network; ClamAV on the backend network | Inter-container traffic disabled on `egress`; ClamAV on its own `av` network shared only with the API | Compose review |
| R1-8 | Low | Crafted pagination cursors caused 500s | Cursors range-checked against the column type; database data errors map to `422 invalid_value` | `tests/unit/test_database_value_guards.py` |
| R1-9 | Low | Webhooks: replay nonce consumed before storing (silent loss), timing difference for unknown endpoints, quota charged before verification | Nonce released on failure (`409 delivery_in_progress`); identical HMAC work on a decoy secret; quota charged after verification | `tests/integration/test_business_api.py` |
| R1-10 | Low | Uploads: shared small `/tmp`; files stuck in `ACCEPTED` could never be re-uploaded | Dedicated spool volume; a run that ends without storing its file releases the upload; de-duplication covers live uploads only | `test_business_api.py` |

### R2 - due-diligence review

| ID | Sev | Finding | Resolution | Test |
|---|---|---|---|---|
| R2-1 | High | API keys kept their role after the creator was removed or demoted | Key permissions are intersected with the creator's current membership on every request; keys revoked on member removal and account deletion (audited) | `tests/security/test_api_key_lifecycle.py` |
| R2-2 | High | Unsupported claim of an "independent" security review | Wording corrected everywhere; this document records what was actually done | - |
| R2-3 | Medium | Argon2 hashing under a row lock: a login flood could exhaust the pool | Three phases: read, verify outside the transaction, apply under `FOR UPDATE` with re-checks | `tests/security/test_login_locking.py` |
| R2-4 | Medium | RLS context can be set by the application role; no all-tables RLS test | Limitation documented (THREAT_MODEL 4.7); a test enumerates every table and requires forced RLS with a policy | `test_database_security.py` |
| R2-5 | Medium | Supply chain: actions on mutable tags; browser image not scanned | Actions pinned to commit SHAs; both images scanned (Trivy) with SBOMs; n8n pinned to a current release | CI |
| R2-6 | Low | Sign-up reveals whether an e-mail is registered | **Accepted**: fail-closed rate limit (10/hour/IP); disable sign-up after bootstrapping | - |
| - | - | Found while fixing R2-1: account deletion always failed (audit tenant mismatch) | Fixed | `test_api_key_lifecycle.py` |

### R4 - test-driven review of the adapters

| ID | Sev | Finding | Resolution |
|---|---|---|---|
| R4-1 | High | A REST source stopped at its page cap was reported as a complete snapshot, so records beyond the cap were marked deleted | Stopping at the page cap marks the snapshot truncated |
| R4-2 | Medium | An empty-string pagination cursor restarted at page 1 (duplicate items) | Empty cursors end pagination |
| R4-3 | High | A redirect answer from Slack, Telegram or a webhook counted as a delivered alert | Any 3xx that is not followed is a failed request |
| R4-4 | Medium | Temporary SMTP replies (4xx) were treated as permanent: greylisting dropped alerts | 4xx replies are retried with backoff |
| R4-5 | Medium | An open circuit breaker dead-lettered AI analyses | An open circuit is a temporary failure |
| R4-6 | Medium | robots.txt evaluated with first-match semantics; `*` and `$` ignored (RFC 9309) | Own RFC 9309 matcher: longest match, wildcards, end anchors, percent-encoding; linear time |
| R4-7 | Low | robots.txt redirects escaped the source's domain allowlist | robots.txt fetched under the source policy; such redirects refused and never cached |
| - | - | Observations: policy-blocked sends not counted in metrics; robots.txt outages failed runs permanently; oversized robots.txt failed runs; redirect hops not checked against robots.txt | All fixed: counted; retried later; truncated at 512 KiB; every hop checked |

Tests: `tests/unit/adapters/`, `tests/unit/http/test_ssrf_protection.py`.

### R5 - test-driven review of the core chain

| ID | Sev | Finding | Resolution |
|---|---|---|---|
| R5-1 | High | Extreme decimals made change detection overflow on every retry: the dataset stopped being processed | At most 18 fractional digits at ingestion; relative changes capped |
| R5-2 | Medium | A policy-blocked notification destination left the delivery in `SENDING` forever | Every failure settles the delivery |
| R5-3 | Medium | Notification dead letters did not emit `job.failed` (operators never paged) | One staging path for all dead letters, always with the event |
| R5-4 | Medium | Channel throttling used up delivery attempts: alert storms lost alerts | Throttled deliveries are deferred without spending an attempt |
| R5-5 | Medium | An analysis interrupted by a worker crash stayed `RUNNING` forever | The reaper re-queues it (bounded attempts); a late result from a reaped worker is discarded (fencing by claim time) |
| R5-6 | Medium | A sensitive key field reached AI prompts and alert titles | Key fields cannot be sensitive (`422`) |
| R5-7 | Medium | Numeric alert rules on sensitive fields could never fire | Conditions see the complete diff; the alert still shows the masked one |
| R5-8 | Low | An explicit empty `tracked_fields` tracked every field | It tracks nothing |
| R5-9 | Low | A 9-byte number (`1e-999999`) was stored as a million-character string | Covered by R5-1 |

Tests: `tests/unit/core_chain/`, `tests/integration/test_core_chain.py`.

### R6 - completion review

| ID | Sev | Finding | Resolution | Test |
|---|---|---|---|---|
| R6-1 | High | The retention job never deleted anything: the runtime role may not delete dead letters, so every pass failed and rolled back | A narrow `SECURITY DEFINER` purge function (old rows of the current scope only) instead of a DELETE grant | `tests/integration/test_data_lifecycle.py` |
| R6-2 | High | `NEXUSFLOW_NOTIFICATIONS__SMTP_CA_FILE` was read as a secret-file indirection: the integrations worker would not start in the demo stack | Setting renamed `smtp_ca_bundle`; tests forbid settings named `..._file` and require every Compose variable to be a real setting | `tests/unit/test_config_reference.py` |
| R6-3 | Medium | Data classification was stored but not enforced | Restricted data never leaves the platform: no external AI, no record keys or values in alert messages | `test_core_chain.py::TestRestrictedData` |
| R6-4 | Medium | The platform audit chain (events without a tenant) could not be read, verified or anchored | Two narrow read functions; verified by `nexusflow audit verify`; anchored hourly; tamper detection tested | `test_database_security.py`, `test_cli.py` |
| R6-5 | Medium | Worker and beat health checks passed while a worker hung | Event-loop heartbeat, stale while disconnected from the broker | `tests/unit/workers/test_liveness.py` |
| R6-6 | Medium | The kill switch could not unpublish n8n workflows in the Compose stack (no API key; the documented container had no route to n8n) | Key mounted into `api-internal`; runbook updated; the flag is set and audited first | `test_cli.py` |
| R6-7 | Medium | Workflow 5's retry path could never retry (hard-coded attempt, unused backoff) | The platform counts failures per retry chain; a Wait node applies the backoff; n8n retries through its loopback API with a dedicated credential, pinned by the lint | `test_n8n_workflows.py`, `test_failure_ledger.py` |
| R6-8 | Medium | SMTP password and AI provider key could not be configured in the Compose stack | Optional secrets, each mounted only where used; empty file means "not configured" | `test_routing.py`, `test_core_utilities.py` |
| R6-9 | Low | Listing the runs of another tenant's source or workflow answered `200` (empty) instead of `404` | Parent checked first; an IDOR sweep covers every resource route | `tests/security/test_idor_sweep.py` |
| R6-10 | Low | `field_changed` rules fired for every new record (alert noise on imports) | Updates only | `test_alert_rules.py` |
| R6-11 | Low | Purges, organization creation and workflow deletion were not (or wrongly) audited | Audited as `data.retention_purged`, `dataset.purged`, `org.purged`, `org.created`, `workflow.deleted` | `test_data_lifecycle.py` |
| R6-12 | Low | Prices with a currency code ("EUR 9.90") were rejected | Currency letters are not taken for exponents | `tests/unit/pipeline/test_stages.py` |
| R6-13 | Info | The incident guide claimed request IDs correlate API and worker logs | Implemented: the request ID travels with outbox messages into worker logs (`core/correlation.py`, migration 0006) | `tests/integration/test_correlation.py`, `tests/unit/core/test_correlation.py` |
| R6-14 | Low | The n8n client counted a redirect answer as a delivered event or a successful unpublish | Only a 2xx answer is a success | `tests/unit/adapters/test_n8n_client.py` |

### R7 - deployment startup review

The stack could not be started in the development environment (no Docker), so
this review simulated it: it resolved the Compose files with the example
environment, generated secrets and certificates, loaded the settings and built
the application and Celery objects of every application role with exactly the
variables and secrets Compose gives it, confirmed that every image tag exists,
and checked the behaviour of nginx, Prometheus, RabbitMQ, Docker's DNS, Grafana
and Mailpit against their sources. "Evidence" names the file that carries the
fix where no automated test can.

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| R7-1 | High | Prometheus exited on every start (`--web.enable-lifecycle=false` is not a valid flag): nothing was scraped and no alert could fire | Flag removed; the lifecycle API is off by default | `docker-compose.yml` |
| R7-2 | Medium | JavaScript rendering could not be used: the API did not know a renderer existed (sources were refused), and the sandbox would have reached the browser at its address on `egress`, which drops traffic between containers | Every application container knows the renderer; the browser is reached as `renderer`, an alias on the internal `render` network only | `docker-compose.yml` |
| R7-3 | Medium | The API's upload spool volume was owned by root, so uploads over 1 MB went to the 64 MB in-memory `/tmp` (three concurrent 20 MB uploads failed) | The directory is created in the image for the application user | `docker/Dockerfile` |
| R7-4 | Medium | RabbitMQ named its node after the container ID: a recreated container started empty and stranded the queued jobs | Fixed host name | `docker-compose.yml` |
| R7-5 | Medium | Delayed retries (direct exchange, quorum queues) were held by the workers in their few prefetch slots: an outage of one integration could stall a pool for minutes | The platform exchange is a topic exchange, so RabbitMQ holds retries (native delayed delivery). The sandbox's exchange stays direct by design (its account must not reach the shared delay exchanges); its retries are short | `test_routing.py::test_exchange_types_agree_and_retries_are_held_by_the_broker` |
| R7-6 | Low | nginx resolved the API once at startup: a recreated API container answered 502 until nginx restarted | Resolved again every 10 s | `deploy/nginx/nginx.conf` |
| R7-7 | Low | Worker children were recycled at 512 MB: four of them could exceed the 1 GB container limit, and Docker kills the whole container first | 200 MB per child | `celery_app.py` |
| R7-8 | Low | Development certificates were unreadable by nginx and Mailpit under a restrictive umask | Explicit 0644 | `scripts/dev_certs.py` |
| R7-9 | Low | The eleventh demo or end-to-end run within an hour hit the sign-up limit | The demo overlay raises that limit | `docker-compose.demo.yml` |
| R7-10 | Low | The n8n editor lost its connection through nginx (Origin and Host differ by the port) | Host forwarded with the port | `deploy/nginx/nginx.conf` |
| R7-11 | Low | Grafana logged errors for its log file and for plugin downloads | Console logging; no plugin preinstall | `docker-compose.yml` |
| R7-12 | Low | ClamAV and closing sign-up could not be set from `.env` (the documented variable never reached the container) | Pass-throughs `NEXUSFLOW_CLAMAV_ADDRESS`, `NEXUSFLOW_SIGNUP_ENABLED` | `docker-compose.yml`, `.env.example` |
| R7-13 | Low | Mailpit ran as root; n8n ran two init processes | Unprivileged user; image init only | Compose files |
| R7-14 | Info | The Compose header claimed every container was read-only and non-root | Corrected: the exceptions (PostgreSQL, ClamAV, RabbitMQ, n8n) are named | `docker-compose.yml` |
| R7-15 | Info | Host prerequisites were implicit: at least 2 vCPUs (CPU limits), the default umask, SELinux labels, a free `172.28.1.0/24` | Documented; the edge subnet is configurable (`NEXUSFLOW_EDGE_SUBNET`) and stays the only trusted proxy range | `docs/DEPLOYMENT.md` |

### R8 - test-driven review: hostile uploads and rate limits

| # | Severity | Finding | Resolution | Test |
|---|---|---|---|---|
| R8-1 | Medium | Changing the password had no rate limit, and a wrong current password did not count toward lockout: whoever held a stolen access token could guess the password without limit | 5 attempts per 15 minutes per user (fail closed), and every wrong current password counts like a failed sign-in (lockout, audit `auth.password.change_failed`); hashing no longer runs under the user's row lock | `tests/security/test_rate_limits.py::test_password_change_guesses_are_throttled` |
| R8-2 | Medium | A 5 KB workbook whose only data row is numbered 1,048,576 cost about 25 s of sandbox CPU: blank rows did not count toward the row cap, and the reader produces one for every skipped row number | openpyxl is told where to stop (the row cap plus 1,000 blank rows); stopping there marks the file truncated | `test_malicious_uploads.py::test_sparse_row_numbers_do_not_make_the_parser_walk_the_gap` |
| R8-3 | Medium | Tuning a fail-closed scope's limit (the documented override shape) silently made it fail open during a Redis outage | An override changes only the fields it names | `test_rate_limiter.py::test_tuning_a_limit_keeps_the_scopes_failure_policy` |
| R8-4 | Low | Broken or hostile workbook content (XXE and entity expansion refused by defusedxml, malformed XML, a missing sheet) escaped the parser as a crash: the sandbox parsed the hostile file again on each of three retries and reported a generic error | Mapped to `upload_malformed`, a permanent error | `test_malicious_uploads.py::test_hostile_workbook_content_is_rejected_with_an_upload_code` |
| R8-5 | Low | Macro detection matched part names only: a workbook declared macro-enabled (a renamed `.xlsm`), or a VBA project under another name, passed | The package's content types and relationships are checked too (a bounded byte search, no XML parsing) | `test_malicious_uploads.py::test_macro_enabled_workbooks_are_rejected` |
| R8-6 | Low | The limiter rounded its interval down to whole milliseconds: a 400-per-second rule admitted 500 | Exact integer microseconds, rounded up | `test_rate_limiter.py::test_a_burst_never_exceeds_the_configured_limit` |
| R8-7 | Low | Each API key had its own AI and export budget, so a user could multiply the limits (the AI limit guards cost) by creating keys | Costly scopes are charged to the person behind the key | `test_rate_limits.py::test_more_api_keys_do_not_buy_more_ai_budget` |
| R8-8 | Low | Two workbook parts with the same name: intake and the parser could look at different content | Rejected (`upload_duplicate_entries`) | `test_malicious_uploads.py::test_two_parts_with_one_name_are_rejected` |
| R8-9 | Info | Only a CSV's header row was checked against the column cap; an empty CSV was refused only by the sandbox | Every row is checked; an empty file is refused at intake | `test_malicious_uploads.py::TestCsvParsing` |

Checked and found sound: path traversal and absolute names (also with
backslashes), encrypted parts, compression-ratio and total-size bombs, lying
size headers, entity resolution (never happens), external links and web queries
(never fetched), formula cells (inert text), invalid UTF-8 at any position, and
the failure policy of every scope during a Redis outage.

### R9 - second completion pass

| # | Severity | Finding | Resolution | Test |
|---|---|---|---|---|
| R9-1 | High | Reports read at most 5,000 changes, in time order: for a busy period the totals, the daily trend, the trend note and the summary were wrong (later days showed no changes), and the AI tool's 7-day statistics were capped the same way | The database aggregates every change per UTC day, type and significance; the listings show the most significant changes. The same aggregation serves `GET /api/v1/analytics/changes` | `tests/integration/test_change_analytics.py`, `tests/unit/reports/test_report_analytics.py` |
| R9-2 | High | Backups could not run: PostgreSQL requires a password on local connections and the scripts gave none | The superuser password is read inside the container, never on the host's command line | CI end-to-end job runs `backup.sh` and `restore.sh` (first run pending) |
| R9-3 | Medium | A restore would fail: `pg_stat_statements` in the application database belongs to the superuser, so restoring as the migrator errored and `set -e` stopped the restore half-way | The extension lives in the `postgres` database; the restore procedure is tested against PostgreSQL with the production roles | `tests/integration/test_backup_restore.py` |
| R9-4 | Low | Security e-mails, invitations and organization deletions were queued without the request's correlation ID (built outside the outbox helper) | One constructor for every outbox message, enforced by a test | `tests/unit/core/test_correlation.py` |
| R9-5 | Low | The new-device check compared exact IP addresses: every new DHCP lease e-mailed the user, which trains users to ignore the warning | Sign-in risk compares networks (/24, /48) and devices separately, and adds failures before success; suspicious sign-ins are audited, counted and alerted on | `tests/unit/security/test_login_risk.py`, `tests/integration/test_login_risk.py` |
| R9-6 | Low | Sign-in e-mails could have quoted the client's user agent, i.e. text chosen by whoever signed in | E-mails describe the device from a fixed vocabulary ("Firefox on Windows") and give a parsed IP address | `test_login_risk.py` |

### R10 - adversarial review of the day's new code

| # | Severity | Finding | Resolution | Test |
|---|---|---|---|---|
| R10-1 | Medium | For accounts with MFA the "success after failures" sign-in signal was lost: the failure counter was reset when the MFA challenge was issued, so a correct password and code from a new network right after several wrong passwords was only "unfamiliar" - not audited as suspicious, not alerted | The signed MFA challenge carries the preceding failures to the risk assessment (the lockout counter still restarts for the second factor) | `tests/security/test_r10_login_risk.py`, `test_crypto_primitives.py` |

Checked and found sound: analytics tenant isolation and period validation;
the password-change flow; request-ID handling (only well-formed IDs, only from
trusted proxies); the rate limiter after R8; upload inspection after R8; the
sandbox gateway's body limits; sign-in e-mail content; and, by inspection, the
backup scripts, workflows (SHA-pinned actions, least-privilege permissions, no
untrusted expressions in `run:`), nginx and the image pinning script. Noted,
not a defect: the request ID deliberately stops at the sandbox-to-gateway hop -
the internal API does not trust request IDs from the sandbox.

### R11 - first run of the full stack

The end-to-end CI job built both images and started the whole stack for the
first time. R7 had reviewed the startup statically - and missed this:

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| R11-1 | High | nginx refused to start (`"proxy_read_timeout" directive is duplicate`): the export and report-download location raised the read timeout and then included the shared proxy snippet, which set it again. The edge never served a request - the platform was unreachable | The upstream timeouts are set once per server block; the download location overrides only the read timeout. CI now runs `nginx -t` before starting the stack, and a unit test parses the configuration (snippets included) for repeated single-value directives - it fails on the old file | `tests/unit/test_edge_config.py`, `.github/workflows/ci.yml` |

The lesson is R7's own caveat made concrete: a static review of a deployment is
no substitute for starting it.

## 3. Checklist (specification section 39)

| Item | How it is addressed | Evidence |
|---|---|---|
| Authentication | Argon2id; breached passwords refused; EdDSA access tokens (10 min) with key IDs; rotating refresh tokens with reuse detection; TOTP with replay protection; lockout; sign-in risk; session list and revocation; API keys capped by the creator's membership; per-organization network allowlists for sessions and API keys | `tests/integration/test_identity_flows.py`, `tests/security/` (incl. `test_network_allowlist.py`) |
| Authorization | Permission checks at the route and in every service method; roles and scoped keys | `test_api_security.py`, `test_idor_sweep.py` |
| Input validation | Strict request models (`extra="forbid"`), bounded sizes, lengths, counts and depth; typed dataset schemas | `test_api_security.py`, `test_stages.py` |
| Output encoding | CSV formula neutralisation, XLSX string cells, XML-escaped PDF text, JSON only in APIs | `test_files_and_reports.py` |
| Injection | SQLAlchemy bound parameters only; allowlisted purge targets; no shell or code execution anywhere (n8n lint forbids code nodes) | code review, `test_n8n_workflows.py` |
| SSRF | URL policy plus connect-time IP checks of all DNS answers; re-validated redirects; browser pinning proxy | `test_ssrf_protection.py`, adapter tests |
| CSRF | Not applicable to bearer tokens (no cookies); explicit CORS origins | THREAT_MODEL 4.1 |
| XSS | JSON APIs only, `nosniff`, strict CSP, downloads as attachments; no HTML rendering of tenant data | `test_api_security.py` (headers) |
| Secrets exposure | Secrets as files, `SecretStr`, encrypted integration secrets (AES-256-GCM), keyed token hashes; secrets never returned after creation | `tests/unit/security/test_crypto_primitives.py`, `test_log_redaction.py` |
| Logging exposure | Structured logs with key and value redaction; no local variables in tracebacks; scrubbed dead-letter messages | `tests/unit/observability/test_log_redaction.py` |
| Rate limiting | GCRA limits per scope in Redis, fail-closed for authentication, exports, AI and webhooks | `test_api_security.py`, `test_business_api.py` |
| Resource exhaustion | Body caps, bounded decompression, item and page caps, bounded queues, timeouts, per-host throttling | `test_ssrf_protection.py`, `test_workers.py` |
| Tenant isolation | Forced RLS on a non-bypass role, explicit `org_id` filters, `404` for foreign identifiers | `test_database_security.py`, `test_idor_sweep.py` |
| Race conditions | State machines with row locks, unique constraints, `SKIP LOCKED` claims, fencing of reaped work | `test_core_chain.py` (concurrent deliveries, reaped analysis) |
| Replay attacks | Webhook timestamp window plus nonce plus unique row; refresh-token reuse detection; TOTP step replay | `test_business_api.py`, identity tests |
| Idempotency | `Idempotency-Key` on commands; idempotent workers; failure ledger idempotent per execution | `test_business_api.py`, `test_failure_ledger.py` |
| Error leakage | Uniform error schema; internals only in logs; validation errors never echo input | `test_api_security.py` |
| Dependency vulnerabilities | Hash-locked `uv.lock`, pip-audit, Trivy, CodeQL, Semgrep, Gitleaks, Dependabot; images and actions pinned by digest and SHA (checked in CI); zizmor audits the workflows (pedantic, with online checks for impostor commits and vulnerable actions); dependency review and OpenSSF Scorecard once the repository is public | CI |

## 4. What remains

Residual risks accepted by design are listed per component in the
[threat model](THREAT_MODEL.md); limitations of the product and of this
review are in [FINAL_REVIEW.md](FINAL_REVIEW.md). Before production, commission
an independent penetration test and run the deployment checklist in
[DEPLOYMENT.md](DEPLOYMENT.md).
