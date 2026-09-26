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
| R11 | First run of the full stack (CI) | The Compose stack built and started behind the TLS edge on a CI runner; the end-to-end suite, backup and restore, and a passive DAST scan of every API operation | 1 High, 2 Medium |
| R12 | Six parallel reviews | Identity and access; pipeline and data lifecycle; workers, sandbox and browser; alerting, AI, notifications and reports; the database (measured on PostgreSQL); the deployment (checked against upstream sources) | 53 unique findings: 5 High, 28 Medium, 20 Low |
| R13 | What fixing R12 surfaced | The first weekly scan of the third-party images, CI coverage, DAST, the accepted sign-up enumeration, and the lockout on the MFA path | 1 High, 4 Medium, 1 Low |

In R4 and R5, every defect was first committed as a *strict expected failure*
(the test fails because of the bug), then fixed, which turned the test into a
permanent regression test.

## 2. Findings and resolutions

Severities in R1, R2 and R12 are the reviewers'; in R4-R11 and R13 they were assigned when the defect was fixed. "Test" names the regression test that pins the fix.

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
| R2-6 | Low | Sign-up reveals whether an e-mail is registered | Accepted at the time (fail-closed rate limit); **resolved** by R13-1: sign-up proves the address first and answers alike for every address | `tests/integration/test_signup.py` |
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
first time, ran the end-to-end suite, a backup-and-restore round trip and a
passive DAST scan. R7 had reviewed the startup statically - and missed R11-1:

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| R11-1 | High | nginx refused to start (`"proxy_read_timeout" directive is duplicate`): the export and report-download location raised the read timeout and then included the shared proxy snippet, which set it again. The edge never served a request - the platform was unreachable | The upstream timeouts are set once per server block; the download location overrides only the read timeout. CI now runs `nginx -t` before starting the stack, and a unit test parses the configuration (snippets included) for repeated single-value directives - it fails on the old file | `tests/unit/test_edge_config.py`, `.github/workflows/ci.yml` |
| R11-2 | Medium | Backups could not be taken or restored as documented (`scripts/backup.sh`: "Permission denied"): the repository had been re-created from a Windows checkout, which does not keep the executable bit, so every script was stored as `100644` | Executable again; a test fails when a script with a shebang is not executable in git | `tests/unit/test_repository_hygiene.py` |
| R11-3 | Medium | Found by the first DAST run (OWASP ZAP): responses the edge generates itself - 404 for the hidden paths, 413, and the 429s of its rate limiting - carried none of the security headers the application sets (ZAP: no CSP, Medium; no HSTS or Permissions-Policy, Low) and an HTML body where API clients expect the JSON error schema | nginx adds HSTS, CSP, `nosniff`, `DENY`, `no-referrer`, Permissions-Policy and `no-store` to every response the application did not answer - never a second copy - and answers its own errors in the application's JSON error schema with the request ID | `tests/unit/test_edge_config.py`, `tests/e2e/test_edge.py`, the DAST step |

The lesson is R7's own caveat made concrete: a static review of a deployment is
no substitute for starting it.

### R12 - six parallel reviews

Six reviewers, each with its own scope, worked at the same time and wrote a
reproduction for every finding before it was fixed: **A** identity and access,
**B** the pipeline and the data lifecycle, **C** the workers, the sandbox and the
browser, **D** alerting, AI analysis, notifications and reports, **E** the
database (measured on PostgreSQL with the production statement timeout), and **F**
the deployment (every Compose, nginx, Docker and operations file, checked against
the upstream sources). 58 findings; five were found twice (D-4 = C-7, D-5 = B-6,
D-7 = B-5, D-8 = B-11, D-12 = C-8), leaving 53: 5 High, 28 Medium, 20 Low. All are
fixed except D-n2, accepted with its reason. Every fix has a regression test that
fails on the old code, or, for deployment files, the file named as evidence.

**A - identity and access**

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| A-1 | Medium | Enabling or disabling MFA and erasing the account checked the password but counted no failure, ignored a lockout and hashed under the row lock: a stolen access token - or an API key, which acts for its creator - was an unlimited password oracle | One password confirmation for all of them: sessions only, a locked account refused, a wrong password counted toward the lockout and audited, the hash outside any transaction | `tests/security/test_password_confirmation.py` |
| A-2 | Medium | In an organization that requires MFA, every request of a session without it was refused - the enrolment endpoints included - so a member without MFA, or an owner who had just turned the policy on, could never recover | The enrolment endpoints authenticate in a set-up mode (the account, no organization); confirming MFA marks the session MFA-verified | `tests/security/test_mfa_enforcement.py` |
| A-3 | Low | The network allowlist was enforced on every request, at sign-in and on switching - but not on renewal: a stolen refresh token kept an organization session alive from anywhere | Renewal from outside is refused (audited) without spending the token | `tests/security/test_network_allowlist.py` |

**B - the pipeline and the data lifecycle**

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| B-1 | High | Key rotation skipped rows other transactions held and reported success, and re-wrapped only the first 500 webhook secrets: an operator following the procedure could retire a key-encryption key still in use and lose that data | `keys rewrap` counts what is still under an old key (without locks), exits 3 with the counts per tenant until nothing is left, retries held rows (`--passes`, `--wait-seconds`); webhook secrets are paged by id | `tests/integration/test_field_encryption.py` (`TestKeyRotation`), `tests/integration/test_cli.py` |
| B-2 | Medium | Version retention deleted the version change detection still had to compare with | A version goes only once its successor has been diffed | `tests/integration/test_data_lifecycle.py` (`TestRecordRetention`) |
| B-3 | Low | Record keys longer than 512 characters were cut after de-duplication: two records sharing a prefix became one | Keys are bounded first: prefix, `#` and the SHA-256 of the whole key | `tests/unit/pipeline/test_stages.py`, `tests/integration/test_pipeline_integrity.py` |
| B-4 | Medium | One item with an unreadable URL port failed the whole run; IPv6 hosts lost their brackets | Such an item is `invalid_url` (any unexpected item error `invalid_item`); brackets kept; unstorable text refused per item | `tests/unit/pipeline/test_stages.py`, `tests/integration/test_pipeline_integrity.py` |
| B-5 | Medium | Marking a field `sensitive` sealed new values only: every stored value (records, history, change diffs) stayed in clear | A job seals them in batches after waiting for ingestions that read the old schema; detection reads the schema under a share lock | `tests/integration/test_field_encryption.py` (`TestMarkedSensitiveLater`) |
| B-6 | Medium | Deleting a dataset, source or project left its uploaded files and reports on disk for ever, and the organization purge missed them | The deleting transaction reads the storage keys and queues a job that deletes the tenant's own unreferenced files; the organization purge removes the tenant's directories; re-wrap and delete share a lock | `tests/integration/test_stored_files.py` |
| B-7 | Medium | A record seen unchanged by another source kept its old owner, so the deletion detection of the source that now had it never saw it disappear | The source that last saw a record owns it | `tests/integration/test_pipeline_integrity.py` (`TestOwnership`) |
| B-8 | Medium | Runs finishing out of order applied an older full snapshot over a newer one | Each run records when its data was collected; an older full snapshot is skipped as `superseded` | `tests/integration/test_pipeline_integrity.py` (`TestSnapshotOrder`) |
| B-9, D-6 | Medium | Retention handled the first 200 datasets of a tenant only, and changes (old and new values) were never purged | Every dataset, in batches; changes follow the dataset's retention once their alerts are evaluated | `tests/integration/test_data_lifecycle.py` |
| B-10 | Low | The next-page cursor after a long non-ASCII name exceeded the cursor length limit: the next page was refused | UTF-8 JSON cursors, limit 1,024 (the longest possible is 708) | `tests/unit/core/test_core_utilities.py`, `tests/integration/test_business_api.py` |
| B-11 | Low | Idempotency keys were truncated (collisions), scoped to the whole organization, and never expired (the TTL setting was unused) | Stored whole (`req:` and SHA-256), bound to the request they started (reuse for another answers 409 `idempotency_key_reused`), released after `idempotency_keys_hours` | `tests/integration/test_idempotency.py` |
| B-12 | Low | A stored file without the sealed header was served as legacy plaintext - write access to the volume could plant content | Refused | `tests/unit/security/test_file_sealing.py` |
| B-13 | Low | Plaintext copies left by a killed process were never removed | Purged at start-up and daily | `tests/unit/security/test_file_sealing.py`, `tests/integration/test_stored_files.py` |
| B-x | Low | Webhook items beyond the source's limit were dropped without a trace | The run and the receipt report `truncated` | `tests/integration/test_business_api.py` |

**C - workers, sandbox and browser**

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| C-1 | High | Every XLSX upload failed in the sandbox: it stores its input without an extension, and openpyxl refuses such a path (the unit tests named their files `*.xlsx`) | The workbook is opened from a file object; a number that is not finite is a malformed upload | `tests/unit/test_upload_parsing.py`, `tests/integration/test_workers.py` (an XLSX through the real sandbox) |
| C-2 | Medium | The renderer read a page's content without a timeout: a page that never yields kept its slot for ever | Navigation, the final-address check and the content share one deadline; the context is always closed and the slot released | `tests/unit/security/test_browser_guard.py` |
| C-3 | Medium | The robots.txt matcher was quadratic: a hostile robots.txt kept a sandbox worker busy for up to an hour | Linear matching within caps (10,000 rules, 128 KiB), a path cap derived from the policy | `tests/unit/adapters/test_robots_policy.py` |
| C-4 | Medium | The content type was checked before the status: an outage answered with an HTML error page failed a run for good instead of being retried | The type is checked for successful answers only | `tests/unit/http/test_ssrf_protection.py` |
| C-5 | Medium | A retry after the gateway was busy could not download its input again; refusals by the gateway were never reported; the item count was fooled by braces in text | The attempt's input stays available until its result is in; permanent refusals fail the run; items are counted while parsing; non-finite numbers refused | `tests/integration/test_workers.py` (`TestSandboxBoundary`), `tests/unit/workers/test_task_policy.py` |
| C-6 | Medium | A run the reaper gave up on emitted no event and counted no failure: `run_failed` alerts never fired and its workflow run stayed open | Failed like any failed run, in the reaper's transaction | `tests/integration/test_core_chain.py` (`TestCrashRecovery`) |
| C-7, D-4 | Medium | Retrying a dead letter did nothing for most task types; a report failed for good on its first error | A retry resets its entity (run, delivery, analysis, report); reports fail only once their retries are spent | `tests/integration/test_core_chain.py` (`TestDeadLetterRetries`) |
| C-8, D-12 | Low | `isdigit()` accepted non-ASCII digits in `Retry-After`, `Content-Length` and the webhook timestamp: server errors instead of refusals | ASCII digits only; an unexpected sender error is retried like a transient one | `tests/unit/http/test_ssrf_protection.py`, webhook signature tests |

**D - alerting, AI analysis, notifications and reports**

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| D-1 | High | One evaluation handled 500 changes and nothing evaluated the rest until the next event - alerts were silently late or never raised | Up to 2,000 per evaluation in batches of their own, a follow-up job for any backlog, and a periodic sweep in both orchestration modes | `tests/integration/test_core_chain.py` (`TestAlertBacklog`) |
| D-2 | Medium | Collected data reached Slack unescaped: `<!channel>` pinged everyone, `<https://evil|Sign in>` disguised a link | Slack's own escaping, markdown off | `tests/unit/adapters/test_notification_senders.py` |
| D-3 | Medium | The filter that keeps AI output to links on hosts found in the data was bypassed with `?`, `#`, `\` or user-info | The host is the one a browser would open; ASCII host names only; bare hosts with a path removed | `tests/unit/test_ai_safety.py` |
| D-9 | Low | A project report listed alerts from other projects | Only alerts of its own rules | `tests/integration/test_business_api.py` (`TestReports`) |
| D-10 | Low | Changes left out of the prompt by its budget were marked analysed | Only the changes the model saw; the offline analyser covers a change too large for any prompt | `tests/unit/test_ai_safety.py`, `tests/integration/test_core_chain.py` |
| D-11 | Low | The trend sentence compared the halves of an odd-length period by totals | By daily averages | `tests/unit/reports/test_report_analytics.py` |
| D-13 | Low | `GET /sources/{id}/uploads` answered 200 with an empty list for a foreign source, where its siblings answer 404 | 404; the IDOR sweep covers the route | `tests/security/test_idor_sweep.py` |
| D-n1 | Low | Eleven repository queries of the pipeline relied on row-level security alone, against the threat model's "every query also filters by `org_id`" | An explicit tenant filter in each; a static test fails on any new one | `tests/unit/test_repository_tenant_filters.py` |
| D-n2 | Low | A member who may read records can page through a whole dataset; only exports are audited in the tenant's trail and budgeted | **Accepted**: reading records is what the permission grants; pages are rate-limited and every request is logged with its principal and organization; exports stay the audited bulk path (threat model 4.7) | - |

**E - the database**

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| E-1 | High | Foreign keys whose parent rows are deleted had no index on the child: retention, source and dataset deletes and purges scanned whole tables, hit the 15 s statement timeout and rolled back - that tenant's retention never ran again | Migration 0007 adds the indexes, built concurrently | `tests/integration/test_database_hygiene.py` (an index for every foreign key that can fire) |
| E-2 | Medium | The reaper, the retention and change listings scanned whole tables per tenant | Partial and tenant-led indexes (0007) | migration 0007 |
| E-3 | Medium | Deleting a large dataset or organization was one cascading statement, longer than the timeout | Large tables are deleted bottom-up in batches, each its own transaction | `tests/integration/test_data_lifecycle.py` (`TestLargePurges`) |
| E-4 | Medium | Audit verification stopped after 100,000 entries and reported success | The daily job and the CLI check whole chains; the API's bounded check says `complete: false` | `tests/integration/test_audit_verification_bounds.py` |
| E-5 | Medium | The audit purge deleted by time, stamped before the chain lock orders appends: a cut could leave a gap, reported as tampering for ever | It deletes a prefix of each chain | `tests/integration/test_database_hygiene.py` |
| E-6 | Low | Listing changes by time or score had no index | Indexes (0007) | migration 0007 |
| E-7 | Medium | One organization's failed purge stopped the purge of the others | Each organization is purged on its own, oldest request first; failures are reported and retried | `tests/integration/test_data_lifecycle.py` |

The test harness now runs with the production engine timeouts and the production
database privileges, so a query too slow or a grant too wide fails in tests too.

**F - the deployment**

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| F-1 | High | The documented egress firewall dropped the containers' DNS on hosts whose resolver sits in a private range (most clouds): nothing on `egress` resolved | Name resolution let through first, new outbound connections from the public network dropped, and a command to check | [DEPLOYMENT.md](DEPLOYMENT.md) section 1 |
| F-2 | Medium | An IPv6 client reached nginx through Docker's proxy and appeared as the bridge gateway - to rate limits, sign-in risk and network allowlists | Ports published on IPv4; IPv6 through a load balancer | `docker-compose.yml`, DEPLOYMENT.md |
| F-3 | Medium | Real edge certificates could not be used as documented (nginx's uid could not read the key, Let's Encrypt's symlinks dangled) nor renewed without downtime | `scripts/install_edge_cert.sh`; the edge serves ACME challenges for `certbot --webroot` | `tests/unit/test_edge_config.py` |
| F-4 | Medium | RabbitMQ sized its memory watermark from the host's RAM, not its 768 MiB limit | An absolute watermark | `deploy/rabbitmq/rabbitmq.conf` |
| F-5 | Medium | ClamAV had 2 GiB (upstream's minimum is 3): killed on its first signature update, it stayed "running" while every upload was refused | 4 GiB, unprivileged; scans counted; `MalwareScannerUnavailable` alerts | `tests/unit/adapters/test_malware_scanning.py`, `tests/unit/observability/test_alert_rules.py` |
| F-6 | Medium | Dependabot could not read how the images were pinned - no base or third-party image would ever get an update proposed; the BuildKit frontend was unpinned | Literal `FROM` lines and whole-value Compose defaults; the frontend pinned; a weekly scan of every third-party image | `tests/unit/test_image_pins.py`, `.github/workflows/supply-chain.yml` |
| F-7 | Medium | The secret tooling could not add a secret a new release needs without re-keying everything; no upgrade path to internal TLS; the internal PKI was undocumented | Add-missing mode (half-present groups refused), `--tls-urls`, `internal_pki.py --check`, the documentation | `tests/unit/test_internal_pki.py`, DEPLOYMENT.md |
| F-8 | Low | Restores ran the dumps' SQL as the superuser, and the manifest proved integrity, not origin | Each database restored by its owner role; manifests signed and verified | the CI backup round trip |
| F-9 | Low | Worker metrics of exited children accumulated on `/tmp` | Their own tmpfs, cleared at start; exiting children drop their gauges | `tests/unit/workers/test_worker_metrics.py` |
| F-10 | Low | n8n always started, and its owner account waited for whoever claimed it first | Opt-in (a Compose profile); claim the owner at once | `docker-compose.yml`, DEPLOYMENT.md |
| F-11 | Low | Earlier Docker engines expose ports published on 127.0.0.1 to the local network; the `public` network could open connections | Docker 28 required; a firewall rule for `public` | DEPLOYMENT.md |
| F-12 | Low | Tracing could not reach a collector; empty SMTP dead-lettered every account mail; Alertmanager's SMTP password could not be mounted; PostgreSQL and ClamAV ran as root | Collector placement documented; account mail skipped and logged; the secret mounted; both run as their own users | `tests/unit/workers/test_account_mail.py`, `docker-compose.yml` |

### R13 - what fixing R12 surfaced

| # | Severity | Finding | Resolution | Evidence |
|---|---|---|---|---|
| R13-1 | Medium | Sign-up answered `409 email_taken` - anyone could learn who has an account (R2-6, accepted until now) - and created the account at once, so anyone could open one in someone else's name, with a password of their choosing | Sign-up proves the address first: the same answer for every address, a link (or a notice) by e-mail, the account created by whoever opens the link | `tests/integration/test_signup.py`, `tests/security/test_api_security.py` |
| R13-2 | Medium | Personal data without an end: sign-in sessions (address, browser) and expired tokens were kept for ever; nothing produced a person's copy of their data; audit entries could not be removed after any retention period | Daily identity retention; `GET /users/me/export` and `nexusflow user export`; `nexusflow user erase`; `nexusflow audit purge` as the migrator (never the application) | `tests/integration/test_privacy.py`, [PRIVACY.md](PRIVACY.md) |
| R13-3 | High | The first weekly scan of the third-party images failed seven: Grafana ran from a repository that had stopped receiving releases, Prometheus from a long-term-support line out of support, nginx from a superseded mainline | Maintained lines (Grafana 12.4, Prometheus 3.13 LTS, nginx 1.30 slim, current n8n); what the newest releases still carry is accepted only when unreachable here, with its reason and an expiry date; n8n's findings are reported, not failed on | `.trivyignore.yaml`, `.github/workflows/supply-chain.yml`, SECURITY.md |
| R13-4 | Medium | n8n became opt-in (F-10) and so silently left CI's end-to-end stack; nothing checked the monitoring stack after it started | CI starts n8n again; end-to-end tests check Grafana's provisioned dashboard and data source, and a Prometheus with every alert rule, every target and Alertmanager | `tests/e2e/test_monitoring.py`, `.github/workflows/ci.yml` |
| R13-5 | Low | OWASP ZAP reported a "credit card number" in a response: nginx's 32-digit hexadecimal request ID now and then holds a Luhn-valid run of 13 digits | Request IDs shaped like UUIDs at the edge (no run beyond 12 digits), in the logs, the edge's errors and the forwarded header | `tests/unit/test_edge_config.py`, `tests/e2e/test_edge.py` |
| R13-6 | Medium | The password step reset the failure counter when it issued the MFA challenge: whoever knew the password could guess four TOTP codes per password step, for ever - some 20 guesses a minute per account within the rate limits, about an 8 % chance of a hit a day (found while adding passkeys, which cannot be guessed) | The counter runs across both factors until a sign-in completes: wrong passwords and wrong codes add up to one exponential lockout | `tests/security/test_mfa_guessing.py` |

## 3. Checklist (specification section 39)

| Item | How it is addressed | Evidence |
|---|---|---|
| Authentication | Argon2id; breached passwords refused; e-mail-verified sign-up; EdDSA access tokens (10 min) with key IDs; rotating refresh tokens with reuse detection; TOTP with replay protection; lockout; password confirmations counted like sign-ins; sign-in risk; session list and revocation; API keys capped by the creator's membership; per-organization network allowlists for sessions, renewals and API keys | `tests/integration/test_identity_flows.py`, `tests/security/` (incl. `test_network_allowlist.py`) |
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
| Tenant isolation | Forced RLS on a non-bypass role, explicit `org_id` filters (checked statically), `404` for foreign identifiers | `test_database_security.py`, `test_idor_sweep.py`, `test_repository_tenant_filters.py` |
| Race conditions | State machines with row locks, unique constraints, `SKIP LOCKED` claims, fencing of reaped work | `test_core_chain.py` (concurrent deliveries, reaped analysis) |
| Replay attacks | Webhook timestamp window plus nonce plus unique row; refresh-token reuse detection; TOTP step replay | `test_business_api.py`, identity tests |
| Idempotency | `Idempotency-Key` on commands; idempotent workers; failure ledger idempotent per execution | `test_business_api.py`, `test_failure_ledger.py` |
| Error leakage | Uniform error schema; internals only in logs; validation errors never echo input | `test_api_security.py` |
| Dependency vulnerabilities | Hash-locked `uv.lock`, pip-audit, Trivy, CodeQL, Semgrep, Gitleaks, Dependabot; images and actions pinned by digest and SHA (checked in CI) in forms Dependabot reads; a weekly rebuild and scan of the platform's images and a weekly scan of every third-party image, with documented, expiring exceptions; zizmor audits the workflows (pedantic, with online checks for impostor commits and vulnerable actions); dependency review and OpenSSF Scorecard once the repository is public | CI |

## 4. What remains

Residual risks accepted by design are listed per component in the
[threat model](THREAT_MODEL.md); limitations of the product and of this
review are in [FINAL_REVIEW.md](FINAL_REVIEW.md). Before production, commission
an independent penetration test and run the deployment checklist in
[DEPLOYMENT.md](DEPLOYMENT.md).
