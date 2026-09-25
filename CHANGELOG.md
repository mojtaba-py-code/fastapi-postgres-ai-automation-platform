# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-09-25

### Added
* Identity and access:
  * registration and login with Argon2id and exponential lockout;
  * EdDSA access tokens and rotating refresh tokens with reuse detection;
  * TOTP MFA with recovery codes;
  * scoped API keys, capped by their creator's current membership;
  * organizations, memberships, invitations and five roles with 38 permissions.
* Multi-tenancy with forced PostgreSQL row-level security and least-privilege
  database roles.
* Hash-chained, append-only audit log per tenant plus a platform chain, with
  verification (`nexusflow audit verify`) and hourly external anchoring.
* Data platform:
  * projects and typed datasets with data classification (restricted data never
    leaves the platform);
  * sources (website, REST API, signed webhook, CSV/XLSX upload);
  * a pipeline of explicit stages - validate, normalize, clean (including URL
    tracking parameters), deduplicate, enrich;
  * versioned records, change detection with significance scoring, and exports.
* Intelligence: offline analyzer and an Anthropic provider (opt-in per tenant), with
  redaction, spotlighting, a read-only tool gateway and strict output validation.
* Alert rules, notification channels (e-mail, Slack, Telegram, signed webhooks) and
  reports in JSON, CSV, XLSX and PDF, with a daily trend, a trend note, unusual days
  (robust statistics) and a change-volume chart.
* Change analytics (`GET /api/v1/analytics/changes`): totals per type and
  significance, every day of the period, unusual days and a trend note for a
  project or dataset, aggregated by the database over every change.
* Sign-in risk assessment: a new device, a new network (/24, /48) and success
  after repeated failures. Users are e-mailed the time, address and device of an
  unfamiliar sign-in; suspicious ones are also audited, counted and alerted on
  (`SuspiciousSignIns`).
* Request correlation: the request ID travels with the outbox messages into every
  job it causes and their log lines (also for scheduled jobs and CLI commands).
* Encryption at rest by the application: the values of `sensitive` fields in
  records, their versions and change diffs, staged raw payloads, and stored files
  (uploads, reports; streaming AES-256-GCM) - each bound to its tenant and row or
  file, re-wrapped on key rotation, failing closed when moved or altered. Record
  content hashes are keyed.
* Automation:
  * workflows, a transactional outbox and Celery workers (pipeline, integrations,
    sandbox);
  * dead letters, a reaper (runs, deliveries, analyses, reports), retention and key
    re-wrapping;
  * five n8n workflows, generated from `scripts/generate_n8n_workflows.py` and
    linted, including failure recovery with platform-counted retries and backoff;
  * the internal automation API;
  * per-workflow, per-tenant and global kill switches.
* Sandbox trust boundary with per-run HMAC tickets, and an isolated headless-browser
  service behind a pinning egress proxy.
* Operator CLI (`nexusflow`): service accounts, kill switch, key rotation, audit
  verification, migrations, configuration check.
* Deployment:
  * hardened Docker images; worker and beat health from an event-loop heartbeat;
  * segmented docker-compose with file secrets, each mounted only where needed;
  * nginx edge, Redis ACL and RabbitMQ definitions generated with password hashes;
  * Prometheus alerts, Alertmanager and a Grafana dashboard;
  * encrypted backups;
  * a demo overlay (Mailpit, development CA) and `make demo`, a scripted walkthrough.
* Documentation: architecture, API, generated configuration reference, deployment,
  demo, development, threat model (with an attack-surface enumeration), security
  review record, incident response and final review.
* CI: Ruff, mypy (strict), import-linter, Bandit, pip-audit, Semgrep (pinned),
  Gitleaks, CodeQL, Trivy and SBOMs for both images, the n8n lint, drift checks
  (configuration reference, image digests), and an end-to-end job against the full
  Compose stack that also backs it up, changes it, restores it and verifies the
  audit chains; actions pinned to commit SHAs.
* Release workflow: a version tag publishes both images to GHCR, scanned first,
  with SBOM and provenance attestations, signed keyless with cosign.
* Base and third-party images pinned to digests (`make pin-images`).
* DAST in CI: OWASP ZAP requests every API operation of the running stack as a
  signed-in owner and scans the responses passively; Medium or High alerts fail
  the build. zizmor audits the workflows; dependency review and OpenSSF Scorecard
  run once the repository is public.
* A self-assessed OWASP ASVS 5.0 mapping with evidence and gaps (`docs/ASVS.md`).

### Security
The code went through several AI-assisted reviews (adversarial code review,
due-diligence and traceability audits, test-driven reviews of the adapters and the
core chain). Every finding is fixed with a regression test, or accepted as a
residual risk in the threat model. The full record is in
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md); the main items:

* Sandbox isolation: the sandbox broker user can no longer declare queues or
  bindings (it could have tapped jobs); the sandbox app never declares, runs one
  process per job, and an upload's input is single-use per attempt. The sandbox
  queue is bounded (`reject-publish`) and the sandbox has its own Redis.
* The sandbox gateway checks the ticket before reading a result body, caps the body
  per run, parses it off the event loop and handles large bodies one at a time.
* The global kill switch and tenant freezes also stop internal orchestration.
* Failure events can no longer loop, and identical operator alerts page once per
  15 minutes.
* The headless browser connects only through a pinning egress proxy (no DNS
  rebinding).
* Webhooks: a delivery that fails to store stays retryable; unknown endpoints cost
  the same HMAC work; the per-endpoint quota is charged only after the signature
  verifies; no row lock before authentication.
* API keys lose the permissions their creator loses, and are revoked when the
  creator leaves; password hashing never runs under a row lock.
* robots.txt follows RFC 9309 (longest match, wildcards), is checked on every
  redirect hop and cannot redirect outside a source's allowed domains.
* Restricted datasets are never sent to external AI, and their alerts carry no
  record keys or values; key fields cannot be marked sensitive.
* Every resource route answers `404` for another tenant's identifiers (IDOR sweep).
* Crafted pagination cursors and other data exceptions return `422` instead of `500`.
* Sign-in e-mails describe the device in a fixed vocabulary and never quote the
  client's user agent (no sender-chosen text in platform e-mails).
* Changing the password is rate limited per user, and a wrong current password
  counts toward lockout (a stolen access token is no password oracle).
* Breached passwords are refused: 72,985 of 12 characters or more from public
  corpora, including the UK NCSC's 100,000 most used.
* Organizations can confine access to their own networks (`allowed_ip_ranges`):
  members' sessions and API keys work only from the listed CIDR ranges. Refusals are
  counted and alerted (`NetworkAllowlistDenials`), valid sign-ins from outside are
  audited, administrators cannot lock themselves out, and operators can lift a list
  (`nexusflow org clear-network-allowlist`).
* Every Prometheus alert and Grafana query is checked against the metrics and labels
  the platform exports, so a misspelt rule cannot fail silently.
* Users list their signed-in sessions (`GET /api/v1/users/me/sessions`) and end any
  one of them at once; API keys cannot manage sessions.
* A daily job verifies every audit hash chain; a break is alerted
  (`AuditChainBroken`) and pages the operators.
* AI analyses and exports are charged to the person behind an API key, so more
  keys do not buy more budget.
* Uploads: macro-enabled workbooks are recognised by their content types and
  relationships too; duplicate parts and empty CSV files are refused at intake;
  every CSV row obeys the column cap.
* The browser image no longer ships the base image's unused global pip and
  virtualenv (with the vulnerable setuptools and msgpack they carried).

### Fixed
* Retention never deleted anything: the dead-letter purge lacked a privilege and
  rolled back the whole pass (now a narrow `SECURITY DEFINER` function).
* The integrations worker could not start in the demo stack: a setting named
  `..._file` was read as a secret file (renamed; guarded by tests).
* A REST source stopped at its page cap was treated as a complete snapshot, so
  records beyond the cap were marked deleted.
* A redirect answer counted as a delivered notification; temporary SMTP errors
  dropped alerts; throttling used up delivery attempts; a blocked destination left
  a delivery stuck; notification dead letters did not page operators.
* Extreme decimals made change detection overflow on every retry.
* An analysis interrupted by a worker crash stayed running forever.
* Account deletion always failed.
* Workflow 5's retry path could never retry.
* Reports read at most 5,000 changes in time order, so a busy period's totals,
  trend and summary were wrong; the AI tool's statistics were capped the same way.
* Backups could not run (local database connections need a password) and a restore
  failed on a superuser-owned extension.
* A small workbook with sparse row numbers could cost the sandbox minutes of CPU;
  broken or hostile workbook content crashed the parser (and was retried) instead
  of failing the upload.
* Tuning a fail-closed rate limit silently made it fail open, and the limiter
  admitted more than a fractional-interval rule allowed.
* For accounts with MFA, a successful sign-in right after several wrong passwords
  lost its "after failures" risk signal (R10-1).
* From the deployment review: Prometheus could not start; JavaScript rendering
  could not be used; large uploads spooled to a small in-memory `/tmp`; RabbitMQ
  lost its queues when recreated; delayed retries held worker slots; nginx kept a
  recreated API's old address; worker memory recycling exceeded the container
  limit; development certificates depended on the umask.
* The edge (nginx) refused to start - a timeout directive was set twice for the
  download routes - so the platform was unreachable; found by the first run of the
  full stack in CI (R11-1). CI now tests the edge configuration before starting
  the stack.
* The backup and restore scripts had lost their executable bit, so backups failed
  as documented (R11-2); a test now guards every script's mode.
* Responses generated by the edge itself (hidden paths, 413, 429, 502) lacked the
  security headers and answered in HTML; they now carry the application's headers
  and JSON error schema (R11-3, found by the first DAST run).

## [Unreleased]

Nothing yet.
