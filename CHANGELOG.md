# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
* E-mail-verified sign-up: `POST /auth/register` takes an address and mails it a
  link - or, if it already has an account, a notice; `POST /auth/register/complete`
  creates the account and its organization; an invitation creates the account
  directly (`POST /auth/register/invitation`). Operators print a link instead of
  mailing it with `nexusflow signup issue`, also while self-service sign-up is off.
* Privacy tooling ([docs/PRIVACY.md](docs/PRIVACY.md)): a person's copy of their
  data (`GET /users/me/export`, `nexusflow user export`), erasure on request
  (`nexusflow user erase`), a daily identity retention (sessions 90 days after they
  expire, expired tokens after a week) and audit retention run as the migrator
  (`nexusflow audit purge`).
* Internal TLS on every hop by default - PostgreSQL (`hostssl` only,
  `verify-full`), both Redis instances and RabbitMQ accept TLS only - with a
  private CA (`scripts/internal_pki.py`, `--check` for expiring certificates).
* Optional HashiCorp Vault transit wrapping of the key-encryption keys
  (`security.kek_provider=vault-transit`, `docker-compose.vault.yml`,
  `nexusflow keys vault-wrap | vault-new | vault-rewrap`).
* Weekly security runs: CI rebuilds and scans the platform's images and runs the
  whole stack every week; Trivy scans every third-party image, with expiring,
  reasoned exceptions in `.trivyignore.yaml`.
* End-to-end tests of the monitoring stack: Grafana's provisioned dashboard and
  data source, Prometheus's rules, targets and Alertmanager.
* A periodic alert sweep (both orchestration modes); `keys rewrap` reports what
  is left under old keys and retries rows in use; jobs that delete the files of
  deleted rows and seal the values of fields marked sensitive later.
* Backups: signed manifests (`BACKUP_SIGNING_KEY`, verified with
  `BACKUP_ALLOWED_SIGNERS`); edge certificates installed with
  `scripts/install_edge_cert.sh` and renewed through the ACME webroot.

### Changed
* **API:** `POST /auth/register` takes only `email` and answers `202`; the account
  is created by `/auth/register/complete`; invited people use
  `/auth/register/invitation` instead of an `invitation_token` field.
* Idempotency keys are bound to the request they started - reusing one for a
  different request answers `409 idempotency_key_reused` - and are released after
  `retention.idempotency_keys_hours`. Webhook receipts report `truncated`; run
  statistics carry `collected_at` and `superseded`.
* Record keys longer than 512 characters are stored as a prefix and a hash: an
  existing record with such a key is re-created once.
* Stored files without the sealed header are refused.
* Reports fail only once their retries are spent, and a dead-letter retry redoes
  the work.
* Images: Grafana from `grafana/grafana` 12.4 (the `grafana-oss` repository stopped
  receiving releases), Prometheus 3.13 (its long-term-support line), nginx 1.30
  slim, n8n 2.40.7; base images pinned in literal `FROM` lines Dependabot reads.
* n8n is opt-in (Compose profile `n8n`); ClamAV gets 4 GiB and runs unprivileged;
  PostgreSQL runs as its own user; ports are published on IPv4; Docker Engine 28
  or later is required.
* Request IDs are shaped like UUIDs from the edge on.

### Security
Review round 12 - six parallel AI-assisted reviews of the whole platform, 53
unique findings (5 High, 28 Medium, 20 Low) - and round 13, five findings its fixes
surfaced. All are fixed except one accepted residual risk (D-n2); the record is in
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). The main items:

* A password confirmation (MFA, account erasure) counts like a sign-in: a stolen
  token or API key is no longer an unlimited password oracle (A-1).
* Sign-up no longer reveals who has an account, and no one can open an account in
  someone else's name (R13-1; accepted until now as R2-6).
* Network allowlists also stop session renewal (A-3); members can set up the MFA
  their organization requires (A-2).
* Key rotation no longer reports success while data is still under an old key
  (B-1); a field marked sensitive later has its stored values sealed (B-5); files
  are deleted with their rows (B-6); every data query names its tenant (D-n1).
* Slack text is escaped (D-2); the AI link filter judges a link by the host a
  browser would open (D-3).
* Restores run as the owning roles, never as the superuser, and backups are signed
  (F-8); the documented egress firewall no longer breaks DNS (F-1).
* Third-party images moved off lines that no longer received fixes (R13-3).

### Fixed
* XLSX uploads failed in the sandbox (C-1).
* Alerts beyond 500 pending changes were never evaluated (D-1).
* Retention ran into the statement timeout and never ran again (E-1), handled only
  200 datasets and never purged changes (B-9, D-6); large deletes and purges now
  run in batches (E-3, E-7).
* Audit verification stopped at 100,000 entries and said "ok" (E-4); an audit
  purge could leave a gap reported as tampering (E-5).
* One malformed item failed a whole run (B-4); snapshots applied out of order
  (B-8); records kept a source that no longer saw them (B-7); long keys collided
  (B-3); long cursors were refused (B-10).
* A hostile robots.txt could keep a worker busy for an hour (C-3); a page that never
  yielded kept a renderer slot (C-2); an outage answered in HTML failed for good
  (C-4); sandbox retries after a busy gateway, and refusals by the gateway (C-5);
  runs the reaper gave up on raised no failure (C-6); non-ASCII digits in numeric
  headers (C-8).
* Report scope, trend and AI budget accounting (D-9, D-10, D-11);
  `GET /sources/{foreign}/uploads` answered 200 (D-13).
* Deployment: RabbitMQ's memory watermark (F-4), ClamAV's memory (F-5), Dependabot
  could not read the image pins (F-6), secrets on upgrade (F-7), worker metrics of
  exited children (F-9), account mail with e-mail off (F-12).
* A DAST false positive: nginx's request IDs could look like card numbers (R13-5).

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
