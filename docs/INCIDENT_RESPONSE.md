# Incident response

## 1. Roles and severities

| Severity | Examples | Response |
|---|---|---|
| **SEV-1** | Confirmed cross-tenant access, key-material compromise, audit chain broken, active exploitation | Page immediately; incident commander; freeze first, investigate second |
| **SEV-2** | Credential stuffing in progress, compromised API key/service token, sandbox compromise suspected | Respond within 1 hour |
| **SEV-3** | Elevated errors, dead letters accumulating, blocked SSRF probing | Next business day |

Roles: **incident commander** (decides and communicates), **operator** (executes
commands, preserves evidence), **scribe** (keeps the timeline). All CLI commands
below are written to the platform audit chain.

Run CLI commands in the internal API container. It is the one that reaches n8n
and holds the n8n API key (`secrets/n8n_api_key`) that unpublishing needs:

```bash
docker compose run --rm api-internal nexusflow kill-switch status
```

Commands print JSON. The kill switch exits with status 3 when the flag was set
but some n8n workflows could not be unpublished; the output lists them.

## 2. Emergency stop: automation kill switches

Use the narrowest switch that contains the incident.

| Scope | Command / action | Effect |
|---|---|---|
| **One n8n workflow** | `nexusflow service-account disable --workflow-key <key> --reason "<why>"` | That workflow's token is rejected immediately; other workflows keep running |
| **One tenant** | `POST /api/v1/organizations/current/automation-freeze {"frozen": true, "reason": "..."}` (owner/admin/operator) | Runs, uploads, webhooks and n8n steps for that tenant are refused; queued runs are cancelled, not failed |
| **Everything** | `nexusflow kill-switch engage --reason "<why>" --deactivate-n8n <workflow ids>` | The flag is set first, then: all automation endpoints answer `503 automation_disabled`, the listed n8n workflows are unpublished, and failure reporting still works. The flag has no TTL and fails safe if Redis is unreachable. The engagement is audited even when n8n is unreachable |
| **Cut n8n out entirely** | Set `NEXUSFLOW_ORCHESTRATION=internal` in `.env`, `docker compose up -d` (recreates the platform containers), `docker compose stop n8n` | The platform orchestrates itself; no n8n involvement |

Release: `nexusflow kill-switch release --reason "<why>"`, then unfreeze the tenants.

## 3. Playbooks

### 3.1 Credential attacks (alerts `CredentialStuffingSuspected`, `SuspiciousSignIns`)
`CredentialStuffingSuspected` fires on sustained failed logins; `SuspiciousSignIns`
on successful sign-ins that look like a working attack - a new device on a new
network, or a new device or network right after several wrong passwords.
1. Check the rate-limit rejections and the top source IPs in nginx logs; block abusive
   ranges at the firewall or WAF.
2. Lockout and fail-closed limits are already active. Consider temporarily lowering
   `auth.login.*` limits (configuration change and redeploy).
3. Find the accounts signed in during the window: audit `auth.login.suspicious` first,
   then `auth.login.new_device` (a new device *or* network). Every
   `auth.login.succeeded` entry carries its `risk` and `signals` (`new_device`,
   `new_network`, `after_failures`). The users were e-mailed the time, IP address
   and device of each such sign-in. Force `logout-all` and a password reset for
   affected users; recommend MFA or enforce it per organization (`require_mfa`).

### 3.2 Compromised user account
1. Owner/admin removes the membership or changes the role (audited).
2. The user runs `POST /auth/logout-all` or an operator revokes sessions. A password
   change revokes all other sessions and increments the token version.
3. Review the audit trail for the actor: `GET /api/v1/audit?actor_id=...`.

### 3.3 Leaked API key or service token
* API key: `DELETE /api/v1/api-keys/{id}` (immediate). Review `last_used_at` and the
  audit trail by `actor_type=api_key`.
* n8n service token: `nexusflow service-account rotate --workflow-key <key>`, then
  update the n8n credential. `disable` first if the token is being actively abused.

### 3.4 Leaked integration or webhook secret
* Integration: `POST /api/v1/integrations/{id}/status {"status":"quarantined"}`, then
  rotate at the provider and `POST /integrations/{id}/rotate`.
* Webhook: `POST /api/v1/webhook-endpoints/{id}/rotate-secret`. The old secret stays
  valid for 24 h for the sender to switch; disable the endpoint to cut it immediately.

### 3.5 Key-material compromise (SEV-1)
* **JWT signing key**:
  1. Generate a new Ed25519 key and install it with a new `jwt_key_id`.
  2. Remove the compromised public key from `jwt_previous_public_keys`.
  3. Redeploy. All access tokens die within their 10-minute TTL, or immediately if
     the old key is dropped.
* **KEK**:
  1. Add a new key to `encryption_keys` and make it active.
  2. Redeploy, then run `nexusflow keys rewrap` until it reports 0.
  3. Remove the compromised KEK.
  4. Rotate every integration secret at its provider, because they may have been
     decrypted.
* **HMAC pepper**: rotating it invalidates every stored token hash. All API keys,
  refresh tokens, reset links and invitations become unusable. Announce it, rotate,
  and ask tenants to re-issue API keys; users simply sign in again.
* **Database or broker passwords**: regenerate the affected secret, update the
  role, Redis ACL or definitions, and restart the dependent services.

### 3.6 Suspected cross-tenant access (SEV-1)
1. Freeze automation globally and preserve the database, logs and audit trail.
2. Verify every chain: `nexusflow audit verify`.
3. Check RLS state: `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r';`
   Every tenant table must show `t, t`.
4. Look for `404`/`403` storms per principal and for `AuthorizationDenialsSpike`.
5. Notify affected tenants according to your legal obligations.

### 3.7 Sandbox or browser compromise suspected
1. `docker compose stop sandbox browser`. Collection of websites and uploads pauses
   and runs are recovered by the reaper later.
2. Rotate `broker_sandbox_url` (and the sandbox user in the RabbitMQ definitions),
   `redis_sandbox_url` with `redis_sandbox_acl`, and `browser_token`, then rebuild
   the images from a clean base. `redis-sandbox` holds only caches: recreate it
   (`docker compose rm -sf redis-sandbox`) rather than inspecting it.
3. Scope: a compromised sandbox container can have consumed *any* job queued in the
   window (it holds the pool's broker credentials) and submitted falsified results
   for those runs. Review the runs that received results during the window (the
   internal API logs ticket use per run); treat their collected data as untrusted.
   Stored files, other runs, secrets and the database are out of its reach.
4. Look for `egress_blocked` events from the browser's pinning proxy: repeated blocks
   for internal addresses indicate a page probing for SSRF. Many `gateway_busy`
   answers mean something is submitting large results back to back.
5. Re-run affected collections after the rebuild. Runs that the sandbox failed
   released their uploads, so affected files can simply be uploaded again.

### 3.8 Prompt injection or AI misbehaviour (alert `AiToolCallsDenied`)
1. Disable external processing for the tenant
   (`PATCH /organizations/current {"settings": {"ai_external_processing": false}}`),
   for one dataset by classifying it `restricted` (restricted data is always
   analysed offline), or platform-wide with `NEXUSFLOW_AI_PROVIDER=offline` in
   `.env` and `docker compose up -d worker-integrations`.
2. Review the affected insights and the dataset content that fed them. Insights are
   advisory; tell users about misleading ones.

### 3.9 Audit chain verification fails (SEV-1)
`nexusflow audit verify` recomputes every tenant chain and the platform chain
(events without a tenant: failed sign-ins for unknown accounts, operator
commands); `--org <id>` checks one tenant.
1. Treat it as tampering until proven otherwise. Freeze, snapshot the database volume,
   and collect the anchored chain heads (`audit_anchor` log events, one per chain
   per hour, `chain=platform` for the platform chain).
2. The first invalid `seq` shows where history diverges. Compare it with the anchors
   to bound the time window, and restore from a backup taken before it if needed.

### 3.10 Unhealthy workers or undelivered alerts (SEV-3, SEV-2 if alerts are lost)
1. `docker compose ps`: workers and beat are unhealthy when their heartbeat goes
   stale - a hung event loop or no broker connection. Check the service's logs,
   then `docker compose restart <service>`. Work that was in flight is recovered
   by the reaper (every 5 minutes): runs, deliveries and analyses are re-queued
   with backoff and failed after a bounded number of attempts.
2. Undelivered notifications: temporary errors (SMTP 4xx, 5xx from a webhook,
   network) are retried with backoff; a rate-limited channel waits without using
   up attempts; permanent errors and exhausted retries become dead letters and
   emit `job.failed`, which pages operators. Review them in
   `GET /api/v1/dead-letters` and re-drive with `POST /dead-letters/{id}/retry`.
3. Collections failing with `robots_unavailable` are retried automatically (the
   site's robots.txt could not be fetched); `robots_redirect_blocked` means the
   site's robots.txt redirects outside the source's allowed domains - add the
   target domain to the source's allowlist or leave the source paused.

### 3.11 Vulnerable dependency
1. Triage CVSS and reachability; `pip-audit` and Trivy results are in CI.
2. Bump the dependency in `uv.lock` (`uv lock --upgrade-package <name>`), run
   `make check`, rebuild and redeploy.

## 4. Evidence and forensics

Preserve these **before** remediating when you can:
* the audit log (`audit_logs`, append-only) and the external chain anchors;
* JSON logs of every container. The request ID (`X-Request-ID`, echoed in every
  error body) links nginx and API log lines, and travels with the outbox
  messages the request committed: worker log lines of every job it caused -
  and of the jobs *those* caused - carry it as `request_id`, next to the task
  name, task ID and organization. A scheduled job correlates its follow-up work
  with its own task ID; an operator command with a `cli-...` ID. To follow a
  request end to end, search all containers' logs for its ID, or query
  `outbox_messages.correlation_id`;
* database and volume snapshots;
* Prometheus data (`prometheus-data` volume).

## 5. After the incident

Within 5 business days, hold a blameless review: timeline, root cause, what worked,
action items with owners. Update this document and the threat model.
