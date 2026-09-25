# REST API

Base URL: `https://<your-domain>/api/v1`. All bodies are JSON (except uploads) and
all timestamps are ISO-8601 with a time zone. The OpenAPI document and Swagger UI
(`/docs`) are available outside production and disabled in production.

## Authentication

| Method | How |
|---|---|
| **User session** | `POST /auth/login {email, password}` returns an `access_token` (10 min) and a `refresh_token`. If MFA is enabled it instead returns `{mfa_required: true, mfa_token, expires_in}`; finish with `POST /auth/mfa/verify {mfa_token, code}` (a TOTP code or a recovery code). Send `Authorization: Bearer <access_token>`. |
| **Refresh** | `POST /auth/refresh {refresh_token}` issues a new pair. Refresh tokens are single-use; presenting a used one revokes the whole session. |
| **API key** | Create with `POST /api-keys {name, role, scopes[], expires_in_days}`. The `nxf_…` token is shown **once**; send it as `Authorization: Bearer nxf_…`. Scopes must be a subset of the role's permissions. |
| **OAuth2 password form** | `POST /auth/token` (form-encoded), for tools that expect the OAuth2 password flow. |

The public signing keys are published at `/.well-known/jwks.json`.

Other authentication endpoints:
* sign-up: `/auth/register`;
* sign-out: `/auth/logout`, `/auth/logout-all`;
* passwords: `/auth/password/change`, `/auth/password/reset-request`,
  `/auth/password/reset`;
* MFA: `/auth/mfa/enroll`, `/auth/mfa/confirm`, `/auth/mfa/disable`;
* organizations: `/auth/switch-organization`, `/auth/invitations/accept`.

## Conventions

**Errors** always have the same shape. `request_id` matches the `X-Request-ID`
response header and the logs:

```json
{"error": "permission_denied", "message": "You are not allowed to perform this action.", "request_id": "…", "details": null}
```

| Status | Meaning |
|---|---|
| 400 | Malformed multipart or protocol-level problem |
| 401 | Missing or invalid credentials (`WWW-Authenticate` set) |
| 403 | Authenticated but not permitted |
| 404 | Not found **or belongs to another tenant** |
| 409 | State conflict (e.g. `automation_frozen`, `report_not_ready`, `duplicate`) |
| 413 / 415 | Body too large / unsupported media type |
| 422 | Validation failed: `details` lists fields and codes, never the submitted values. `invalid_cursor` for a cursor that does not fit the sort; `invalid_value` for a value the database cannot store |
| 429 | Rate limited: honour `Retry-After` |
| 503 | Dependency unavailable or automation kill switch engaged |

**Pagination** is keyset-based. Query parameters are `limit` (1 to 200, default 50),
`cursor` (opaque, from `next_cursor`) and `sort` (`field` or `-field`, from a
per-resource allowlist). Responses have the form `{"items": [...], "next_cursor": "…"|null}`.
A cursor is only valid with the sort it was issued for; tampered cursors are
rejected with `422 invalid_cursor`.

**Idempotency**: `POST /sources/{id}/runs`, `POST /workflows/{id}/runs`,
`POST /intelligence/analyses` and `POST /reports` accept an `Idempotency-Key` header
(8 to 128 characters of `[A-Za-z0-9._:-]`). A repeat with the same key returns
`200` with the original resource instead of `202` with a new one.

**Rate limits** (defaults, per principal unless noted):

| Scope | Limit |
|---|---|
| Reads / writes | 600 / 120 per minute |
| Exports and downloads | 20 per hour per person (all of a user's API keys share it) |
| AI analyses | 30 per hour per person (all of a user's API keys share it) |
| Login | 20 per minute per IP, 5 per minute per account |
| Password change | 5 per 15 minutes per user; a wrong current password also counts toward lockout |
| Webhook receipt | 600 per minute per IP (before verification); 120 per minute per endpoint, counted only for correctly signed deliveries |

**Mass assignment**: request bodies reject unknown fields with `422`. Fields such as
`org_id`, `status` or `role` can never be smuggled into a create or update.

## Resources

Permissions in brackets. Owners have all permissions; see `domain/authorization/roles.py`
for the role matrix.

### Organization, users, access
| Method | Path | |
|---|---|---|
| GET/PATCH | `/users/me` | Profile |
| GET | `/users` | Users of the current organization, with their roles [members:read] |
| POST | `/users/me/delete` | Erase own account (password confirmation) |
| GET | `/organizations` | Organizations of the current user |
| GET/PATCH | `/organizations/current` | View / update [org:update]. `settings` is a partial update |
| POST | `/organizations/current/automation-freeze` | Tenant kill switch with reason [workflows:disable] |
| POST | `/organizations/current/deletion` | Request deletion (slug confirmation, 7-day grace) [org:delete] |
| GET, PATCH, DELETE | `/organizations/current/members[/{id}]` | Members and roles [members:read / members:manage] |
| GET, POST, DELETE | `/organizations/current/invitations[/{id}]` | Invitations [members:manage] |
| GET, POST, DELETE | `/api-keys[/{id}]` | API keys [api_keys:manage] |
| GET | `/audit`, `/audit/verify` | Audit trail and hash-chain verification [audit:read] |

### Data
| Method | Path | |
|---|---|---|
| GET, POST, GET/PATCH/DELETE | `/projects`, `/projects/{id}` | [projects:read / projects:write]. Deleting a project that still has datasets answers `409 project_not_empty` |
| GET, POST, GET/PATCH/DELETE | `/datasets`, `/datasets/{id}` | Typed schema, classification, retention [datasets:*]. The key field cannot be `sensitive` (`422`): record keys appear in alerts, reports and AI prompts |
| GET | `/datasets/{id}/records` | Current records; sensitive fields masked without [records:read_sensitive] |
| GET | `/datasets/{id}/export?format=csv\|jsonl` | Streaming, audited export [datasets:export] |
| GET | `/records/{id}/history` | Version history [records:read] |
| GET | `/changes` | Filter by `dataset_id`, `record_id`, `change_type`, `min_significance`, `since` [changes:read] |
| GET | `/analytics/changes?project_id=&dataset_id=&period_start=&period_end=` | Change volume of a project or one of its datasets: totals per type and significance, every UTC day of the period (quiet days included), unusual days (robust z-score) and a trend note. Counts only, computed on request; the period defaults to the last 30 days and is at most a year (`422 invalid_period`) [changes:read] |

### Collection
| Method | Path | |
|---|---|---|
| GET, POST, GET/PATCH/DELETE | `/sources`, `/sources/{id}` | Website, REST API, webhook and file-upload sources [sources:*] |
| POST | `/sources/{id}/runs` | Run now (pull sources) [sources:run] |
| GET | `/sources/{id}/runs`, `/runs/{id}` | Run history and status |
| POST | `/sources/{id}/uploads` | `multipart/form-data`, one part named `file` (CSV/XLSX). Re-uploading a file that is already live returns `200` with the existing upload; a file whose run failed can be uploaded again (`201`) [uploads:write] |
| GET | `/sources/{id}/uploads` | Upload history |
| GET, POST, GET/DELETE | `/integrations`, `/integrations/{id}` | Credentials; secrets are write-only [integrations:*] |
| POST | `/integrations/{id}/rotate`, `/integrations/{id}/status` | Rotate / revoke / quarantine |
| GET, POST | `/webhook-endpoints` | Inbound endpoints; the signing secret is shown once [webhooks:*] |
| POST | `/webhook-endpoints/{id}/rotate-secret`, `/webhook-endpoints/{id}/status` | Rotation (24 h grace), disable |

### Intelligence, alerting, reporting, automation
| Method | Path | |
|---|---|---|
| POST | `/intelligence/analyses {dataset_id}` | Queue an analysis [insights:generate] |
| GET | `/intelligence/insights[/{id}]` | Insights [insights:read] |
| GET, POST, PATCH, DELETE | `/alert-rules[/{id}]` | Conditions: `change_type`, `significance_at_least`, `field_changed` (updates only; use `change_type` for new or deleted records), `numeric_change`, `insight_risk_at_least`, `run_failed`. Conditions see the complete change, including sensitive fields; the alert shows them masked [alerts:*] |
| GET | `/alerts?status=` | Alerts [alerts:read] |
| POST | `/alerts/{id}/acknowledge {resolve}` | [alerts:ack] |
| GET, POST, PATCH, DELETE | `/channels[/{id}]` | Email, Slack, Telegram, signed webhook [channels:*] |
| POST | `/reports` | JSON, CSV, XLSX or PDF for a period of up to a year [reports:generate]. JSON, XLSX and PDF contain the executive summary, totals, the daily trend and a trend note, unusual days, anomalies (the 25 most significant high and critical changes), the 200 most significant changes, alerts, AI insights and sources; XLSX and PDF add a change-volume chart. Totals, the trend and the summary count every change of the period, however many. CSV is one table: the listed changes |
| GET | `/reports[/{id}]`, `/reports/{id}/download` | Downloads are attachments with a `Repr-Digest` SHA-256 header [reports:download] |
| GET, POST, GET/PATCH/DELETE | `/workflows[/{id}]` | Scheduled collection → detection → analysis → alerting [workflows:*] |
| POST | `/workflows/{id}/status {status, reason}` | Activate, pause or disable (emergency stop) |
| POST, GET | `/workflows/{id}/runs` | Run now (idempotent) / history [workflows:execute / read] |
| GET | `/dead-letters` | Failed jobs [dead_letters:manage] |
| POST | `/dead-letters/{id}/retry`, `/dead-letters/{id}/discard` | Re-drive idempotent jobs |

## Inbound webhooks

`POST /api/v1/webhooks/{org_id}/{endpoint_id}` with a JSON body and two headers:

```
X-NexusFlow-Delivery:  <unique id, 8-128 chars of [A-Za-z0-9._:-]>
X-NexusFlow-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>
```

The signature is `HMAC_SHA256(secret, f"{t}.{delivery_id}." + raw_body)`:

```python
import hashlib, hmac, json, time, uuid

body = json.dumps({"items": [{"sku": "A-1", "price": "9.99"}]}).encode()
timestamp, delivery = int(time.time()), str(uuid.uuid4())
mac = hmac.new(secret.encode(), f"{timestamp}.{delivery}.".encode() + body, hashlib.sha256).hexdigest()
headers = {
    "Content-Type": "application/json",
    "X-NexusFlow-Delivery": delivery,
    "X-NexusFlow-Signature": f"t={timestamp},v1={mac}",
}
```

| Response | Meaning |
|---|---|
| `202 {"status": "accepted", "run_id": …}` | Queued for processing |
| `200 {"status": "duplicate"}` | Already received **and stored**; safe to stop retrying |
| `401 invalid_signature` | Bad signature, stale timestamp or unknown endpoint (indistinguishable) |
| `409 delivery_in_progress` | An earlier attempt with this delivery id has not finished; retry later with the same id |
| `409 source_inactive` | The source or organization is not accepting data; retry later |
| `422` | The signed body is not valid JSON or does not match the source mapping; fix it and retry with the same delivery id |
| `429` | The endpoint's delivery quota is spent; honour `Retry-After` |

Timestamps must be within 5 minutes. During secret rotation, both secrets are valid
for 24 hours, and a header may carry several `v1=` values. A delivery that was not
stored (any non-2xx answer) can always be retried under the same delivery id; sign
each attempt with a fresh timestamp.

## Data classification

Datasets are classified `public`, `internal` (default), `confidential` or
`restricted`. **Restricted data never leaves the platform**: it is never sent to
an external AI provider (the offline analyser is used even when the
organization opted in), and alert messages - which are sent by e-mail, Slack,
Telegram or webhook - name the changed fields but carry no record keys or values.
The full details stay available in the API to users allowed to see them.

## Snapshot deletions

Website, REST API and upload sources with `snapshot_mode: "full"` mark records that
a complete, fully valid snapshot no longer contains as deleted (soft delete, with a
version entry). A snapshot that would delete more than the source's
`max_deletion_ratio` (0 to 1, default 0.5) of the live records deletes nothing; the
run succeeds and reports `deletions_withheld` in its `stats`. Set the ratio to `1.0`
on a source to accept any deletion.

## Internal API (not public)

`/internal/v1/automation/*` (n8n, service tokens) and `/internal/v1/sandbox/*` (sandbox,
per-run tickets) are served only by the internal app on the private network. See
[ARCHITECTURE.md](ARCHITECTURE.md) and [workflows/n8n](../workflows/n8n/README.md).
