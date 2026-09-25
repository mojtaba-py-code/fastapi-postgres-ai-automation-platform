# Security policy

## Reporting a vulnerability

Please **do not** open public issues for security problems. Report them privately
through GitHub's *Report a vulnerability* (security advisories) on this repository.
Include affected versions, reproduction steps and impact. You will get an
acknowledgement within 3 business days. We aim to ship a fix or mitigation for
critical issues within 14 days, and we credit reporters who want to be named.

Good-faith research that respects tenant data and availability is welcome. Do not
access data you do not own, do not run denial-of-service tests against shared
deployments, and stop and report as soon as you reach a vulnerability.

## Supported versions

Only the latest release on `main` receives security fixes.

## Security model in one page

Details are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Identity and access**
* Passwords are hashed with Argon2id (64 MiB, t=3, p=4, bounded by a concurrency
  semaphore). The policy is length-based, in line with NIST SP 800-63B: it rejects
  passwords found in breached-password corpora (72,985 of 12 characters or more,
  including the UK NCSC's 100,000 most used) and passwords derived from the
  account's own identifiers.
* Users see their signed-in sessions (device, address, times) and can end any one
  of them, which invalidates its tokens at once. A sign-in from an unfamiliar device
  or network is e-mailed to the user; a suspicious one is also audited and alerted.
* Access tokens are 10-minute EdDSA (Ed25519) JWTs with issuer, audience, `token_use`
  and key-ID checks, plus a JWKS for rotation. Algorithm confusion is impossible.
* Refresh tokens are opaque, HMAC-peppered at rest and rotated on every use. Reuse of
  a rotated token revokes the whole session family and notifies the user.
* TOTP MFA rejects code replay and uses single-use recovery codes. Organizations can
  require MFA.
* Accounts lock out exponentially after repeated failures. Authentication endpoints
  also have fail-closed rate limits per IP and per account.
* API keys (`nxf_…`) are scoped to a subset of a role's permissions and expire; they
  are shown once and stored only as a keyed hash. n8n service tokens (`nxs_…`) are
  per workflow, scope-limited and rejected by the tenant API.

**Tenant isolation and authorization**
* PostgreSQL row-level security is `FORCE`d. The runtime role cannot bypass it, and
  the tenant scope is set per transaction.
* Every repository query also filters by `org_id` explicitly (defence in depth).
  Identifiers from other tenants return `404`, never `403`.
* Role-based permissions are checked at the route and again in the domain service.
  Mass assignment is prevented by strict request models (`extra="forbid"`).

**Input, output and outbound traffic**
* SSRF protection runs on every outbound request (collection, notifications,
  webhooks, browser):
  * scheme, port and domain policy, with a tenant domain allowlist;
  * an IP check at connect time against every DNS answer, including IPv6-embedded
    IPv4 addresses;
  * manual, re-validated redirects;
  * size, time and decompression limits;
  * proxy environment variables are ignored;
  * the headless browser can only connect through a pinning egress proxy that
    resolves each host once, requires every answer to be public and connects to
    exactly that address (no DNS rebinding); QUIC and non-proxied WebRTC are off.
* Web pages and uploads are parsed only in the sandbox pool. The sandbox has no
  database, storage or secrets; per-run HMAC tickets bound to (org, run, attempt) are
  its only credential. The gateway checks the ticket before it reads a result, an
  upload's input can be downloaded once per attempt, the sandbox's broker user
  cannot declare queues, and it gets its own disposable Redis.
* Uploads are streamed with a size cap. Types are sniffed from content, XLSX archives
  are inspected (entry count, sizes, traversal, macros), files are optionally scanned
  with ClamAV, and deduplicated by SHA-256 (live uploads only: a file whose run
  failed can be uploaded again).
* Exports and reports neutralize spreadsheet formulas and XML-escape PDF text.
  Downloads are always attachments with `nosniff`.
* Webhooks carry HMAC-SHA256 over `timestamp.delivery_id.body`, checked against a
  timestamp window. Replay protection uses a Redis nonce plus a unique database row;
  a delivery that failed to store stays retryable, and `duplicate` is only answered
  for stored deliveries. Secrets can be rotated with a grace period. All rejections
  look identical and cost the same HMAC work, so endpoints cannot be enumerated.
  The per-endpoint quota is only charged after the signature verifies.
* Client-controlled values never become server errors: pagination cursors are
  range-checked against the column type, and database data exceptions map to 422.

**AI**
* Analysis is offline (heuristic) unless an organization opts in to external
  processing. Datasets classified `restricted` are always analysed offline, and
  alerts about them name the changed fields but carry no record keys or values.
* Fields marked sensitive are removed and free text is redacted (credentials, PII)
  before any prompt is built. Untrusted data is spotlighted inside a random boundary.
* The model can only call two read-only, tenant-scoped tools through a gateway that
  enforces an allowlist, argument schemas, permissions and a call budget.
* Output must match a strict schema, cite real change IDs and contain only links to
  hosts present in the data; anything else is rejected.

**Integrity, audit and operations**
* Secrets are sealed with AES-256-GCM envelope encryption, bound to their context
  (AAD) and protected by rotatable KEKs, then re-encrypted in the background after
  rotation.
* Tenant data at rest: the values of fields marked `sensitive` (in records, their
  history and change diffs), staged raw payloads, uploaded files and reports are
  encrypted by the application under the same KEKs, each bound to its tenant and
  row or file; a moved or altered ciphertext fails closed. Record content hashes
  are keyed.
* The audit log is append-only and hash-chained per tenant, plus a platform chain for
  events without a tenant (failed sign-ins for unknown accounts, operator commands).
  It is writable only through a `SECURITY DEFINER` function, verifiable through the API
  and CLI, and every chain head is anchored hourly to external logs. A daily job
  recomputes every chain: a break is alerted (`AuditChainBroken`) and pages the
  operators.
* Kill switches: per n8n workflow (service account), per tenant (automation freeze)
  and platform-wide (Redis flag with no TTL, which fails safe when Redis is
  unreachable). They apply in both orchestration modes (n8n and internal).
* A full snapshot that would delete more than half of a dataset (configurable per
  source) deletes nothing and is flagged on the run.
* Structured JSON logs redact secrets. Errors returned to clients never contain
  internals, and tracebacks never include local variables.
* Containers run non-root with read-only filesystems, no capabilities and
  no-new-privileges. Networks are segmented and only the edge proxy is exposed.

## Review status

The code has been reviewed with AI assistance (adversarial code review,
due-diligence and traceability audits, test-driven reviews); every finding and
its fix is recorded in [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). It has
**not** been penetration-tested by an independent third party.
