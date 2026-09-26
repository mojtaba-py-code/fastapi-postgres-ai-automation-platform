# Threat model (STRIDE)

Scope: the NexusFlow AI platform as deployed by `docker-compose.yml`, covering the
public API, internal API, workers, sandbox, browser, n8n, PostgreSQL, Redis,
RabbitMQ and the edge proxy. Reviewed against the implementation in this repository.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Tenant business data (records, versions, changes, insights, reports) | Confidentiality and integrity; competitive intelligence is sensitive |
| Credentials: passwords, sessions, API keys, service tokens | Account and tenant takeover |
| Integration secrets (API credentials, Slack/Telegram/SMTP) | Pivot into customers' third-party systems |
| Platform key material: JWT signing key, KEKs, HMAC pepper | Forging identities, decrypting every secret |
| Audit trail | Accountability, forensics, compliance |
| Availability of collection and alerting | Missed alerts cost money |
| AI provider budget and reputation | Abuse drives cost; manipulated insights mislead decisions |

## 2. Threat actors

1. Anonymous internet attacker (credential stuffing, scanning, exploiting inputs).
2. Malicious or curious **tenant user** (IDOR, privilege escalation, cross-tenant access).
3. Holder of a **leaked API key or token**.
4. **Author of collected content**: a hostile website, API or uploaded file, which can
   attempt parser exploits, SSRF pivots and indirect prompt injection.
5. **Compromised partner** sending webhooks.
6. **Compromised internal component**: sandbox, n8n or a worker.
7. **Insider / operator** with host access.
8. **Supply chain**: a malicious or vulnerable dependency or base image.

## 3. Trust boundaries

```
Internet ─┬─> nginx ──> public API ──> PostgreSQL / Redis / RabbitMQ
          │                              ^
          ├─< sandbox <── ticket ──> internal API <── service token ── n8n
          ├─< browser (render only)
          └─< integrations worker (APIs, AI, notifications)
```

Every arrow that crosses a boundary authenticates (TLS/JWT/API key, HMAC ticket,
service token or HMAC webhook signature) and validates its input.

### 3.1 Attack surface

Everything that accepts input, as deployed by `docker-compose.yml`. nginx is the
only container with published ports; everything else sits on internal Docker
networks. Rates are the defaults (`RATE_LIMITS__RULES`, see
[CONFIGURATION.md](CONFIGURATION.md)); "fail closed" limits refuse requests when
Redis is unavailable.

**Inbound**

| # | Entry point | Reachable from | Authentication | Abuse controls | Input limits |
|---|---|---|---|---|---|
| E1 | `/api/v1/auth/*` - register, login, OAuth2 token, refresh, MFA (TOTP, passkeys: `/auth/webauthn/*`, `/auth/mfa/webauthn/*`), password reset, invitations | Internet (nginx, 443) | None - it establishes identity; single-use MFA challenges, hashed reset and invitation tokens | nginx 5 r/s per IP; per-IP and per-account limits (fail closed); exponential lockout; sign-in risk assessment | 1 MB body; strict request models (unknown fields rejected) |
| E2 | `/api/v1/*` resources | Internet | EdDSA access token or API key; RBAC and scopes; row-level security | nginx 20 r/s per IP; 600 reads and 120 writes per minute per principal; exports 20/h and AI analyses 30/h per person (all of a user's API keys share them); password changes 5 per 15 min per user, counted toward lockout | 1 MB body; keyset pagination (at most 200 per page) |
| E3 | `/api/v1/webhooks/{endpoint}` | Internet | HMAC-SHA256 over timestamp, delivery ID and body, per-endpoint secret; 300 s timestamp tolerance; delivery IDs are single-use | nginx 50 r/s per IP; 120/min per endpoint and 600/min per IP (fail closed) | 1 MB body; mapped to the dataset schema |
| E4 | `/api/v1/sources/{id}/uploads` (CSV, XLSX) | Internet | As E2 (`uploads:write`) | As E2 | 20 MB (25 MB at nginx), 100,000 rows, 200 columns; archive inspection (bombs, traversal, encryption, macros by name and by declaration, duplicate parts); malware scan (ClamAV); parsed only in the sandbox, with a bounded row walk |
| E5 | Dataset exports, report downloads | Internet | As E2; audited | 20 per hour per principal (fail closed) | Streamed |
| E6 | `/health/live`, `/health/ready`, `/.well-known/jwks.json` | Internet | None: no tenant data | As E2 at nginx | - |
| E7 | Internal automation API `/internal/v1/automation/*` | `automation` network only (the `api-internal` container); nginx answers 404 | Per-workflow service tokens: scoped, rotatable, and disabled individually (the per-workflow kill switch) | 1,200/min per token | Strict request models |
| E8 | Sandbox gateway `/internal/v1/sandbox/*` | `sandbox_net` network only | HMAC ticket bound to the tenant, run and attempt | 600/min | Result body bounded by the upload limit |
| E9 | n8n editor | `127.0.0.1:5678` on the host (SSH tunnel) | n8n user management | - | 16 MB |
| E10 | Grafana | `127.0.0.1:3000` on the host (SSH tunnel) | Grafana login | - | - |
| E11 | PostgreSQL, Redis, RabbitMQ, ClamAV | Internal networks, no published ports | Per-component credentials: least-privilege database roles, Redis ACL users, separate broker users for the platform and the sandbox | - | - |
| E12 | `/metrics` | Monitoring network (nginx answers 404) | None: aggregate counters only | - | - |
| E13 | Operator CLI (`nexusflow`) | Host shell (`docker compose exec`) | Host access; every command is audited on the platform chain | - | - |

**Outbound** - content the platform fetches, or sends out

| # | Surface | Runs in | Controls |
|---|---|---|---|
| O1 | Website and REST API collection | Sandbox worker (egress network, no inter-container traffic) | SSRF guard: DNS pinned per request, private and reserved ranges blocked, every redirect hop re-checked; robots.txt (RFC 9309) honoured; size and time limits; hostile content parsed only here |
| O2 | Browser rendering | Isolated browser service behind a pinning egress proxy | Renders only - no credentials, no platform network; token-authenticated; hardened container (read-only, no capabilities, no new privileges) |
| O3 | AI provider (Anthropic) | Integrations worker | Off by default; per-tenant opt-in; never for restricted data; redaction and spotlighting; read-only tools; strict output validation; circuit breaker |
| O4 | Notifications: e-mail, Slack, Telegram, signed webhooks | Integrations worker | SSRF-guarded; restricted data never leaves; sensitive values masked; per-channel rate limit |
| O5 | Events to n8n | Integrations worker, `automation` network | HS256 JWT (60 s) on every event |

## 4. STRIDE analysis

### 4.1 Public API and authentication

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **S** | Credential stuffing, password spraying | Argon2id; breached passwords refused at sign-up and change (72,985-entry corpus); exponential per-account lockout; fail-closed rate limits per IP and per account; generic login errors; sign-in risk assessment (new device, new /24 or /48 network, success after failures): the user is e-mailed, suspicious sign-ins are audited and counted, and `CredentialStuffingSuspected` / `SuspiciousSignIns` alert operators | Distributed low-rate attacks from many IPs; mitigate with a WAF or CAPTCHA upstream. No geolocation (impossible-travel) checks |
| **S** | Phishing or guessing the second factor | Passkeys: the signature covers the origin and the relying-party ID, user verification is required, allowed origins are an exact list, challenges are 256-bit, single-use and bound to the session or the MFA token; counters that do not move forward are refused, audited and e-mailed (possible clone). TOTP: replay refused. Wrong passwords and wrong second factors add up to one exponential lockout until a sign-in completes (review R13-6) | TOTP and recovery codes can still be phished, and `require_mfa` cannot yet demand passkeys; synced passkeys report no counter, so their clones go undetected; no attestation (any authenticator model is accepted); passkeys have not been tested with real browsers and authenticators yet |
| **T** | Planting a second factor or stripping MFA with a stolen session | Adding or removing a factor needs the password and, once the account has one, a session that passed it; the last factor cannot be removed (MFA goes off only with the password and a code, ending every session); every change is audited and e-mailed; the runtime role cannot change a stored passkey's key | Setting up a first factor does not end other sessions; removing a passkey does not end sessions it verified |
| **S** | Token forgery / algorithm confusion | EdDSA only, `kid` keyring, issuer/audience/`token_use`/expiry checks; tests cover HS256-with-public-key confusion | Theft of the private key (see 4.8) |
| **S** | Stolen refresh token | Rotation on every use; reuse revokes the session family and emails the user; absolute session lifetime | Window until the thief uses the token first |
| **S** | A leaked API key or stolen session used from outside the customer's network | Per-organization network allowlist (CIDR, IPv4/IPv6), enforced on every request for sessions and API keys and at sign-in and organization switch; fails closed when the client address is unknown; the address comes from `X-Forwarded-For` only when the peer is the trusted edge, which overwrites the header; refusals are counted (`NetworkAllowlistDenials`) and valid sign-ins from outside are audited in the tenant's trail | Opt-in per organization. An attacker inside an allowed network (or controlling an allowed egress address) is not stopped by it; a load balancer in front of the edge must pass the real client address (DEPLOYMENT.md, section 1). Inbound webhooks are authenticated by their per-endpoint signing secret, not by the allowlist (they come from the sending service's addresses) |
| **T** | Mass assignment (`org_id`, `role`, `status` in bodies) | Request models `extra="forbid"`; server-set fields are never bindable | — |
| **R** | User denies an action | Hash-chained audit entries with actor, IP, user agent and request ID | Actions done with a shared API key are attributable to the key, not a person |
| **I** | IDOR / cross-tenant reads | RLS forced on a non-bypass role; explicit `org_id` filters; `404` for foreign IDs; integration tests assert isolation | A new table that forgets RLS: migration review checklist plus a test pattern |
| **I** | Error messages leaking internals | Uniform error schema; internals only in logs; validation errors never echo input | — |
| **I** | Enumeration (accounts, webhook endpoints) | Sign-up and password reset answer alike for every address: a sign-up mails the address a link, or a notice if it already has an account; webhook rejections are indistinguishable and unknown endpoints cost the same HMAC work (decoy secret) | Microsecond-scale timing differences (one more row written for a new address; secret decryption), far below network jitter |
| **S/E** | CSRF, clickjacking | Credentials are bearer tokens sent in the `Authorization` header, never cookies, so a browser cannot attach them to a cross-site request; CORS allows explicit https origins only; `X-Frame-Options: DENY` and `frame-ancestors 'none'` | — |
| **T** | HTTP request smuggling / header spoofing | nginx is the only entry point and forwards to uvicorn (h11) on a private network; forwarded headers are honoured only from the configured trusted proxy range; the internal API runs with `--no-proxy-headers` | — |
| **D** | Request floods, large bodies, slowloris | nginx limits and timeouts; per-route body caps; GCRA rate limits in Redis; bounded pagination | Volumetric DDoS needs an upstream provider |
| **D** | Crafted inputs turning into server errors | Pagination cursors are type- and range-checked against the sort column (integer width, finite floats, no NUL or lone surrogates, UTC-normalised timestamps); any remaining SQLSTATE class 22 error maps to `422 invalid_value` without echoing SQL or parameters | — |
| **E** | Privilege escalation via roles or keys | Permission checks at the route and in the service; API-key scopes must be a subset of the role; members cannot raise their own role; owner-only actions | — |
| **E** | A key outliving its creator's access | An API key's permissions are the intersection of its own role and scopes with its creator's **current** membership, checked on every request; removing a member or deleting an account revokes their keys (audited) | — |
| **D** | Login floods starving the database | Password hashing (Argon2id) never runs while a row lock is held: read, verify outside the transaction, then apply the outcome under `FOR UPDATE` with re-checks | — |

### 4.2 Inbound webhooks

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **S** | Forged deliveries | HMAC-SHA256 over `timestamp.delivery_id.body` with a per-endpoint secret; constant-time compare; rotation with a grace period | A leaked secret until it is rotated |
| **T** | Replay | Timestamp tolerance (300 s); Redis nonce plus a unique `(endpoint, delivery_id)` row | — |
| **T/D** | Silent data loss through replay protection | The nonce is released when storing fails; a claimed but unstored delivery answers `409 delivery_in_progress`, so `duplicate` is only ever answered for stored deliveries | — |
| **I** | Probing which tenants or endpoints exist | Identical `401 invalid_signature` for unknown endpoints and bad signatures, after the same HMAC work on a decoy secret; organization state checked only after the signature | — |
| **D** | Flooding one endpoint | Per-IP fail-closed limit before verification; the per-endpoint quota is charged only after the signature verifies, so forged traffic cannot starve a sender; no row locks before authentication; body size cap; bounded JSON depth | A distributed flood of forged requests still costs one lookup and one HMAC each, bounded by nginx and the per-IP limit |

### 4.3 Collection, SSRF and hostile content

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **S/E** | SSRF to metadata services or internal hosts | URL policy (schemes, ports, blocked domains, tenant allowlist); connect-time IP validation of **all** DNS answers, including IPv6-embedded IPv4; manual, re-validated redirects; no proxy env; egress only from the pools that need it | — for the platform clients. Chromium connects only through an in-process pinning proxy that resolves once, requires every answer to be public and connects to the checked address; QUIC and non-proxied WebRTC are disabled. The egress firewall stays as defence in depth |
| **T/E** | Parser exploits (lxml, openpyxl) via crafted HTML/XLSX | Parsing only in the sandbox: no DB, no storage, no secrets, read-only FS, no capabilities, resource limits; defusedxml; XLSX inspection (entries, ratio, traversal, macros, encryption) | A sandbox RCE can still fetch arbitrary internet content and read the tickets of runs it receives while compromised |
| **T** | A compromised sandbox forging results for other tenants | Tickets bound to (org, run, attempt) via HMAC with a pepper the sandbox never sees; the ticket is checked before the result body is read; results bounded and schema-validated again; an upload's input can be downloaded once per attempt; the sandbox broker account cannot declare anything (`configure ^$`), reads only its own queue and publishes only to its own exchange; one process per job (`max_tasks_per_child=1`) | With the pool's broker credentials a compromised sandbox container can drain the sandbox queue and falsify the results of every run queued meanwhile (collected data only: no database, storage, platform Redis or other queues) |
| **T** | A broken or hostile source wiping a dataset | Deletions only from complete, valid, untruncated full snapshots; a snapshot that would delete more than the source's `max_deletion_ratio` (default 50 %) of the live records deletes nothing and reports `deletions_withheld` on the run | A source that shrinks slowly, below the threshold per run, still deletes over several runs; deletions are soft, versioned and undone when items reappear |
| **I** | Credential leakage in outbound requests or logs | Credentials only in the integrations worker, injected per request; sensitive headers redacted from logs; `trust_env=False` | — |
| **D** | Huge or slow responses, decompression bombs, robots abuse | Timeouts, byte caps, a bounded decompressor, per-host throttling, item caps | Many slow targets can still tie up sandbox concurrency (bounded by pool size) |
| **T/E** | Ignoring a site's robots.txt, or being steered by it | RFC 9309 matching (longest rule wins, `*` and `$`, percent-encoding normalised) with a linear-time matcher; robots.txt is checked for every redirect hop before it is followed and for the browser's final URL; it is fetched under the source's URL policy, so a redirect cannot leave the allowlist (refused, never cached across tenants); oversized files are truncated at 512 KiB, not rejected; unreachable robots.txt means "retry later" | — |
| **T** | A redirect answer counted as a delivered notification | Notification requests never follow redirects, and any 3xx answer is a failed delivery | — |
| **D** | A compromised sandbox exhausting shared infrastructure | Its own disposable Redis (`redis-sandbox`: no persistence, LRU, 48 MB) instead of the platform Redis; the sandbox queue is length- and byte-bounded with `reject-publish`; gateway rate limit, per-run body caps, and large results buffered and parsed one at a time in `api-internal`, so even valid tickets cannot exhaust its memory | Per-user connection/channel limits on RabbitMQ are not set by default (see DEPLOYMENT.md) |

### 4.4 Uploads

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **T** | Malware or disguised files | Content sniffing (not extension/MIME); XLSX structure checks; optional ClamAV; files never served back | Without ClamAV, malware is only stored, never executed |
| **I** | Path traversal via filenames | Server-generated storage keys, validated key syntax, `is_relative_to` check; original names only displayed | — |
| **T** | CSV/formula injection into downstream spreadsheets | Exports prefix formula starters; XLSX writes string cells; PDF text is XML-escaped | — |
| **D** | Zip bombs, huge files | Streaming with a byte cap into a dedicated temp volume; ratio and entry limits; row and column caps in the sandbox | — |
| **D** | A file stuck behind an upload that never finishes | A run that ends without storing its file (failure, cancellation, lost worker) marks the upload failed; deduplication covers live uploads only (partial unique index), so the file can be uploaded again | — |

### 4.5 AI analysis

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **T** | Indirect prompt injection in collected data | Spotlighting inside a random boundary; system rules take precedence; read-only tool gateway (allowlist, schema, permission, budget); strict output schema; references must be real change IDs; links restricted to hosts present in the data | The model can still be steered within the space of valid outputs; insights are advisory and labelled as AI-generated |
| **I** | Sending personal or sensitive data to a third party | Offline by default; external processing only after tenant opt-in; sensitive fields dropped; PII and credential redaction; size-bounded context; datasets classified `restricted` are never sent to a provider (offline analysis) and their alert messages carry no record keys or values; a key field cannot be marked sensitive (keys appear in alerts, reports and prompts) | Redaction of free text is pattern-based and conservative, not perfect |
| **D/$** | Cost abuse | Rate limit `api.ai` (30/hour per principal), bounded tool rounds and output tokens, circuit breaker | — |

### 4.6 Automation (n8n and the internal API)

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **S** | Forged events into n8n | HS256 JWT (60 s) on every event webhook; n8n reachable only on the internal network | Replays within 60 s; receivers are idempotent |
| **E** | Compromised n8n abusing the platform | One service token per workflow with minimal scopes; endpoints return IDs and counters only (no tenant content); per-token rate limit; global kill switch; tenant freeze honoured | n8n can trigger work (detection, analysis) for any tenant; bounded and idempotent |
| **E** | Dangerous n8n nodes (code, shell, files) | `NODES_EXCLUDE`, `N8N_BLOCK_ENV_ACCESS_IN_NODE`, community packages disabled (`N8N_COMMUNITY_PACKAGES_ENABLED=false`) and no internet egress; CI lint rejects such nodes, external URLs, inline credentials and redirects; n8n runs only when enabled (a Compose profile) | An admin with n8n editor access can change workflows; protect the editor (SSH tunnel only) and claim its owner account the moment it starts. n8n's image carries vulnerabilities in its own dependencies that only n8n can fix: they are reported weekly, not failed on |
| **R** | Untraceable automation actions | Service principals are audited, and so are the automation steps (scheduled dispatch, detection, analysis, alert evaluation, run completion); dead letters record failures | — |
| **T/E** | Abusing workflow 5's retries | The platform counts failures per retry chain itself (Redis, idempotent per execution), so a forged or replayed failure report cannot reset the count; at most 3 retries with backoff, and none while the tenant is frozen. The only call n8n may make outside the internal API is its own loopback `POST /api/v1/executions/{id}/retry`: the lint pins the exact URL and requires the dedicated `NexusFlow n8n API key` credential, which no other node may use | The n8n API key grants n8n-level access if stolen from n8n's credential store (it is encrypted with `N8N_ENCRYPTION_KEY`) |
| **D** | Paging loops and alert storms | The failure-handling tasks (event routing, event forwarding, operator alerts) never raise `job.failed` themselves, and workflow 5 ignores them; identical operator alerts page once per 15 minutes (fail-open: sent anyway if Redis is down) | — |

### 4.7 Data stores and messaging

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **I** | Database dump, backup or volume exposure | Values of `sensitive` fields (records, versions, change diffs), staged raw payloads, uploads and reports are encrypted by the application (AES-256-GCM, bound to tenant/dataset/record/field or storage key); secrets sealed the same way; record content hashes keyed; tokens stored as keyed hashes; passwords as Argon2id | Non-sensitive fields are plaintext so they can be queried (disk encryption recommended); an attacker holding the KEK keyring as well as the data can decrypt |
| **T** | Moving or altering encrypted values in the database | Every value and file chunk is authenticated and bound to its row, field or storage key: a moved or altered ciphertext fails to open, and reads fail closed | Deleting data is not prevented by encryption (backups, audit) |
| **T** | Tampering with the audit trail | Only a `SECURITY DEFINER` function can append; triggers block UPDATE/DELETE/TRUNCATE; hash chain verification of every tenant chain and of the platform chain - daily and automatic, alerted and paged (events without a tenant, readable only through two narrow `SECURITY DEFINER` functions); hourly external anchors of every chain | A superuser can rewrite the chain; anchors make this detectable, not impossible |
| **I** | Reading across tenants from a compromised application process | Row-level security is `FORCE`d and every query also filters by `org_id` (a static test fails on a data query without it), which stops application bugs. Deliberate exceptions: `audit_logs` (RLS on, not forced; the owner-only append function) and `outbox_messages` (identifiers only, drained across tenants by the relay) | The tenant context is a session setting (`app.current_org_id`): code running *inside* an application process (RCE) can set it to another tenant. RLS is a defence against bugs, not against a compromised process; the sandbox, which handles hostile content, has no database access at all |
| **I** | Bulk copying a dataset without an export | Exports are audited in the tenant's trail and budgeted per person (`api.export`); record pages are rate-limited, and every request is logged with its principal and organization | **Accepted** (review D-n2): a member who may read records can page through a whole dataset; reading is what the permission grants |
| **S/E/I** | Rogue client on Redis or RabbitMQ, or sniffing internal traffic | Per-user ACLs (default user disabled); the sandbox has no account on the platform Redis (it gets `redis-sandbox`) and its broker user is confined to its queue and exchange; internal networks only; TLS on every internal hop (PostgreSQL `hostssl` only with `verify-full`, `rediss://`, `amqps://`), verified against the stack's private CA | The internal certificates must be renewed before they expire (`internal_pki.py --check`, monthly) |
| **D** | Poison messages | JSON-only; strict message schemas; delivery limit; dead-letter exchange; application dead letters | — |
| **D** | Work stuck after a worker crash, or hung workers that look healthy | The reaper re-queues abandoned runs, notification deliveries and analyses with backoff and fails them after a bounded number of attempts (dead letter plus `job.failed`); a reaped analysis's late result is discarded (fencing by claim time); workers and beat report unhealthy when their event-loop heartbeat goes stale | — |

### 4.8 Keys, secrets and operations

| | Threat | Mitigations | Residual risk |
|---|---|---|---|
| **I** | Secret leakage in repositories, images or env | Secrets as files (`*_FILE`), never env values or images; `.dockerignore`; Gitleaks in CI and pre-commit; `SecretStr` everywhere | Host compromise exposes `./secrets` |
| **S** | Stolen JWT signing key | Key IDs with rotation procedure; short access TTL | Forged tokens until rotation |
| **I** | Stolen KEK or pepper | KEK keyring with background re-wrap that reports what is left under old keys; optionally kept wrapped by HashiCorp Vault's transit engine, so the secrets file alone decrypts nothing and access to the keys is granted, audited and revoked in Vault; the pepper protects token hashes | A running process holds the keys in memory (Vault or not); pepper rotation invalidates all API keys and sessions (documented) |
| **E** | Container escape | Non-root, read-only, no capabilities, no-new-privileges, seccomp default, PID/memory limits | Kernel vulnerabilities |
| **T** | Supply-chain compromise | `uv.lock` with hashes; pip-audit, Trivy, CodeQL, Semgrep; SBOM; Dependabot (images pinned in forms it reads); the platform's images rebuilt and scanned weekly; every third-party image scanned weekly, findings the newest upstream release still carries accepted only when unreachable here, with an expiry date | Zero-days in dependencies; upstream images that lag on fixes |
| **I** | Personal data kept longer than needed | Daily identity retention (sessions 90 days after expiry, expired tokens after a week); per-dataset retention; a person's copy of their data and erasure on request; audit entries purged only by the migrator, never by the application (PRIVACY.md) | Old invitations stay while their organization exists; backups keep erased data until they expire |

## 5. Assumptions

* The host is patched, firewalled, and only the edge proxy's ports are reachable.
* Operators protect `./secrets` and the n8n and Grafana editors (SSH tunnel).
* The egress firewall in DEPLOYMENT.md is applied to the `egress` network.
* TLS certificates are valid and private keys are protected.

## 6. Review triggers

Revisit this model when adding a source kind, a notification channel, an AI tool,
a public endpoint, a new network path, or when changing authentication.
