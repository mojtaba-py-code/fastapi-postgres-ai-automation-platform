# Architecture decision records

| # | Decision | Status |
|---|---|---|
| [0001](0001-postgresql-row-level-security.md) | PostgreSQL with forced row-level security for tenant isolation | Accepted |
| [0002](0002-transactional-outbox-celery.md) | Transactional outbox + Celery on RabbitMQ quorum queues | Accepted |
| [0003](0003-n8n-orchestration-with-internal-fallback.md) | n8n orchestrates through a narrow internal API; internal fallback mode | Accepted |
| [0004](0004-ssrf-guard-at-connect-time.md) | SSRF protection at connect time (httpx2 network backend) | Accepted |
| [0005](0005-sandbox-trust-boundary.md) | A secret-less sandbox pool with per-run HMAC tickets | Accepted |
| [0006](0006-ai-safety.md) | AI: offline by default, tenant consent, tool gateway, strict output validation | Accepted |
| [0007](0007-hash-chained-audit-log.md) | Append-only, hash-chained audit log written by a SECURITY DEFINER function | Accepted |
| [0008](0008-envelope-encryption.md) | Envelope encryption with context binding and KEK rotation | Accepted |
| [0009](0009-token-design.md) | EdDSA access tokens, opaque rotating refresh tokens, peppered hashes | Accepted |
| [0010](0010-modular-monolith-and-service-extraction.md) | A modular monolith with a planned service-extraction path | Accepted |

Use [template.md](template.md) for new records.
