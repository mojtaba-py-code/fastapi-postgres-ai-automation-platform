# 0007. Append-only, hash-chained audit log written by a SECURITY DEFINER function

* Status: accepted
* Date: 2026-09-24

## Context
Audit records must survive a compromised application and must reveal tampering.

## Decision
* `audit_logs` rows form a per-tenant chain, where
  `hash_n = SHA-256(hash_{n-1} || canonical_n)` and the canonical JSON is stored
  with the row.
* The application role cannot insert, update or delete audit rows. Appends go through
  `nf_append_audit`, a `SECURITY DEFINER` function that checks that the event's tenant
  matches the transaction's tenant. Triggers reject `UPDATE`, `DELETE` and `TRUNCATE`.
* Tenants can verify their chain (`GET /audit/verify`), as can operators
  (`nexusflow audit verify`).
* Chain heads are logged hourly (`audit_anchor`) for anchoring in external,
  append-only log storage.
* Retention: `nf_purge_audit_logs(before)` is not executable by the application role.
  It removes entries older than a cutoff, and each chain stays verifiable from its
  first remaining entry. Nothing schedules it automatically; operators run it
  deliberately according to their retention policy.

## Consequences
Tampering by the application is impossible. Tampering by a database superuser is
detectable by comparing against the anchors.

## Alternatives considered
External write-once storage only, which does not support tenant queries. Signing
each entry, which requires key management in the database path.
