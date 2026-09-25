# 0001. PostgreSQL with forced row-level security for tenant isolation

* Status: accepted
* Date: 2026-09-24

## Context
Every table holds data of many tenants. A single missing `WHERE org_id = …` in
application code would leak data across tenants, and code review alone does not
reliably catch that class of bug.

## Decision
* PostgreSQL 17, with every tenant table having `org_id`, RLS **enabled and forced**,
  and a policy `org_id = nf_current_org()`.
* The tenant scope is a transaction-local setting applied in an SQLAlchemy
  `after_begin` hook, so every transaction carries it, including implicit ones.
* Two roles:
  * a migrator (schema owner, `BYPASSRLS`), used only for migrations;
  * the runtime role (`NOBYPASSRLS`, minimal grants, column-level `UPDATE` where it
    matters).
* Cross-tenant jobs get identifiers only from `SECURITY DEFINER` functions.
* Repositories still filter by `org_id` explicitly.

## Consequences
* Isolation holds even when application code is wrong; integration tests connect as
  the runtime role to prove it.
* Every new table needs RLS in its migration; a checklist and the migration-drift
  test help.
* A small overhead per transaction (one `set_config`).

## Alternatives considered
Schema-per-tenant or database-per-tenant gives stronger physical separation, but
migrations and connection counts scale per tenant. That could be added later for
premium tenants. Application-only filtering was rejected as too fragile.
