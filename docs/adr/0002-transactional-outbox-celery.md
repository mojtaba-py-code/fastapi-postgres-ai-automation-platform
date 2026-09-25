# 0002. Transactional outbox + Celery on RabbitMQ quorum queues

* Status: accepted
* Date: 2026-09-24

## Context
State changes must reliably trigger background work: a queued run must be
collected and a triggered alert must be delivered. Publishing to a broker inside
a request is not atomic with the database commit; either side can fail.

## Decision
* Services append jobs and events to `outbox_messages` **in the same transaction** as
  the state change.
* A post-commit publisher sends them immediately. A relay (`FOR UPDATE SKIP LOCKED`
  with leases) sends whatever is left, so the delivery guarantee is at-least-once.
* Celery on RabbitMQ:
  * JSON only;
  * `acks_late` and prefetch 1;
  * quorum queues with a delivery limit and a DLX;
  * no result backend (results live in PostgreSQL).
* Three pools with different privileges: `pipeline` (no egress), `integrations`
  (egress, credentials) and `sandbox` (egress, no secrets, its own exchange).
* Handlers are idempotent. Exhausted jobs go to an application dead-letter store that
  tenant admins can inspect and retry.

## Consequences
* No lost or phantom jobs. Duplicates are expected, so everything is idempotent.
* The outbox table needs cleanup (a daily beat job).

## Alternatives considered
Publishing directly from requests (not atomic). Redis as a broker: weaker durability,
and it shares a failure domain with rate limiting. Kafka: operationally heavier than
the workload needs.
