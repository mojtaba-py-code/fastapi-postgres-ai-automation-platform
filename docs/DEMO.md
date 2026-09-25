# Demo guide

A ten-minute, scripted walkthrough of NexusFlow AI on one machine, for a
presentation or an evaluation. Everything runs locally behind the real TLS edge;
alert e-mails land in a local mail catcher.

## 1. Prerequisites

* Docker Engine with Compose v2, `make`, and [uv](https://docs.astral.sh/uv/)
  (the walkthrough script runs on the host).
* Free ports: 80 and 443 (the edge), 8025 (Mailpit), 3000 and 5678 on 127.0.0.1
  (Grafana, n8n).
* At least 2 CPU cores and about 6 GB of free memory. The first start builds two
  images and takes a few minutes; later starts take about a minute.

## 2. One-time setup

```bash
make install
```

```bash
make secrets dev-certs
```

```bash
cp .env.example .env
```

In `.env`, set `NEXUSFLOW_DOMAIN=localhost`. `make dev-certs` created a
development CA and a certificate for `localhost` in `deploy/certs/`
(never use them in production).

## 3. Start the stack

```bash
make demo-up
```

This is `docker-compose.yml` plus `docker-compose.demo.yml` (Mailpit, and
Alertmanager routed to it). Wait until every service is healthy:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml ps
```

```bash
curl --cacert deploy/certs/dev-ca.pem https://localhost/health/ready
```

## 4. Run the walkthrough

```bash
make demo
```

The script (`scripts/demo.py`) uses the public API only, exactly as a customer
integration would, and narrates each step. Sample output:

```text
[ 1] Platform health
     ready: {'database': 'ok', 'redis': 'ok'}

[ 2] Sign up an organization owner
     owner+4d14e41e@nexusflow.example.com: the answer is the same for every address; a link was mailed
     the owner opened the link and chose a password (never printed or stored)
     owner+4d14e41e@nexusflow.example.com owns organization 'Acme Retail Intelligence'

[ 3] Model the competitor catalogue
     typed schema: sku (key), title, price (decimal), in_stock, url
     price thresholds: medium 5 %, high 10 %, critical 25 %
     signed webhook endpoint created (the secret is shown once, kept in memory)

[ 4] Route alerts to the pricing team
     rule 'Price up 10 % or more' (critical) -> e-mail
     rule 'Availability changed' (warning) -> e-mail

[ 5] Partner pushes the first catalogue snapshot
     6 products accepted; the same delivery again -> duplicate
     run succeeded: received 6, valid 6, invalid 0

[ 6] Partner pushes the second snapshot (a day later)
     7 products accepted; the same delivery again -> duplicate
     run succeeded: received 7, valid 7, invalid 0

[ 7] Change detection (automatic)
     NX-102  updated  critical price: 499 -> 649 (+30.1 %)
     NX-100  updated  high     price: 49.9 -> 55.9 (+12.0 %)
     NX-106  created  medium   new listing: Orbit USB-C Dock, 119 EUR
     NX-104  updated  medium   in_stock: True -> False
     NX-101  updated  medium   price: 219 -> 199 (-9.1 %)
     NX-103: a campaign-tagged URL is noise, removed by the Clean stage - no change

[ 8] Alerting (automatic)
     [CRITICAL] Price up 10 % or more: updated NX-102
     [WARNING] Availability changed: updated NX-104
     [CRITICAL] Price up 10 % or more: updated NX-100
     3 alert e-mail(s) in Mailpit: http://127.0.0.1:8025

[ 9] Analyse the changes
     completed by offline - risk critical
     11 changes detected in 'Competitor catalogue': 4 updated, 7 created, 0 removed. Highest significance: critical.
       - Review 2 increases in tracked values; the largest is price on NX-102 (+30.1%).
       - Review the decrease in price on NX-101 (-9.1%).
       - Assess 7 newly listed records.

[10] Reports
     last 30 days: 11 changes (7 new, 4 updated, 0 removed); All detected changes fall in the second half of the period.
     demo-output/competitor-brief.pdf (6,012 bytes, SHA-256 verified)
     demo-output/competitor-brief.xlsx (11,821 bytes, SHA-256 verified)

[11] Audit trail
     14 entries, e.g. alert_rule.created, auth.registered, channel.created, dataset.created, ...
     hash chain: intact (14 entries recomputed)
```

The same scenario runs in the test suite on every change: over real HTTP against
the API in the integration tests, and against the full Compose stack in CI's
end-to-end job.

## 5. What to show, and what to say

| Step | Show | Point to make |
|---|---|---|
| 3 | the schema in the script | Data is typed and validated; fields not in the schema are never stored |
| 5-6 | "same delivery again -> duplicate" | Webhooks are signed (HMAC over timestamp, delivery id and body) and replay-proof; a retry never duplicates data |
| 7 | NX-103 | The pipeline's Clean stage strips campaign parameters, so marketing noise is not reported as a change |
| 8 | Mailpit, http://127.0.0.1:8025 | Alerting is automatic; e-mail goes over STARTTLS with certificate validation, even in the demo |
| 9 | the insight | Offline analysis by default: no data leaves the platform until a tenant opts in to external AI, and restricted datasets never do |
| 10 | `demo-output/competitor-brief.pdf` | Executive summary, trend chart, unusual days, anomalies, alerts, insights and sources; downloads carry an integrity digest |
| 11 | the chain check | The audit log is append-only and hash-chained; chain heads are anchored hourly |

Optional extras:

* **Grafana**: http://127.0.0.1:3000 (user `admin`, password in
  `secrets/grafana_admin_password`), dashboard *NexusFlow AI - Overview*.
* **Emergency stop** (incident response):

  ```bash
  docker compose run --rm api-internal nexusflow kill-switch engage --reason "demo"
  ```

  ```bash
  docker compose run --rm api-internal nexusflow kill-switch release --reason "demo over"
  ```

* **Audit verification of every chain**:

  ```bash
  docker compose run --rm api-internal nexusflow audit verify
  ```

* **Security at the edge**: `curl -sI --cacert deploy/certs/dev-ca.pem https://localhost/api/v1/projects`
  shows the security headers and a `401`; `/metrics`, `/docs` and `/internal/*`
  answer `404` from outside.
* **Change analytics** (step 10 prints its headline): `GET /api/v1/analytics/changes`
  returns, for a project or dataset, totals per type and significance, every day
  of the period (30 days by default), unusual days and a trend note - counted by
  the database, however many changes there are.
* **One request, every job**: an API response's `X-Request-ID` appears as
  `request_id` in the log lines of every worker job the request caused
  (`docker compose logs worker-pipeline | grep <id>`).
* **Network allowlist**: with the owner's token, `PATCH /api/v1/organizations/current`
  with `{"settings": {"allowed_ip_ranges": ["198.51.100.0/24"]}}` is refused with
  `422 would_lock_you_out` - a list must include the caller's own address. Once a
  list is set, sessions and API keys from any other network get `403 ip_not_allowed`,
  and a valid sign-in from outside shows in the audit trail (`auth.network_denied`).
  An operator can lift a list that locked an organization out:

  ```bash
  docker compose run --rm api-internal nexusflow org clear-network-allowlist --org <id> --reason "<ticket>"
  ```

* **Tested as deployed**: every CI run's `zap-report` artifact is the OWASP ZAP scan
  of every API operation against the running stack (no warnings); the security
  posture against OWASP ASVS 5.0, with evidence and gaps, is in
  [ASVS.md](ASVS.md).

## 6. Reset

```bash
make demo-down
```

To start from an empty database as well, remove the volumes:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml down -v
```

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `the platform is not ready` | Still starting: check `docker compose ... ps` and the logs of the unhealthy service |
| Certificate errors | `.env` has another domain than `localhost`, or the certificates predate it: run `make dev-certs` again after deleting the three files in `deploy/certs/` |
| `sign-up failed: HTTP 429` | The demo overlay allows 200 sign-ups an hour per address (production: 10), and the count survives restarts (Redis persists). Wait, or reset the demo completely with `down -v` (section 6) |
| `https://127.0.0.1` answers `400` | Use `https://localhost`: the API accepts only its configured host names |
| No e-mails in Mailpit | The demo overlay was not used: start with `make demo-up`, not `make up` |
| Port already in use | Another web server or Mailpit is running; stop it or change the published ports |

The demo stack is for evaluation only. Production deployment is described in
[DEPLOYMENT.md](DEPLOYMENT.md).
