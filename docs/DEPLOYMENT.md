# Deployment

This guide deploys NexusFlow AI on a single Linux host with Docker Compose, which is
the reference topology in `docker-compose.yml`. The same images run on Kubernetes;
map every compose control (networks, read-only, capabilities, secrets, limits) to
its Kubernetes equivalent (NetworkPolicies, securityContext, Secrets, requests and
limits).

## 1. Host prerequisites

* A recent Linux kernel, Docker Engine ≥ 25 with Compose v2, and automatic security
  updates.
* A host firewall that allows inbound 22 (SSH, preferably from a VPN or bastion) and
  443/80 only.
* Full-disk encryption or an encrypted volume for Docker data (tenant data is stored
  in plaintext in PostgreSQL).
* NTP time sync: token expiry, webhook timestamps and TOTP all depend on the clock.
* At least 2 vCPUs and 8 GB of memory (16 GB with ClamAV). The API and the browser
  are limited to 2 CPUs each, and Docker refuses to create a container whose CPU
  limit exceeds the host's.
* The repository checked out with the default umask (022): containers read the
  bind-mounted configuration as unprivileged users. On SELinux-enforcing hosts,
  add `:z` to the bind mounts (or label the directory `container_file_t`).
* The `edge` network uses `172.28.1.0/24`, the only range the API accepts
  forwarded headers from. If that range is taken on the host, set another one in
  `NEXUSFLOW_EDGE_SUBNET` (`.env`).

### Egress firewall (required)

The `egress` network is the only one with internet access. It is shared by the
integrations worker, the sandbox, the browser and ClamAV (signature updates), with
inter-container traffic disabled (`enable_icc: false`), so they cannot reach each
other over it. The application already pins every outbound connection to a
validated public address (the browser through its pinning egress proxy). Also block
private ranges at the network layer, as defence in depth against a compromised
container that no longer runs the application's guards:

```bash
docker network inspect nexusflow_egress --format '{{(index .IPAM.Config 0).Subnet}}'
```

```bash
EGRESS=172.18.0.0/16  # the subnet printed above
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8; do
  sudo iptables -I DOCKER-USER -s "$EGRESS" -d "$net" -j DROP
done
```

Persist the rules (for example with `iptables-persistent`) and re-apply them if the
network is recreated. For stricter setups, send `egress` through an allowlisting
forward proxy.

### Sandbox isolation (what Compose already does)

* The sandbox pool has no database, storage mount or platform secrets. It talks to
  the platform only through the internal gateway with per-run tickets.
* It uses its own Redis (`redis-sandbox`: no persistence, LRU eviction, 48 MB) and
  has no account on the platform Redis that holds rate limits, replay nonces and the
  kill switch.
* Its RabbitMQ user cannot declare anything, reads only the `sandbox` queue and
  publishes only to the `nexusflow.sandbox` exchange. The queue is bounded
  (10,000 messages, 64 MiB) with `reject-publish`.
* Optionally cap its connections and channels as well:

```bash
docker compose exec rabbitmq rabbitmqctl set_user_limits -p nexusflow sandbox '{"max-connections": 16, "max-channels": 64}'
```

## 2. Configuration and secrets

```bash
make secrets    # python scripts/generate_secrets.py
```

This writes `./secrets` (directory mode 0700) containing database, Redis and
RabbitMQ credentials with their hashed ACLs, the Ed25519 JWT key, the KEK keyring,
the HMAC pepper, the n8n secrets and the browser token. Compose mounts them as
`/run/secrets/*`, and the application reads them through `NEXUSFLOW_*_FILE`
variables. **Back up `./secrets` offline**: losing the KEKs makes stored integration
secrets unrecoverable.

Three optional secrets are created **empty** (an empty secret file means "not
configured") and are never overwritten once filled in. Each is mounted only into
the one container that uses it:

| File | Fill in | Used by |
|---|---|---|
| `secrets/smtp_password` | when the SMTP relay requires authentication | `worker-integrations` |
| `secrets/ai_api_key` | with `NEXUSFLOW_AI_PROVIDER=anthropic` | `worker-integrations` |
| `secrets/n8n_api_key` | after n8n's first start (*Settings > n8n API*) | `api-internal` (operator CLI) |

```bash
cp .env.example .env
```

Set at least `NEXUSFLOW_DOMAIN` and the TLS directory. Base and third-party images
are already pinned to digests in the Compose files (see section 10). Every
application setting, its default and its constraints are listed in
[CONFIGURATION.md](CONFIGURATION.md) (generated from the settings classes).

**TLS**: put `fullchain.pem` and `privkey.pem` in `deploy/certs/` (see its README).
For a local evaluation, `make dev-certs` creates a development CA and a
certificate for `localhost` there; never use it in production.

**E-mail**: set `NEXUSFLOW_SMTP_HOST`, `NEXUSFLOW_SMTP_PORT`,
`NEXUSFLOW_SMTP_TLS_MODE` (`starttls` or `tls`; TLS and certificate validation
cannot be switched off), `NEXUSFLOW_SMTP_USERNAME`, `NEXUSFLOW_SMTP_FROM` and
`NEXUSFLOW_OPERATOR_EMAILS` in `.env`, and the password in
`secrets/smtp_password`. A relay with a private CA is trusted through
`NEXUSFLOW_NOTIFICATIONS__SMTP_CA_BUNDLE`. Temporary SMTP failures (4xx replies)
are retried with backoff; permanent ones (5xx) go to the dead-letter store.

**AI provider (optional)**: put the Anthropic API key in `secrets/ai_api_key` and
set `NEXUSFLOW_AI_PROVIDER=anthropic`. Only the integrations worker receives the
key. Tenants still have to opt in with `ai_external_processing` before any data
is sent, and datasets classified `restricted` are always analysed offline.

## 3. First start

```bash
docker compose up -d --build
```

The `migrate` service applies Alembic migrations with the migrator role and exits.
Every application service waits for it. Check the state and security posture:

```bash
docker compose ps
```

```bash
docker compose run --rm api nexusflow check-config
```

`check-config` lists security warnings, such as TLS disabled on internal hops or no
malware scanner configured.

Health: the APIs are probed on `/health/live`. The workers and beat keep a
heartbeat file fresh from their event loop - the worker consumer only while it
is connected to the broker - and are reported unhealthy when it goes stale
(`docker/healthcheck.py`), so a hung worker does not look healthy. Docker
restarts containers that exit, not unhealthy ones: alert on
`docker ps --filter health=unhealthy` (or run an orchestrator that restarts them).

Create the first organization by registering through the API. Then disable public
sign-up with `NEXUSFLOW_SIGNUP_ENABLED=false` in `.env` and `docker compose up -d`,
and invite further users from inside the organization.

## 4. n8n

Follow [workflows/n8n/README.md](../workflows/n8n/README.md) to issue one
service token per workflow, create the credentials and import the five workflows.
The editor is reachable only through an SSH tunnel:

```bash
ssh -L 5678:127.0.0.1:5678 admin@your-host
```

Then open http://localhost:5678. To run without n8n, set
`NEXUSFLOW_ORCHESTRATION=internal`.

## 5. Evaluation stack (demo overlay)

`docker-compose.demo.yml` adds Mailpit, a local mail catcher, so invitations,
password resets and alert e-mails are visible at http://127.0.0.1:8025, and
routes Alertmanager's e-mails there too. TLS stays on: Mailpit presents the
development certificate and only the demo stack trusts the development CA.

```bash
make secrets dev-certs demo-up
```

```bash
make demo
```

`make demo` runs the scripted walkthrough (`scripts/demo.py`); see
[DEMO.md](DEMO.md). Never expose the demo overlay publicly.

## 6. Optional components

* **Malware scanning**: `docker compose --profile av up -d` starts ClamAV on its own
  `av` network (only the API can reach it). Also set
  `NEXUSFLOW_CLAMAV_ADDRESS=clamav:3310` in `.env`.
* **JavaScript rendering**: the browser service starts by default; the sandbox
  reaches it as `renderer` on the internal `render` network (never over `egress`,
  which drops traffic between containers). Chromium's own sandbox needs user
  namespaces; to enable it, run the browser with a seccomp profile that permits
  `clone`/`unshare` for namespaces and set `NEXUSFLOW_BROWSER__CHROMIUM_SANDBOX=true`.
* **Tracing**: set `NEXUSFLOW_OTLP_ENDPOINT` to your OpenTelemetry collector.
* **TLS on internal hops**, for deployments that spread the services over several
  hosts (on one host this traffic stays on internal Docker networks). The clients
  are built for it and verify every server against your internal CA:
  `NEXUSFLOW_DATABASE__SSL_MODE=verify-full` with `NEXUSFLOW_DATABASE__SSL_ROOT_CERT`;
  a `rediss://` URL with `NEXUSFLOW_REDIS__SSL_CA_CERTS` (and
  `NEXUSFLOW_SANDBOX__REDIS_SSL_CA_CERTS` for the sandbox's Redis); an `amqps://`
  URL with `NEXUSFLOW_BROKER__USE_SSL=true` and `NEXUSFLOW_BROKER__SSL_CA_CERTS`.
  On the servers, enable PostgreSQL `ssl` with a `hostssl`-only `pg_hba.conf`,
  Redis `tls-port` with `port 0`, and RabbitMQ `listeners.ssl` with
  `listeners.tcp = none`, and mount the CA into every application container. The
  Compose file does not ship this server configuration; `check-config` warns for
  every hop that is still unencrypted.

## 7. Monitoring

Prometheus scrapes both APIs, both platform worker pools (port 9101) and RabbitMQ,
and evaluates the rules in `deploy/prometheus/alerts.yml`. Grafana is provisioned
with the *NexusFlow AI - Overview* dashboard and is reached through an SSH tunnel on
port 3000. Its admin password is `secrets/grafana_admin_password`.

**Alertmanager** is part of the stack. Edit the receiver in
`deploy/alertmanager/alertmanager.yml` before production (SMTP relay, PagerDuty,
Opsgenie or Slack): alerts must reach people without going through the platform
being monitored. Critical alerts repeat hourly and silence the warnings they
explain.

Ship container logs (JSON) to a central store with append-only retention. The
hourly `audit_anchor` log events (one per tenant chain and one for the platform
chain) are your external audit anchors: compare them with `nexusflow audit verify`.

## 8. Key rotation

| What | Procedure | Impact |
|---|---|---|
| **JWT signing key** | 1. Generate a new Ed25519 key and set a new `jwt_key_id`. 2. Add the old public key to `jwt_previous_public_keys` so existing tokens validate until they expire. 3. Redeploy. 4. Remove the old public key after the access-token TTL. | None |
| **KEK** | 1. Add a new key to `encryption_keys` and set `encryption_active_key_id`. 2. Redeploy. 3. Run `nexusflow keys rewrap` until it reports 0; the daily beat job also re-wraps. 4. Remove the old key. MFA secrets are re-encrypted on each user's next MFA sign-in, so keep old KEKs until all users have signed in or MFA was re-enrolled. | None |
| **HMAC pepper** | Only after a compromise, see INCIDENT_RESPONSE.md | All API keys, sessions and pending links become invalid |
| **Service tokens** | `nexusflow service-account rotate --workflow-key <key>`, then update the n8n credential | That workflow fails until updated |
| **Webhook secrets** | `POST /api/v1/webhook-endpoints/{id}/rotate-secret` (24 h grace) | None |
| **Integration secrets** | `POST /api/v1/integrations/{id}/rotate` | None |
| **Database / Redis / RabbitMQ passwords** | Change the role, ACL or definition, update the secret files (including `redis_sandbox_url` and `redis_sandbox_acl` for the sandbox Redis), restart the dependent services | Brief restart |

## 9. Backups and restore

```bash
BACKUP_AGE_RECIPIENT=age1... scripts/backup.sh /srv/backups
```

The script dumps both databases and the file volume, encrypts everything with
[age](https://age-encryption.org) and writes a SHA-256 manifest. Unencrypted backups
are refused. `scripts/restore.sh` verifies the manifest before decrypting and asks
for confirmation (automation can answer on standard input:
`echo RESTORE | scripts/restore.sh <dir>`). Objects are restored as their usual
owners, and any error stops the restore: the application database holds no
superuser-owned objects (`pg_stat_statements` lives in the `postgres` database).
Test restores regularly, and run `nexusflow audit verify` after each restore.

Both are tested: `tests/integration/test_backup_restore.py` runs the same
`pg_dump`/`pg_restore` steps against PostgreSQL with the production roles and
checks rows, row-level security, the audit chains and sign-in on the restored
database; the CI end-to-end job backs up the running stack, changes it, restores
it and runs `nexusflow audit verify`.

## 10. Release images

Pushing a version tag (`v0.1.0`) runs `.github/workflows/release.yml`. Both images
are scanned first - a fixable HIGH or CRITICAL vulnerability stops the release -
then pushed to `ghcr.io/<owner>/nexusflow-ai` and `ghcr.io/<owner>/nexusflow-browser`
with SBOM and SLSA provenance attestations, signed keyless with cosign (Sigstore)
and attested with GitHub build provenance. Signing and the GitHub attestation run
only from a public repository (Sigstore's log is public; attestations for private
repositories need GitHub Enterprise Cloud). Verify an image before deploying it:

```bash
cosign verify ghcr.io/<owner>/nexusflow-ai@sha256:<digest> --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github\.com/<owner>/<repo>/\.github/workflows/release\.yml@refs/tags/v'
```

```bash
gh attestation verify oci://ghcr.io/<owner>/nexusflow-ai@sha256:<digest> --owner <owner>
```

Then run it by digest, in `.env`:

```bash
NEXUSFLOW_IMAGE=ghcr.io/<owner>/nexusflow-ai:0.1.0@sha256:<digest>
NEXUSFLOW_BROWSER_IMAGE=ghcr.io/<owner>/nexusflow-browser:0.1.0@sha256:<digest>
```

Base images (Dockerfiles) and third-party images (Compose files, CI) are pinned
to digests; CI fails if a reference loses its digest. After Dependabot proposes a
new tag, `make pin-images` resolves the digests it points at.

## 11. Upgrades

1. Read the CHANGELOG.
2. Take a backup.
3. `docker compose pull` or `docker compose build`, then `docker compose up -d`.

Migrations run automatically and are forward-only in production. They are
additive (new nullable columns, columns with constant defaults, new functions and
indexes), so the previous release keeps working while they run. Roll back by
restoring the pre-upgrade backup.

## 12. Production checklist

- [ ] `NEXUSFLOW_APP__ENVIRONMENT=production`. The app refuses insecure combinations:
  debug mode, an http public URL, wildcard hosts or origins, missing keys.
- [ ] TLS certificates valid; HTTP redirects to HTTPS.
- [ ] Egress firewall rules applied (section 1).
- [ ] Sign-up disabled after bootstrapping; MFA required for admin organizations.
- [ ] `./secrets` backed up offline and readable only by the deploy user.
- [ ] Release images verified with cosign and run by digest; Dependabot enabled.
- [ ] Alerts routed; logs shipped to append-only storage.
- [ ] Backups scheduled and a restore tested.
- [ ] n8n and Grafana reachable only through SSH tunnels.
- [ ] ClamAV enabled if tenants upload files from untrusted parties.
- [ ] Alertmanager receiver configured and a test alert received.
- [ ] `secrets/n8n_api_key` filled in (the kill switch unpublishes n8n workflows).
- [ ] `docker compose ps` shows every service healthy.
