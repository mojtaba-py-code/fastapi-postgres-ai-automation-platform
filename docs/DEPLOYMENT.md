# Deployment

This guide deploys NexusFlow AI on a single Linux host with Docker Compose, which is
the reference topology in `docker-compose.yml`. The same images run on Kubernetes;
map every compose control (networks, read-only, capabilities, secrets, limits) to
its Kubernetes equivalent (NetworkPolicies, securityContext, Secrets, requests and
limits).

## 1. Host prerequisites

* A recent Linux kernel, Docker Engine 28.0 or later with Compose v2, and automatic
  security updates. Earlier engines let hosts on the same network segment reach
  ports published on 127.0.0.1 (the n8n editor, Grafana) and route to container
  ports directly.
* A host firewall that allows inbound 22 (SSH, preferably from a VPN or bastion) and
  443/80 only.
* Full-disk encryption or an encrypted volume for Docker data. The application
  encrypts sensitive field values, staged payloads, uploads and reports itself;
  other tenant data is plaintext in PostgreSQL so it can be queried.
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
* IPv4 at the edge: ports 80 and 443 are published on IPv4 only. An IPv6 client
  would reach nginx through Docker's userland proxy and appear as the bridge
  gateway - one address for every IPv6 user, in rate limits, sign-in risk and
  network allowlists. Do not publish an AAAA record for the platform's domain;
  serve IPv6 through a dual-stack load balancer in front of the edge (next
  section).

### Client addresses behind another proxy

The API sees the real client address because the edge (nginx) overwrites
`X-Forwarded-For` with its peer and the API trusts that header only from the edge
subnet (`NEXUSFLOW_APP__TRUSTED_PROXIES`). If a load balancer or CDN sits in front of
the edge, configure nginx's `real_ip` module (`set_real_ip_from` with the balancer's
ranges, `real_ip_header X-Forwarded-For`) so the edge forwards the client's address,
not the balancer's. Otherwise per-IP rate limits, sign-in risk and organization
network allowlists all see one address - the balancer's.

### Egress firewall (required)

The `egress` network is the only one with internet access. It is shared by the
integrations worker, the sandbox, the browser, ClamAV (signature updates) and
Alertmanager (paging), with inter-container traffic disabled (`enable_icc: false`),
so they cannot reach each other over it. The application already pins every
outbound connection to a validated public address (the browser through its pinning
egress proxy). Also block private ranges at the network layer, as defence in depth
against a compromised container that no longer runs the application's guards:

```bash
EGRESS=$(docker network inspect nexusflow_egress --format '{{(index .IPAM.Config 0).Subnet}}')
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
  sudo iptables -I DOCKER-USER -s "$EGRESS" -d "$net" -j DROP
done
```

Then let name resolution through - **before** the rules above, which is where `-I`
puts them. Docker's embedded DNS forwards the containers' queries from inside their
own network to the host's upstream resolvers, which are often in a private range (a
cloud VPC's resolver, `169.254.169.254` on Google Cloud, a corporate DNS server):
without this, nothing on `egress` resolves - no collection, no rendering, no e-mail
or paging:

```bash
RESOLV=/run/systemd/resolve/resolv.conf; [ -f "$RESOLV" ] || RESOLV=/etc/resolv.conf
for dns in $(awk '/^nameserver/ {print $2}' "$RESOLV"); do
  for proto in udp tcp; do
    sudo iptables -I DOCKER-USER -s "$EGRESS" -d "$dns" -p "$proto" --dport 53 -j RETURN
  done
done
```

Add a `RETURN` rule the same way for any private destination the platform must
reach: an internal SMTP relay (port 587 or 465) or an on-call endpoint for
Alertmanager. Traffic from a container to the host itself goes through `INPUT`, not
`DOCKER-USER`: keep host services closed to the Docker bridge networks in the host
firewall. nginx needs no outbound connections at all:

```bash
PUBLIC=$(docker network inspect nexusflow_public --format '{{(index .IPAM.Config 0).Subnet}}')
sudo iptables -I DOCKER-USER -s "$PUBLIC" -m conntrack --ctstate NEW -j DROP
```

Check that names still resolve (`docker compose exec worker-integrations python -c
"import socket; print(socket.getaddrinfo('example.com', 443)[0][4])"`), persist the
rules (for example with `iptables-persistent`) and re-apply them if a network is
recreated. For stricter setups, send `egress` through an allowlisting forward proxy.

### Sandbox isolation (what Compose already does)

* The sandbox pool has no database, storage mount or platform secrets. It talks to
  the platform only through the internal gateway with per-run tickets.
* It uses its own Redis (`redis-sandbox`: no persistence, LRU eviction, 48 MB) and
  has no account on the platform Redis that holds rate limits, replay nonces and the
  kill switch.
* Its RabbitMQ user cannot declare anything, reads only the `sandbox` queue and
  publishes only to the `nexusflow.sandbox` exchange. The queue is bounded
  (10,000 messages, 64 MiB) with `reject-publish`.
* Optionally cap its connections and channels as well (the limit survives the
  definitions import at every start):

```bash
docker compose exec rabbitmq rabbitmqctl set_user_limits -p nexusflow sandbox '{"max-connections": 16, "max-channels": 64}'
```

## 2. Configuration and secrets

```bash
make secrets    # scripts/generate_secrets.py, then scripts/internal_pki.py
```

This writes `./secrets` (directory mode 0700) containing database, Redis and
RabbitMQ credentials with their hashed ACLs, the Ed25519 JWT key, the KEK keyring,
the HMAC pepper, the n8n secrets, the browser token, and the internal PKI (below).
Compose mounts them as `/run/secrets/*`, and the application reads them through
`NEXUSFLOW_*_FILE` variables. **Back up `./secrets` offline**: losing the KEKs makes
stored integration secrets and every sealed value unrecoverable.

Running `make secrets` again creates only what is missing - an upgrade that
introduces a secret adds it - and never touches an existing file. A group of
values generated together (a password and the URL or hash that embeds it) that is
only partly present is refused: restore the rest from your backup. `--force`
regenerates *every* secret and is for fresh installs only; on a running stack it
locks the database roles out and makes encrypted data unreadable.

**Internal TLS.** PostgreSQL, both Redis instances and RabbitMQ accept TLS
connections only, and every client verifies the server's certificate and host name
against the stack's private CA. `scripts/internal_pki.py` issues it: the CA
(`internal_ca.pem`, mounted into every client; its key `internal_ca.key` never
leaves the host and is mode 0600) and one server certificate per service, valid
for two years. Check them monthly - the command exits 1 within 30 days of an
expiry - and renew before they expire:

```bash
python scripts/internal_pki.py --check
```

```bash
python scripts/internal_pki.py --renew && docker compose up -d --force-recreate
```

`--rotate-ca` replaces the CA as well (every service restarts with the new one).
`docker-compose.dev.yml` keeps plain connections on 127.0.0.1 for local development.

Three optional secrets are created **empty** (an empty secret file means "not
configured") and are never overwritten once filled in. Each is mounted only into
the containers that use it:

| File | Fill in | Used by |
|---|---|---|
| `secrets/smtp_password` | when the SMTP relay requires authentication | `worker-integrations`; `alertmanager` (its `auth_password_file`) |
| `secrets/ai_api_key` | with `NEXUSFLOW_AI_PROVIDER=anthropic` | `worker-integrations` |
| `secrets/n8n_api_key` | after n8n's first start (*Settings > n8n API*) | `api-internal` (operator CLI) |

```bash
cp .env.example .env
```

Set at least `NEXUSFLOW_DOMAIN` and the TLS directory. Base and third-party images
are already pinned to digests in the Compose files (see section 10). Every
application setting, its default and its constraints are listed in
[CONFIGURATION.md](CONFIGURATION.md) (generated from the settings classes).

**TLS**: nginx runs as uid 101 and reads `fullchain.pem` and `privkey.pem` from
`deploy/certs/` (or `NEXUSFLOW_TLS_DIR`). Install them with
`sudo scripts/install_edge_cert.sh <directory>`, which copies them for uid 101 -
Let's Encrypt's `live/` entries are symlinks that would dangle in the container -
and reloads nginx. With Let's Encrypt, the edge serves the HTTP-01 challenges from
`deploy/acme`, so certificates are issued and renewed without stopping anything:

```bash
sudo certbot certonly --webroot -w ./deploy/acme -d example.com --deploy-hook "$PWD/scripts/install_edge_cert.sh"
```

For a local evaluation, `make dev-certs` creates a development CA and a certificate
for `localhost` in `deploy/certs/`; never use it in production.

**E-mail**: set `NEXUSFLOW_SMTP_HOST`, `NEXUSFLOW_SMTP_PORT`,
`NEXUSFLOW_SMTP_TLS_MODE` (`starttls` or `tls`; TLS and certificate validation
cannot be switched off), `NEXUSFLOW_SMTP_USERNAME`, `NEXUSFLOW_SMTP_FROM` and
`NEXUSFLOW_OPERATOR_EMAILS` in `.env`, and the password in
`secrets/smtp_password`. A relay with a private CA is trusted through
`NEXUSFLOW_NOTIFICATIONS__SMTP_CA_BUNDLE`. Temporary SMTP failures (4xx replies)
are retried with backoff; permanent ones (5xx) go to the dead-letter store.
Leaving `NEXUSFLOW_SMTP_HOST` empty turns e-mail off: start-up warns, and account
mail (sign-in notices, invitations, password resets) is skipped and logged, not
retried.

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

Create the first organization by signing up through the API: the link to finish
arrives by e-mail (section 2, "E-mail"). Without an SMTP relay yet, an operator
prints one instead - it is valid 24 hours, and whoever opens it chooses the owner's
password:

```bash
docker compose run --rm api-internal nexusflow signup issue --email owner@example.com
```

Then disable public sign-up with `NEXUSFLOW_SIGNUP_ENABLED=false` in `.env` and
`docker compose up -d`, and invite further users from inside the organization.
`nexusflow signup issue` keeps working while sign-up is disabled: it is how an
operator onboards the next customer organization.

## 4. n8n

n8n is opt-in: the platform orchestrates itself by default. Start it with
`COMPOSE_PROFILES=n8n` in `.env` (then `docker compose up -d`), and **set up its
owner account at once** - until then anyone who reaches the editor could claim
it. Follow [workflows/n8n/README.md](../workflows/n8n/README.md) to issue one
service token per workflow, create the credentials and import the five workflows.
The editor is reachable only through an SSH tunnel:

```bash
ssh -L 5678:127.0.0.1:5678 admin@your-host
```

Then open http://localhost:5678, and switch orchestration over with
`NEXUSFLOW_ORCHESTRATION=n8n` once the workflows are active.

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
  `av` network (only the API can reach it), unprivileged, with the 4 GiB upstream
  recommends (a signature update briefly holds two engines). Also set
  `NEXUSFLOW_CLAMAV_ADDRESS=clamav:3310` in `.env`. While ClamAV is unreachable,
  uploads are refused and `MalwareScannerUnavailable` fires.
* **JavaScript rendering**: the browser service starts by default; the sandbox
  reaches it as `renderer` on the internal `render` network (never over `egress`,
  which drops traffic between containers). Chromium's own sandbox needs user
  namespaces; to enable it, run the browser with a seccomp profile that permits
  `clone`/`unshare` for namespaces and set `NEXUSFLOW_BROWSER__CHROMIUM_SANDBOX=true`.
* **Tracing**: set `NEXUSFLOW_OTLP_ENDPOINT` to your OpenTelemetry collector. The
  APIs, the pipeline worker and beat have no route off their internal networks:
  run the collector as a service on the `backend` network (and `monitoring`, to
  export onwards), not on the host or the internet.

## 7. Monitoring

Prometheus scrapes both APIs, both platform worker pools (port 9101) and RabbitMQ,
and evaluates the rules in `deploy/prometheus/alerts.yml`. Grafana is provisioned
with the *NexusFlow AI - Overview* dashboard and is reached through an SSH tunnel on
port 3000. Its admin password is `secrets/grafana_admin_password`.

**Alertmanager** is part of the stack. Edit the receiver in
`deploy/alertmanager/alertmanager.yml` before production (SMTP relay, PagerDuty,
Opsgenie or Slack): alerts must reach people without going through the platform
being monitored. Critical alerts repeat hourly and silence the warnings they
explain. An SMTP relay that requires authentication reads its password from
`secrets/smtp_password`, mounted for `auth_password_file`.

Ship container logs (JSON) to a central store with append-only retention. The
hourly `audit_anchor` log events (one per tenant chain and one for the platform
chain) are your external audit anchors: compare them with `nexusflow audit verify`.

## 8. Key rotation

| What | Procedure | Impact |
|---|---|---|
| **JWT signing key** | 1. Generate a new Ed25519 key and set a new `jwt_key_id`. 2. Add the old public key to `jwt_previous_public_keys` so existing tokens validate until they expire. 3. Redeploy. 4. Remove the old public key after the access-token TTL. | None |
| **KEK** | 1. Add a new key to `encryption_keys` and set `encryption_active_key_id`. 2. Redeploy. 3. Run `nexusflow keys rewrap` until it reports `"ok": true` (it lists what is left per tenant and exits 3 otherwise) - it re-wraps integration and webhook secrets, sealed field values in records, versions and changes, and the keys of stored files; the daily beat job does the same in batches. 4. Remove the old key. MFA secrets are re-encrypted on each user's next MFA sign-in, and staged payloads live only minutes, so keep old KEKs until all users have signed in or MFA was re-enrolled. | None |
| **HMAC pepper** | Only after a compromise, see INCIDENT_RESPONSE.md | All API keys, sessions and pending links become invalid |
| **Service tokens** | `nexusflow service-account rotate --workflow-key <key>`, then update the n8n credential | That workflow fails until updated |
| **Webhook secrets** | `POST /api/v1/webhook-endpoints/{id}/rotate-secret` (24 h grace) | None |
| **Integration secrets** | `POST /api/v1/integrations/{id}/rotate` | None |
| **Database / Redis / RabbitMQ passwords** | Change the role, ACL or definition, update the secret files (including `redis_sandbox_url` and `redis_sandbox_acl` for the sandbox Redis), restart the dependent services | Brief restart |

### Keys wrapped by Vault (optional)

By default `secrets/encryption_keys` holds the key-encryption keys themselves:
whoever copies that file, or a backup of it, can decrypt every sealed value. With
HashiCorp Vault's transit engine the file holds Vault ciphertexts instead. The
platform unwraps them once at start-up - retrying while Vault is unreachable, then
refusing to start - and encrypts locally from then on. Access to the keys is then
granted, audited and revoked in Vault. A running process still holds the keys in
memory, as with local keys.

1. In Vault, a transit key and an AppRole that may only decrypt with it:

   ```bash
   vault secrets enable transit
   ```

   ```bash
   vault write -f transit/keys/nexusflow type=aes256-gcm96
   ```

   ```hcl
   path "transit/decrypt/nexusflow" { capabilities = ["update"] }
   ```

   The operator's own policy also needs `transit/encrypt/nexusflow` and
   `transit/rewrap/nexusflow`.
2. Put the AppRole's secret ID in `secrets/vault_secret_id`, Vault's CA certificate
   in `secrets/vault_ca.pem`, and `NEXUSFLOW_VAULT_ADDRESS` and
   `NEXUSFLOW_VAULT_ROLE_ID` in `.env` (the two files mode 0644, like the other
   secrets: the 0700 directory protects them). The overlay `docker-compose.vault.yml`
   gives the five services that load the keyring these settings and a route to
   Vault; restrict that network to the Vault address in the host firewall, as in
   section 1.
3. Wrap the existing keyring - the keys stay the same, so no stored data changes -
   with an operator token passed from the environment for this one run (the
   keyring is still local at this point):

   ```bash
   NEXUSFLOW_VAULT__TOKEN="$(cat ~/.vault-token)" docker compose -f docker-compose.yml -f docker-compose.vault.yml run --rm -e NEXUSFLOW_SECURITY__KEK_PROVIDER=local -e NEXUSFLOW_VAULT__TOKEN api-internal nexusflow keys vault-wrap
   ```

   Write the printed `encryption_keys` object to `secrets/encryption_keys`, keeping
   the old file offline until the platform has started with the new one.
4. Start with the overlay:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.vault.yml up -d
   ```

To rotate the wrapping key, run `vault write -f transit/keys/nexusflow/rotate`,
then `nexusflow keys vault-rewrap` and write its output to
`secrets/encryption_keys`; the keys themselves do not change. For a new
key-encryption key, `nexusflow keys vault-new --key-id kek-2` prints it wrapped:
add it, make it active and run `nexusflow keys rewrap` as above.

## 9. Backups and restore

```bash
BACKUP_AGE_RECIPIENT=age1... BACKUP_SIGNING_KEY=/root/.ssh/nexusflow-backup scripts/backup.sh /srv/backups
```

The script dumps both databases and the file volume, encrypts everything with
[age](https://age-encryption.org) and writes a SHA-256 manifest - signed with
`ssh-keygen -Y sign` when `BACKUP_SIGNING_KEY` names an SSH key kept off the backup
store. Unencrypted backups are refused. `scripts/restore.sh` checks the manifest
before decrypting anything - with `BACKUP_ALLOWED_SIGNERS` (an allowed-signers file
naming `nexusflow-backup`), also that backup.sh signed it: a hash list proves
integrity, not origin - and asks for confirmation (automation can answer on standard
input: `echo RESTORE | scripts/restore.sh <dir>`). Each database is restored by its
owner role, never as the superuser, so a tampered dump cannot escalate; any error
stops the restore. Test restores regularly, and run `nexusflow audit verify` after
each restore.

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

Base images (literal `FROM` lines), the BuildKit frontend and third-party images
(Compose files, CI) are pinned to digests in forms Dependabot reads; CI fails if a
reference loses its digest. After Dependabot proposes a new tag, `make pin-images`
resolves the digests it points at. Every week CI rebuilds and scans the platform's
images and Trivy scans every third-party image the stack runs; the few findings
that no upstream release fixes yet, and that cannot be reached here, are listed
with their reasons in `.trivyignore.yaml` (see SECURITY.md). Override an image on
purpose with its variable, digest included, e.g.
`NGINX_IMAGE=nginxinc/nginx-unprivileged:1.30-alpine-slim@sha256:<digest>`.

## 11. Upgrades

1. Read the CHANGELOG.
2. Take a backup.
3. `make secrets` - adds any secret the new release needs, touching none that
   exist.
4. `docker compose pull` or `docker compose build`, then `docker compose up -d`.

A stack set up before internal TLS existed (its `secrets/redis_app_url` still
begins with `redis://`) also needs `python scripts/generate_secrets.py --tls-urls`
before step 4: it rewrites the Redis and broker URLs for TLS and keeps their
credentials. Grafana now runs from `grafana/grafana` (the maintained image;
`grafana/grafana-oss` stopped receiving releases) and Prometheus from its current
long-term-support line, 3.13: both keep their data volumes.

Migrations run automatically and are forward-only in production. They are
additive (new nullable columns, columns with constant defaults, new functions and
indexes), so the previous release keeps working while they run. Roll back by
restoring the pre-upgrade backup.

## 12. Production checklist

- [ ] `NEXUSFLOW_APP__ENVIRONMENT=production`. The app refuses insecure combinations:
  debug mode, an http public URL, wildcard hosts or origins, missing keys.
- [ ] TLS certificates valid; HTTP redirects to HTTPS.
- [ ] Docker Engine 28.0 or later; no AAAA record for the domain (section 1).
- [ ] Egress firewall rules applied, and names still resolve on `egress` (section 1).
- [ ] `python scripts/internal_pki.py --check` scheduled monthly.
- [ ] Sign-up disabled after bootstrapping; MFA required for admin organizations.
- [ ] `./secrets` backed up offline and readable only by the deploy user.
- [ ] Release images verified with cosign and run by digest; Dependabot enabled.
- [ ] Alerts routed; logs shipped to append-only storage.
- [ ] Backups scheduled, signed (`BACKUP_SIGNING_KEY`), and a restore tested.
- [ ] Audit retention decided and scheduled (`nexusflow audit purge`, see PRIVACY.md);
  privacy notice and processing agreements in place.
- [ ] n8n and Grafana reachable only through SSH tunnels; n8n's owner set up the
  moment it is enabled.
- [ ] ClamAV enabled if tenants upload files from untrusted parties.
- [ ] Alertmanager receiver configured and a test alert received.
- [ ] `secrets/n8n_api_key` filled in (the kill switch unpublishes n8n workflows).
- [ ] `docker compose ps` shows every service healthy.
