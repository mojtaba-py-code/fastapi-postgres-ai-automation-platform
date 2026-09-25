# TLS certificates

nginx expects `fullchain.pem` and `privkey.pem` in this directory, or in the
directory set by `NEXUSFLOW_TLS_DIR` in `.env`. nginx runs as uid 101 and
must be able to read them: install certificates with
`scripts/install_edge_cert.sh <directory>`, which copies them (Let's Encrypt's
`live/` entries are symlinks that would dangle inside the container), gives
them to uid 101 (the key 0600) and reloads nginx.

With Let's Encrypt, issue and renew through the running edge - it serves the
HTTP-01 challenges from `deploy/acme`, so nothing has to stop for a renewal:

```bash
sudo certbot certonly --webroot -w ./deploy/acme -d example.com \
  --deploy-hook "$PWD/scripts/install_edge_cert.sh"
```

certbot's timer renews the certificate and the hook installs it and reloads
nginx. Do not point `NEXUSFLOW_TLS_DIR` at `/etc/letsencrypt/live/...`.

Never commit key material: `.gitignore` excludes `*.pem` and `*.key` here.

## Local evaluation only

```bash
make dev-certs
```

`scripts/dev_certs.py` creates a throw-away development CA (its private key is
never written to disk) and a certificate for `localhost`, `mailpit` and
`127.0.0.1` - plus `NEXUSFLOW_DOMAIN` when set - signed by it:

| File | Purpose |
|---|---|
| `fullchain.pem`, `privkey.pem` | the edge certificate (nginx) and Mailpit's STARTTLS certificate in the demo overlay |
| `dev-ca.pem` | the CA to trust: `curl --cacert`, `make demo`, the e2e tests, and the demo stack's SMTP client |

Clients verify certificates against `dev-ca.pem`; nothing switches verification
off. The script refuses to overwrite certificates it did not create, so real
certificates placed here are safe. Never use these files in production.
