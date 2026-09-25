# TLS certificates

nginx expects `fullchain.pem` and `privkey.pem` in this directory, or in the
directory set by `NEXUSFLOW_TLS_DIR` in `.env`. Use certificates from your
CA or from Let's Encrypt (for example `certbot certonly --standalone`).

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
