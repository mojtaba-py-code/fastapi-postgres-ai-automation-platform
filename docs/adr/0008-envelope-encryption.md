# 0008. Envelope encryption with context binding and KEK rotation

* Status: accepted
* Date: 2026-09-24

## Context
Integration credentials, webhook signing secrets and TOTP seeds must be usable by
the platform but useless in a database dump, and keys must be rotatable.

## Decision
* AES-256-GCM envelope encryption. Each value gets a random data key, which is wrapped
  with a key-encryption key (KEK) from a keyring.
* The blob records the KEK ID. The **context** (for example
  `integration:{org}:{id}`) is bound as associated data, so a ciphertext copied into
  another row or tenant fails to decrypt.
* Rotation: add a new KEK and mark it active. Old KEKs stay for decryption while a
  daily job and `nexusflow keys rewrap` re-wrap stored secrets. MFA seeds are
  re-wrapped lazily on use.
* KEKs come from secret files, never from the database or images.

## Consequences
A database dump alone reveals no secrets. Losing all KEKs loses the secrets, so the
keys must be backed up offline.

## Alternatives considered
A KMS or Vault transit engine is a drop-in improvement behind the same `SecretCipher`
port for cloud deployments. Database-level encryption (pgcrypto) was rejected because
it puts keys in SQL and logs.
