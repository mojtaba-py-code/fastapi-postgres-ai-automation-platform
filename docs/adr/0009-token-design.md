# 0009. EdDSA access tokens, opaque rotating refresh tokens, peppered hashes

* Status: accepted
* Date: 2026-09-24

## Context
Sessions must be revocable, stolen tokens must have a small window, and a
database leak must not yield usable credentials.

## Decision
* **Access tokens**: EdDSA (Ed25519) JWTs with a 10-minute TTL and `iss`, `aud`,
  `token_use`, `kid`, session ID and token version. Every request checks the session
  and user state, so logout and password changes take effect immediately. The only
  algorithm accepted is EdDSA.
* **Refresh tokens**: opaque random values stored as HMAC-SHA256 with a server-side
  pepper. They are single-use and rotated. Presenting a used token revokes the whole
  session family (reuse detection) and notifies the user. Sessions have an absolute
  lifetime.
* **API keys / service tokens**: `nxf_` and `nxs_` prefixes with an embedded lookup
  prefix and a CRC checksum, so malformed tokens fail before any database access and
  secret scanners recognise them. They are stored as peppered hashes and shown once.
* Password reset and invitation tokens are generated in the mail worker and only
  their hashes are stored. Links carry them in the URL fragment.

## Consequences
Stateless verification plus a cheap session lookup gives immediate revocation.
Rotating the pepper invalidates all opaque tokens, which is acceptable only as an
incident response.

## Alternatives considered
HS256 JWTs (shared secret on every verifier, and algorithm-confusion risk).
Long-lived access tokens. Storing tokens with plain SHA-256 (offline guessing is
cheap if the database leaks, whereas the pepper forces a second compromise).
