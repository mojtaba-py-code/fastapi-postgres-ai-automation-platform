# Passkeys (WebAuthn)

A passkey is a key pair held by an authenticator: a phone, a laptop's secure
element, a security key or a password manager. NexusFlow accepts passkeys as a
**second factor**, equal to an authenticator app (TOTP): an account can have TOTP,
passkeys, or both, and its recovery codes stand in for either.

Passkeys resist phishing where codes do not. The browser writes the origin it is
on into what the authenticator signs, and the authenticator binds the key to the
relying party ID (the site's domain), so a signature obtained through a look-alike
site is useless here - whereas a TOTP code can be typed into any page. Every
passkey ceremony also requires **user verification** (a PIN or biometric check on
the authenticator), so a passkey stands for something the person has *and* is or
knows.

The platform implements WebAuthn Level 2 (sections 7.1 and 7.2) itself, strictly
and without third-party WebAuthn or CBOR libraries: `cryptography` checks the
signatures and parses the keys, and a small CBOR decoder of our own
(`infrastructure/security/cbor.py`) reads what the authenticator sends.

## 1. Registering a passkey

From a signed-in session (never with an API key):

1. `POST /api/v1/auth/webauthn/register/begin {password}` - the password counts
   toward the lockout like a sign-in. The answer's `options` is a
   `PublicKeyCredentialCreationOptionsJSON`:
   * `challenge`: 32 random bytes, valid for five minutes, answerable once, bound to
     this account *and* this session;
   * `rp`: the relying party ID and name (section 4);
   * `user.id`: 64 random bytes, one per account - never the account's ID or e-mail
     address (`user.name` and `user.displayName` are the e-mail address and name,
     which the authenticator may show);
   * `pubKeyCredParams`: ES256 (-7), EdDSA (-8), RS256 (-257), in that order;
   * `attestation: "none"`, `authenticatorSelection: {residentKey: "preferred",
     userVerification: "required"}`, and the account's passkeys in
     `excludeCredentials`.
2. In the browser:
   ```js
   const credential = await navigator.credentials.create({
     publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
   });
   ```
   (or decode the base64url members yourself where `parseCreationOptionsFromJSON` is
   not available yet).
3. `POST /api/v1/auth/webauthn/register/finish {name, credential: credential.toJSON()}`.

The platform then checks the client data (type `webauthn.create`, the challenge in
constant time, an allowed origin, no cross-origin frame, no token binding), the
attestation object (format `none` with an empty statement), and the authenticator
data (the relying party ID's SHA-256, user presence and user verification,
consistent backup flags, a credential ID of 16 to 1,023 bytes, a COSE key whose
type, algorithm and curve agree, with an allowed algorithm), and that the credential
ID is not registered already - to any account. It stores the public key
(SubjectPublicKeyInfo), its algorithm, the signature counter, the transports the
browser reported, the backup flags, the name (cleaned, at most 64 characters) and
the user handle: public data only.

The **first** second factor of an account turns MFA on and returns ten single-use
recovery codes, shown once. The session that registered the passkey counts as
having passed MFA, so an organization that requires MFA opens at once. The
registration is audited (`auth.webauthn.registered`, and `auth.mfa.enabled` for the
first factor) and e-mailed to the account's address ("A passkey was added").
A refused registration answers `422 passkey_rejected` with the reason in
`details[0].code` (for example `origin_not_allowed`) and is audited
(`auth.webauthn.registration_failed`); a credential registered already answers
`409 passkey_exists`. An account has at most **ten** passkeys.

## 2. Signing in with a passkey

1. `POST /api/v1/auth/login {email, password}` answers `{mfa_required: true,
   mfa_token, expires_in, methods}`; `methods` lists `webauthn` when the account has
   passkeys (and `totp`, `recovery_code` as they apply).
2. `POST /api/v1/auth/mfa/webauthn/begin {mfa_token}` answers
   `PublicKeyCredentialRequestOptionsJSON`: a fresh challenge bound to that sign-in
   (valid at most five minutes, never beyond the `mfa_token`, answerable once), the
   account's passkeys in `allowCredentials` and `userVerification: "required"`.
3. `navigator.credentials.get({publicKey:
   PublicKeyCredential.parseRequestOptionsFromJSON(options)})`, then
   `POST /api/v1/auth/mfa/webauthn/verify {mfa_token, credential: credential.toJSON()}`
   returns the token pair.

The platform checks that the credential is one of **this account's** passkeys and
was allowed by the options, that a returned user handle is the account's, the
client data (type `webauthn.get`, challenge, origin, no cross-origin frame), the
authenticator data (relying party ID hash, user presence and verification, no new
credential, backup eligibility unchanged since registration) and the signature over
the authenticator data and the SHA-256 of the client data, with the stored key:
DER-encoded ECDSA P-256 with SHA-256 in its canonical form, Ed25519, or RSASSA-PKCS1-v1_5
with SHA-256.

**Signature counter.** When the stored or the presented counter is not zero, the
presented one must be greater. Otherwise the passkey may have been copied, and the
sign-in is refused, audited (`auth.webauthn.clone_suspected`, with both counters)
and e-mailed to the account. Passkeys that always report zero (most synced passkeys)
are accepted: they offer no counter to compare.

A successful passkey completes the sign-in exactly as a correct TOTP code does: an
MFA-verified session, the failure counters reset, `auth.login.succeeded` (with
`mfa_method: "webauthn"`), and the sign-in risk assessment. A refused one answers
the same generic `401 mfa_failed` whatever the reason, counts toward the account
lockout like a wrong code, and is audited as `auth.mfa.failed` with
`method: "webauthn"` and the reason.

## 3. Managing passkeys

| Request | |
|---|---|
| `GET /api/v1/auth/webauthn/credentials` | My passkeys: ID, name, algorithm, transports, backup flags, created and last used - no key material or credential IDs |
| `PATCH /api/v1/auth/webauthn/credentials/{id} {name}` | Rename (audited `auth.webauthn.renamed`) |
| `POST /api/v1/auth/webauthn/credentials/{id}/delete {password}` | Remove (password confirmation; audited `auth.webauthn.removed`; e-mailed "A passkey was removed") |

Another account's passkey is `404`. Rules that keep MFA meaningful:

* Once an account has a second factor, **changing its second factors needs a
  session that passed one** (at sign-in, or by setting it up): adding a passkey,
  removing one and setting up TOTP answer `403 mfa_session_required` otherwise. A
  stolen session or API key, even with the password, cannot add a factor of its own
  or take one away.
* **The last second factor cannot be removed.** Removing the last passkey of an
  account without TOTP answers `409 last_second_factor`: register another passkey
  or set up TOTP first, or turn MFA off.
* **Turning MFA off** is one audited path, as before: `POST /api/v1/auth/mfa/disable
  {password, code}` with a TOTP code or a recovery code. It removes the authenticator
  app, every passkey and the recovery codes, and ends every session. (An account with
  passkeys only uses a recovery code here.)

## 4. Relying party settings

| Setting | Default | |
|---|---|---|
| `NEXUSFLOW_APP__PUBLIC_BASE_URL` | `http://localhost:8000` | Its host is the relying party ID, and its origin is accepted |
| `NEXUSFLOW_SECURITY__WEBAUTHN_RP_ID` | unset | The public host itself or a parent domain of it, e.g. `example.com` for `https://app.example.com` |
| `NEXUSFLOW_SECURITY__WEBAUTHN_ORIGINS` | `[]` | More origins answers may come from, e.g. a web front end on another subdomain |
| `NEXUSFLOW_SECURITY__MFA_ISSUER` | `NexusFlow AI` | The relying party's name, shown by some authenticators |

* The origin of a passkey answer is the origin of the **web page** that called
  `navigator.credentials`. If the web front end is served from another host than
  `app.public_base_url`, list its origin in `webauthn_origins` and set
  `webauthn_rp_id` to a domain both share.
* Origins are compared exactly, as browsers write them: scheme, lower-case host and a
  port only when it is not the default. They must use https; `http://localhost` is
  accepted only outside staging and production. Each must lie within the relying
  party ID.
* The service refuses to start with a relying party ID that is not the public host
  or a parent domain of it, or with an origin that cannot be used. Browsers also
  refuse public suffixes (such as `co.uk`) as a relying party ID, which the service
  cannot check without the Public Suffix List. Internationalised domain names must
  be written in their `xn--` form.
* When the public host is an IP address (or no https origin is left), passkeys are
  unavailable - the endpoints answer `503 passkeys_unavailable` - and the service
  logs a warning at startup. WebAuthn needs a domain name.
* **Changing the relying party ID invalidates every registered passkey**: each is
  bound to the ID it was created for. Keep it stable; people then sign in with
  TOTP or a recovery code and register again.

## 5. Recovery

* **A lost passkey**: sign in with another passkey, TOTP or a recovery code, then
  remove the lost passkey and register a new one.
* **Recovery codes**: ten single-use codes are issued when the first second factor
  is set up (and replaced when TOTP is set up). Each signs in once in place of a TOTP
  code or a passkey, is audited and e-mailed.
* There is deliberately no operator command that removes a person's second factor:
  it would be a way around MFA. Keep the recovery codes safe.

## 6. Design decisions

* **Challenges live in Redis**, stored by `SET` with a TTL and taken with `GETDEL`:
  a challenge is answered at most once however many answers race for it, and
  expires on its own - nothing to purge and no row locks on the sign-in path. Keys
  are hashed; the stored state names the account, the session (registration) or
  sign-in (sign-in) it is bound to, its expiry and, for a sign-in, the passkeys it
  allowed. Without Redis no challenge is issued or accepted (fail closed), like the
  sign-in steps' rate limits.
* **Credentials** are in `webauthn_credentials`, user-scoped like the recovery
  codes: row-level security enabled and forced, rows visible to their owner (or
  during authentication) only. A credential ID is unique across all accounts, and
  every lookup names the account - an ID alone never selects one. The runtime
  database role may update only a passkey's name, counter, backup state and last
  use: its public key, algorithm, credential ID, user handle and owner cannot be
  changed, only the whole passkey removed.
* `users.mfa_enabled` means "a second factor is set up" (TOTP, passkeys or both);
  a TOTP secret implies it (migration 0011 inverted the check constraint).
* **Rate limits** (fail closed): `auth.webauthn.sign_in`, 20 per 5 minutes per client
  address, for the sign-in step; `auth.webauthn.manage`, 30 per 15 minutes per
  person, for registering and managing.
* Binary values are unpadded base64url in their canonical form, as the WebAuthn
  Level 3 JSON forms use; each request member is bounded before it is decoded
  (client data 4 KiB, attestation object 64 KiB, authenticator data 4 KiB,
  signature 512 bytes, user handle 64 bytes, credential ID 1,023 bytes).
* The CBOR decoder accepts only what WebAuthn needs: major types 0-5 and
  false/true/null, definite lengths, integer or text map keys without duplicates,
  bounded size, depth and item count, nothing after the item. It does not insist on
  the shortest encoding or on key order, which not every client produces.

## 7. Limitations

* **No attestation verification.** Only the `none` attestation format is accepted:
  the platform does not verify who made an authenticator and cannot restrict
  registration to certain models (an AAGUID without attestation proves nothing and
  is not stored). An authenticator that answers `attestation: "none"` with a
  self-attestation (`packed` without a certificate) is refused.
* **User verification is required**: an authenticator without a PIN or biometric
  check cannot be registered.
* **Second factor only**: signing in without a password (discoverable credentials,
  conditional UI) is not offered, though passkeys are created as discoverable where
  the authenticator prefers it.
* No extensions are requested and extension outputs are ignored; cross-origin
  iframes, token binding, related origins (`/.well-known/webauthn`) and native-app
  origins (`android:apk-key-hash:`) are not supported.
* A counter regression refuses the sign-in but does not disable the passkey; the
  person decides (the e-mail says what to do).
* Setting up a first second factor does not end the account's other sessions, and
  removing a passkey does not end sessions that were verified with it: end them from
  the session list (`DELETE /api/v1/users/me/sessions/{id}`) or with
  `POST /api/v1/auth/logout-all`.

## 8. Tests

`tests/support/webauthn.py` is a software authenticator: it builds real `none`
attestation objects and signs real assertions with P-256, Ed25519 and RSA-2048 keys
from `cryptography`, and lets a test break any part of a response. The unit tests
(`tests/unit/security/test_webauthn_verifier.py`, `test_cbor.py`) refuse one defect
at a time and check the reason; `tests/security/test_passkeys.py` runs registration,
sign-in, management, organizations that require MFA, recovery and erasure end to end
through the API.
