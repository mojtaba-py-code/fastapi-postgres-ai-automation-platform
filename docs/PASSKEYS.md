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
   * `rp`: the relying party ID and name (section 5);
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
having passed MFA, so an organization that requires MFA opens at once (one that
requires passkeys does not: that takes a sign-in with the passkey, section 4). The
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
`mfa_method: "webauthn"`), and the sign-in risk assessment - except that the
session is recorded as a passkey session (section 4). A refused one answers
the same generic `401 mfa_failed` whatever the reason, counts toward the account
lockout like a wrong code, and is audited as `auth.mfa.failed` with
`method: "webauthn"` and the reason.

The same two steps finish a **single sign-on** whose organization requires MFA its
identity provider did not provide: the callback answers with an `mfa_token` and lists
`webauthn` among its `methods`, and the passkey opens a session bound to that
organization, as a TOTP code would - audited as `auth.sso.succeeded` with
`mfa_method: "webauthn"`, never as a password sign-in; it starts the failure count
afresh as a completed password sign-in does, and a refused passkey counts toward the
lockout there too ([SSO.md](SSO.md), sections 4 and 6). Where the organization
requires passkeys, the callback always asks, and only a passkey finishes it
(section 4).

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
* **An account bound to passkeys** - a member of an organization that requires them
  (section 4) - adds and removes passkeys, and turns MFA off, only from a session that
  signed in with one of its passkeys (`403 passkey_session_required`).
* **Never from a single sign-on session.** A session an organization's identity
  provider opened neither lists nor changes second factors (`403
  sso_session_restricted`), even when it counts as MFA-verified for that
  organization: the provider's MFA speaks for its organization only, the account's
  second factors guard all of them ([SSO.md](SSO.md), section 5).
* **The last second factor cannot be removed.** Removing the last passkey of an
  account without TOTP answers `409 last_second_factor`: register another passkey
  or set up TOTP first, or turn MFA off.
* **Turning MFA off** is one audited path, as before: `POST /api/v1/auth/mfa/disable
  {password, code}` with a TOTP code or a recovery code. It removes the authenticator
  app, every passkey and the recovery codes, and ends every session. (An account with
  passkeys only uses a recovery code here.)

## 4. Organizations that require passkeys

MFA alone still lets a phished TOTP or recovery code in. An organization can
require its members to **sign in with a passkey**:
`PATCH /api/v1/organizations/current {"settings": {"require_passkey": true}}`.

* **Every session records the second factor it signed in with**, `mfa_method`:
  `totp`, `recovery_code` or `webauthn` (a passkey). It is `null` after a sign-in
  without one, after an identity provider's MFA, and for every session opened
  before the record existed (migration 0012). Confirming TOTP in a session that has
  none records `totp`; **registering a passkey does not make a session a passkey
  session** - only signing in with one does. `GET /api/v1/users/me/sessions` lists
  it; a refresh keeps the session, and so its factor.
* Such an organization admits only sessions whose `mfa_method` is `webauthn`. Any
  other session is refused `403 passkey_required` on every request, when signing
  in *naming* the organization (which its trail shows: `auth.login.failed`, reason
  `passkey_required`) and when switching to it. A passkey sign-in is MFA too, so
  this covers `require_mfa`; the two settings stay independent.
* A sign-in that merely defaults to such an organization opens in it as in one that
  requires MFA: its requests are refused, but the MFA set-up endpoints
  (`/auth/mfa/enroll`, `/confirm`, `/auth/webauthn/register/*`,
  `/auth/webauthn/credentials*`) answer for the account - so a member can register
  their first passkey (below).
* **Its members' accounts are bound to passkeys.** While an account belongs to an
  active organization that requires passkeys, its passkeys are added or removed, and
  MFA turned off, only from a session that signed in with one of its passkeys
  (`403 passkey_session_required`, "Add passkeys from a session that signed in with
  one of your passkeys."). A session that passed a TOTP or recovery code - what a
  phishing site can relay - changes none of them. Nor, once the account has a
  passkey, does it set up an authenticator app ("Set up an authenticator app from a
  session that signed in with one of your passkeys."): a phished recovery code would
  otherwise add the phisher's own factor and replace the member's recovery codes.
  Using recovery codes is unaffected: a session that passed one opens no such
  organization.
* **The first passkey** of such an account - a new member's, or one whose factors an
  operator reset - is registered from the session it has (under the rule of section
  3: once the account has a second factor, a session that passed one). Each binding
  organization's own trail shows it (`auth.webauthn.registered_without_passkey`,
  with the member and the factor that session passed), and its owners and
  administrators are e-mailed, naming the member by address: unexpected, they remove
  the member at once.
* **Turning it on** needs a session that signed in with a passkey: from any other
  session, or with an API key, it is refused (`422 would_lock_you_out`) - the change
  would shut the caller out, and an API key (which it does not affect) shows no one
  can still sign in. Turning it off is always allowed - with an API key too, the way
  out should passkeys become unavailable on the deployment (section 5). Both are
  audited (`org.updated`).
* **API keys** are not sessions: the policy does not apply to them, as `require_mfa`
  does not. Scopes and the network allowlist confine them.
* **Single sign-on**: the provider's MFA never counts here, trusted or not. The
  callback always asks for the platform's step, offering a passkey only, and only a
  passkey completes it; a TOTP or recovery code is refused (`403 passkey_required`),
  and a person without a passkey gets nowhere ([SSO.md](SSO.md), section 6).

**Recovery** when every passkey is lost: a TOTP or recovery code still signs the
member in, but that session reaches neither the organization nor the passkeys. An
operator checks who they are outside the platform, then runs
`nexusflow user reset-second-factors --email <address> --reason <ticket>`: it
removes the account's passkeys, authenticator app and recovery codes and ends every
session; it is audited with the reason in the platform's trail and each of the
account's organizations' (`auth.mfa.reset`), and e-mailed to the account. The member
signs in with the password and registers a first passkey again - announced as above.

**What remains.** The first passkey: an account that has none yet registers it from
whatever session it has, so someone who phishes such an account's password (and a
code, if it has TOTP) before its owner registers one can register theirs. It is
announced, not prevented - the organization's trail shows it and its administrators
are e-mailed. `require_passkey` guarantees that every session reaching the
organization signed in with a passkey, and that only such a session changes a
member's passkeys once they have one.

## 5. Relying party settings

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

## 6. Recovery

* **A lost passkey**: sign in with another passkey, TOTP or a recovery code, then
  remove the lost passkey and register a new one. Where an organization requires
  passkeys, see section 4.
* **Recovery codes**: ten single-use codes are issued when the first second factor
  is set up (and replaced when TOTP is set up). Each signs in once in place of a TOTP
  code or a passkey, is audited and e-mailed.
* An operator removes a person's second factors only on a recovery request checked
  outside the platform (`nexusflow user reset-second-factors`, section 4): it is a
  way around MFA by design, so it takes a reason, is audited in the platform's and
  every organization's trail, and is e-mailed to the account. Keep the recovery
  codes safe.

## 7. Design decisions

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
  a TOTP secret implies it (migration 0010 inverted the check constraint).
* `user_sessions.mfa_method` (migration 0012) names a session's factor; check
  constraints allow the three values only, and a value only on an MFA-verified
  session. Sessions opened before it have none, so requiring passkeys asks everyone
  to sign in with one again.
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

## 8. Limitations

* **No attestation verification.** Only the `none` attestation format is accepted:
  the platform does not verify who made an authenticator and cannot restrict
  registration to certain models (an AAGUID without attestation proves nothing and
  is not stored). An authenticator that answers `attestation: "none"` with a
  self-attestation (`packed` without a certificate) is refused.
* **Not yet tried with real authenticators** (platform authenticators, security
  keys, phones) or browsers other than Chromium: the browser test uses Chromium's
  virtual authenticator (section 9).
* **The first passkey** of an account bound to passkeys comes from a session that did
  not sign in with one (it has none): announced to the organization, not prevented
  (section 4).
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

## 9. Tests

`tests/support/webauthn.py` is a software authenticator: it builds real `none`
attestation objects and signs real assertions with P-256, Ed25519 and RSA-2048 keys
from `cryptography`, and lets a test break any part of a response. The unit tests
(`tests/unit/security/test_webauthn_verifier.py`, `test_cbor.py`) refuse one defect
at a time and check the reason; `tests/security/test_passkeys.py` runs registration,
sign-in, management, organizations that require MFA, recovery and erasure end to end
through the API, and `tests/security/test_passkey_policy.py` organizations that
require passkeys: every enforcement point, the setting's lock-out guard, the recorded
factor, the recovery path and single sign-on (`tests/integration/test_migration_0012.py`
takes its migration down and up). `tests/security/test_passkey_bound_accounts.py`
covers accounts bound to passkeys: what a session that passed a code cannot change,
the first passkey's announcement, and the operator reset.

In a real browser, `tests/e2e/console_smoke.py` drives the web console in Chromium
against the running stack in CI, with a virtual authenticator (Chromium's WebAuthn
testing API): the browser's own `navigator.credentials` creates a passkey through
the console and signs in with it, and the organization then requires passkeys - a
password session having been refused first ([CONSOLE.md](CONSOLE.md), section 6).
