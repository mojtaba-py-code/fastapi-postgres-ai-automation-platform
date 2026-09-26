# Privacy and data protection

This guide is for whoever runs a NexusFlow deployment. It describes the personal
data the platform holds, how long it keeps it, and how to answer requests from the
people it is about, in terms of the UK GDPR and the EU GDPR. It is not legal advice:
your roles, lawful bases and contracts are yours to decide and document.

## 1. Roles

* Each **organization** (tenant) decides what business data it collects and why: it
  is the controller of that data. The **operator** of the deployment processes it on
  the organization's behalf, so an agreement under article 28 (a data processing
  agreement) belongs between them; [DPA_TEMPLATE.md](DPA_TEMPLATE.md) lists its
  required terms with what NexusFlow provides for each.
* **Account data** - the people who sign in, their sessions and their activity - is
  processed to run and secure the service. Whether the operator is its controller,
  or processes it for the organizations, depends on your arrangement; say so in your
  privacy notice and your agreements.

## 2. What the platform holds

| Data | Where | Why | Kept |
|---|---|---|---|
| Account: e-mail address, name, password hash (Argon2id), MFA secret (encrypted), status and timestamps | `users` | Signing in, security notices | Until the account is erased; erasure anonymises the row |
| Passkeys: public key, credential ID, a random user handle, the name the person gave it, transports, backup flags, signature counter, times | `webauthn_credentials` | Second factor at sign-in | Until the person removes it, turns MFA off or the account is erased |
| Sign-in sessions: IP address, browser string, times | `user_sessions` | Session management, revocation, sign-in risk | 90 days after the session expired (`retention.sessions_days`), then deleted |
| Refresh, password-reset and sign-up tokens (keyed hashes only; reset and sign-up requests keep the requesting IP and the address) | `refresh_tokens`, `password_reset_tokens`, `signup_requests` | Sessions, account recovery, proof of address | A week after they expire, then deleted |
| Invitations: the invited address and role | `invitations` | Joining an organization | While the organization exists (see section 7) |
| Audit trail: who did what, from which IP address and browser | `audit_logs` (append-only, hash-chained) | Accountability, security investigations | Until you purge it (section 4) |
| API keys: name, role, scopes, times (the key itself only as a keyed hash) | `api_keys` | Machine access | Until the organization is deleted; revoked when their creator leaves |
| Business data an organization collects - which may contain personal data | `records` and their history, `changes`, uploads, reports | The organization's purposes | Each dataset's own `retention_days` for history and changes; until deleted otherwise |
| Alert recipients (e-mail addresses in notification channels) | `notification_channels` | Alert delivery | Until the organization changes them |
| Application and edge logs (JSON: request IDs, paths, statuses and client IP addresses; no bodies, secrets redacted) | Your log store | Operations, security | Your log store's retention |
| Backups (all of the above, encrypted with age) | Your backup store | Recovery | Your backup rotation: erasure reaches backups when they expire |

Fields an organization marks `sensitive` are encrypted in the database (records,
their history and change diffs), and removed before any AI analysis. Datasets
classified `restricted` never leave the platform, even when an organization has
opted in to external AI.

## 3. Requests from people

| Right | How |
|---|---|
| Access and portability (art. 15, 20) | Self-service: `GET /api/v1/users/me/export` returns a JSON copy - profile, organizations, sessions, passkeys (names, times, transports; no keys), API keys, and the account's own actions in its organizations' audit trails. On a request received otherwise: `nexusflow user export --email <address>`, which also lists the account's entries in the platform's own audit chain. Both exports are audited. |
| Rectification (art. 16) | People change their name themselves (`PATCH /api/v1/users/me`). There is no self-service change of the e-mail address yet: the person can sign up with the new address and be invited again. |
| Erasure (art. 17) | Self-service: `POST /api/v1/users/me/delete` (password required). On a request received otherwise: `nexusflow user erase --email <address> --reason <ticket>`. Either way the person leaves every organization, their API keys are revoked, their sessions end, their recovery codes and passkeys are deleted and the account is anonymised; the sessions themselves go with the identity retention (section 2). Refused while the person is the sole owner of an organization: ownership moves first, or the organization is deleted. Audit entries keep the now anonymous account ID. |
| Business data about a person | Answered by the organization, which controls it (dataset exports, deletion of sources, datasets or the organization). |

Record every request and its outcome in your own case log; the audit trail shows
the exports and erasures themselves (`privacy.data_exported`, `auth.account_deleted`).

## 4. Retention you set

* **Identity data** is deleted by the daily retention job, as in section 2.
  `NEXUSFLOW_RETENTION__SESSIONS_DAYS` (default 90, at least 30) sets how long
  ended sessions stay; shorter than 90 days makes the sign-in risk assessment
  treat returning devices as new more often.
* **Business data**: per dataset (`retention_days`), and the platform-wide
  settings in [CONFIGURATION.md](CONFIGURATION.md) (`NEXUSFLOW_RETENTION__*`).
* **Audit trail**: the application cannot delete audit entries - a compromised
  service must not be able to remove its tracks. Purge them as the migrator, on a
  schedule, keeping at least 90 days (a year or more is common for security
  evidence):

  ```bash
  docker compose run --rm migrate nexusflow audit purge --older-than-days 400
  ```

  It deletes a prefix of every hash chain, so what remains still verifies, and the
  purge itself is recorded in the platform chain.

## 5. Sub-processors and transfers

| Service | When | What it receives |
|---|---|---|
| Your hosting provider | Always | Everything, encrypted where section 2 says so |
| Your SMTP relay | When e-mail is configured | Recipients, subjects and bodies of account mail and alerts |
| Anthropic (Claude API) | Only with `NEXUSFLOW_AI_PROVIDER=anthropic` **and** an organization's opt-in | Change data for analysis: sensitive fields removed, free text redacted, restricted datasets never |
| Your alerting receivers (PagerDuty, Opsgenie, Slack) | If configured in Alertmanager | Alert names and labels - no tenant data |

Sending data to a provider outside the UK or EEA (Anthropic processes in the
United States) needs a transfer mechanism, such as the UK International Data
Transfer Agreement or addendum, or the EU standard contractual clauses. The AI
provider is off by default and each organization opts in.

## 6. Security and breaches

Security of processing (art. 32): [SECURITY.md](../SECURITY.md) and the
[threat model](THREAT_MODEL.md). For a breach, follow
[INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md): the audit trail, its external
anchors and the sign-in data scope what happened. A controller notifies the
supervisory authority (in the UK, the ICO) within 72 hours of becoming aware of a
notifiable breach.

## 7. Known gaps

* Old invitations are kept while their organization exists.
* No self-service change of e-mail address.
* No search across business data for everything about one person: the
  organization answers from its own datasets.

## 8. Record of processing (template)

Article 30 asks controllers and processors to keep a record of their processing.
A starting point, to complete with your own details:

| | Accounts and security | Business data (per organization) |
|---|---|---|
| Controller / processor | *You, or the organization* | The organization (controller); you (processor) |
| Purposes | Authentication, access control, security monitoring | *The organization's own* |
| Categories of people | Users of the platform | *Whoever the collected data is about* |
| Categories of data | Section 2, rows 1-6 | *Per dataset* |
| Recipients | Section 5 | Section 5, plus the organization's own integrations |
| Transfers outside the UK/EEA | *If your hosting or relay is* | Anthropic, only with the opt-in (section 5) |
| Retention | Section 4 | Per dataset (`retention_days`) |
| Security measures | SECURITY.md | SECURITY.md; sensitive fields encrypted |
