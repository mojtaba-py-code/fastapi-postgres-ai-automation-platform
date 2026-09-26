# Data processing agreement - a checklist template

**This is a drafting aid, not legal advice and not a contract.** When an operator of
NexusFlow processes personal data on an organization's behalf, UK GDPR and EU GDPR
article 28 require a written contract with the terms in article 28(3). This page
lists those terms and fills in what NexusFlow itself does, so that your lawyers can
start from facts rather than from a blank page. Have them draft or review the
agreement; the UK ICO's guidance on contracts between controllers and processors
is a good companion.

In this page the *customer* is the organization (the controller) and the
*provider* is whoever runs the NexusFlow deployment (the processor). See
[PRIVACY.md](PRIVACY.md) for the roles and the data inventory.

## 1. Description of the processing (art. 28(3), first paragraph)

| Item | Fill in | What NexusFlow provides |
|---|---|---|
| Subject matter | *The service agreement it belongs to* | Collection, change detection, alerting, analysis and reporting of business data the customer configures |
| Duration | *The service term, plus the deletion period below* | Organization deletion purges all tenant data after a 7-day grace period |
| Nature and purpose | *The customer's purposes* | Automated collection (websites, APIs, webhooks, uploads), storage, comparison, notification, optional AI analysis |
| Types of personal data | *Per dataset* - and the account data of the customer's users | Datasets are typed; fields can be marked `sensitive` (encrypted, masked, never sent to AI) and datasets classified `restricted` |
| Categories of data subjects | *Whoever the collected data is about*; the customer's users | - |

## 2. The processor's obligations (art. 28(3)(a)-(h))

| Clause | Obligation | How NexusFlow supports it |
|---|---|---|
| (a) | Process only on documented instructions, including on transfers | The customer's configuration is the instruction: sources, datasets, retention, AI opt-in (off by default); every configuration change is in the organization's audit trail |
| (b) | People authorised to process are bound to confidentiality | *Your staff contracts.* Operator access paths (CLI, SSH tunnels) are audited in the platform chain |
| (c) | Security of processing (art. 32) | [SECURITY.md](../SECURITY.md), the [threat model](THREAT_MODEL.md) and [ASVS.md](ASVS.md): tenant isolation enforced in the database, encryption in transit (edge and internal) and of sensitive values at rest, MFA, audit trail, backups |
| (d) | Engage sub-processors only with authorisation, and flow down the same terms | The list in [PRIVACY.md](PRIVACY.md) section 5 (hosting, SMTP relay, Anthropic only with the customer's opt-in, alerting services); *your notification and objection procedure* |
| (e) | Assist with data-subject requests | Account data: self-service export and erasure, and operator commands for requests received otherwise ([PRIVACY.md](PRIVACY.md) section 3). Business data: the customer's dataset exports and deletions |
| (f) | Assist with security, breach notification, DPIAs and prior consultation | Breach: [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md), the audit trail and its external anchors; *your notification deadline to the customer (for example 24 or 48 hours)* |
| (g) | Delete or return the data at the end | Dataset exports (CSV, JSON lines) to return it; organization deletion to delete it (purged after 7 days); *backup expiry for the copies in backups* |
| (h) | Make information available and allow audits | This documentation, the security review record, the CI evidence (tests, scans, DAST) and *your audit clause* |

## 3. Transfers

If any processing happens outside the UK or the EEA - your hosting, your relay, or
the optional AI provider (Anthropic, United States) - the agreement needs a transfer
mechanism: the UK International Data Transfer Agreement or the addendum to the EU
standard contractual clauses, or the EU standard contractual clauses themselves.
The AI provider is off by default and each organization opts in; datasets
classified `restricted` are never sent.

## 4. Annex: technical and organisational measures

Summarise, from [SECURITY.md](../SECURITY.md):

* access control - roles, API-key scopes, MFA (enforceable per organization),
  network allowlists, session revocation;
* separation - forced row-level security per tenant plus explicit tenant filters;
  an isolated sandbox for untrusted content;
* encryption - TLS at the edge and on every internal hop; AES-256-GCM for secrets,
  sensitive fields, staged payloads, uploads and reports; keys optionally wrapped
  by HashiCorp Vault;
* integrity and accountability - a hash-chained audit trail, verified daily and
  anchored externally;
* availability - encrypted, signed backups with a tested restore;
* retention - per dataset, identity data deleted on schedule, audit retention set
  by the operator;
* testing - automated security tests, dependency and image scanning, a dynamic scan
  of every API operation on every change, and the review record.

State plainly what has not been done yet, such as an independent penetration test
([FINAL_REVIEW.md](FINAL_REVIEW.md), section 7).
