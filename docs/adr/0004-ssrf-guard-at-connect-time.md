# 0004. SSRF protection at connect time (httpx2 network backend)

* Status: accepted
* Date: 2026-09-24

## Context
Tenants configure URLs that the platform fetches: websites, REST APIs and webhook
channels. Classic SSRF defences validate the URL string and then let the HTTP
library resolve DNS again. That leaves a time-of-check/time-of-use gap (DNS
rebinding), plus redirect and IPv6-embedding bypasses.

## Decision
* A static `UrlPolicy`:
  * `https` (and `http` only outside production);
  * allowed ports;
  * no userinfo;
  * blocked domains;
  * an optional tenant allowlist;
  * IP-literal checks, including IPv4-mapped, 6to4, Teredo and NAT64 embeddings.
* A custom **network backend** for httpx2/httpcore2 resolves the host itself,
  requires **every** answer to be public and connects to that exact validated IP. The
  TLS SNI and Host header keep the hostname.
* Redirects are handled manually; each hop is validated again (max 3).
* Bodies are bounded, including a streaming decompressor with a ratio cap. There is a
  content-type allowlist, and `trust_env=False` ignores proxy variables.
* httpx2, the maintained fork shared with the Anthropic SDK, is the only HTTP client.
  Ruff bans importing `httpx`.

## Consequences
* DNS rebinding cannot redirect a fetch mid-flight inside the platform.
* Chromium would resolve names itself, so the browser service applies the same
  principle one level down: Chromium may only connect through an in-process
  **pinning egress proxy** (`apps/browser/egress_proxy.py`) that validates the
  target, resolves it once, requires every answer to be public and connects to
  exactly those addresses (HTTPS stays end-to-end through `CONNECT`). QUIC and
  non-proxied WebRTC UDP are disabled so nothing bypasses it. The per-request
  route guard remains as an early, cheaper rejection.
* The egress firewall in DEPLOYMENT.md is defence in depth, for a compromised
  container that no longer runs these guards.

## Alternatives considered
An egress proxy (Smokescreen-style) only; it is good as an extra layer and the
deployment guide recommends it for strict environments. URL-string validation only
was rejected as bypassable.
