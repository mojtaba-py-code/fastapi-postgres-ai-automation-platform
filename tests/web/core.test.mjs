// The console's logic outside the DOM: WebAuthn conversions, routing, the
// session store and the API client (token refresh, errors, no cookies).

import assert from "node:assert/strict";
import { test } from "node:test";

import { ApiError, attachmentName, createApi } from "../../web/assets/js/api.js";
import { createMatcher, ENTRY_PATHS, href, takeEntry } from "../../web/assets/js/router.js";
import { createSession } from "../../web/assets/js/session.js";
import {
  assertionJSON,
  creationOptions,
  fromBase64Url,
  registrationJSON,
  requestOptions,
  toBase64Url,
} from "../../web/assets/js/webauthn.js";
import { dayBoundary, formatBytes, humanize } from "../../web/assets/js/format.js";

const bytes = (...values) => new Uint8Array(values).buffer;

// ------------------------------------------------------------------ WebAuthn

test("base64url round-trips every byte value, unpadded", () => {
  const all = new Uint8Array(256).map((_, index) => index);
  const text = toBase64Url(all.buffer);
  assert.match(text, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(new Uint8Array(fromBase64Url(text)), all);
  assert.equal(toBase64Url(bytes(0xfb, 0xff)), "-_8");
  assert.deepEqual(new Uint8Array(fromBase64Url("-_8")), new Uint8Array([0xfb, 0xff]));
  assert.throws(() => fromBase64Url("not base64!"), TypeError);
  assert.throws(() => fromBase64Url("+/=="), TypeError); // standard base64 is refused
});

test("creation options: binary members become ArrayBuffers", () => {
  const options = creationOptions({
    rp: { id: "console.example.com", name: "NexusFlow" },
    user: { id: "AQID", name: "alice@example.com", displayName: "Alice" },
    challenge: "BAUG",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { alg: -8 }],
    timeout: 300000,
    excludeCredentials: [{ type: "public-key", id: "Bwg", transports: ["usb"] }],
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    attestation: "none",
  });
  assert.deepEqual(new Uint8Array(options.user.id), new Uint8Array([1, 2, 3]));
  assert.deepEqual(new Uint8Array(options.challenge), new Uint8Array([4, 5, 6]));
  assert.deepEqual(new Uint8Array(options.excludeCredentials[0].id), new Uint8Array([7, 8]));
  assert.deepEqual(options.excludeCredentials[0].transports, ["usb"]);
  assert.deepEqual(options.pubKeyCredParams, [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }]);
  assert.equal(options.authenticatorSelection.userVerification, "required");
});

test("request options: user verification stays required by default", () => {
  const options = requestOptions({ challenge: "AA", timeout: 60000, rpId: "console.example.com", allowCredentials: [{ id: "AQ" }] });
  assert.equal(options.userVerification, "required");
  assert.deepEqual(new Uint8Array(options.allowCredentials[0].id), new Uint8Array([1]));
  assert.equal(options.allowCredentials[0].type, "public-key");
  assert.equal(options.allowCredentials[0].transports, undefined);
});

test("a new credential serialises to the API's registration form", () => {
  const credential = {
    id: "Bwg",
    rawId: bytes(7, 8),
    type: "public-key",
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({ credProps: { rk: true } }),
    response: {
      clientDataJSON: bytes(1),
      attestationObject: bytes(2),
      getTransports: () => ["internal", "hybrid"],
      getAuthenticatorData: () => bytes(3),
      getPublicKey: () => null, // an algorithm the browser cannot export
      getPublicKeyAlgorithm: () => -8,
    },
  };
  assert.deepEqual(registrationJSON(credential), {
    id: "Bwg",
    rawId: "Bwg",
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: { credProps: { rk: true } },
    response: {
      clientDataJSON: "AQ",
      attestationObject: "Ag",
      transports: ["internal", "hybrid"],
      authenticatorData: "Aw",
      publicKey: null,
      publicKeyAlgorithm: -8,
    },
  });
});

test("an assertion serialises to the API's sign-in form; an empty user handle is null", () => {
  const credential = {
    id: "AQ",
    rawId: bytes(1),
    type: "public-key",
    response: { clientDataJSON: bytes(9), authenticatorData: bytes(8), signature: bytes(7), userHandle: bytes() },
  };
  const json = assertionJSON(credential);
  assert.equal(json.authenticatorAttachment, null);
  assert.deepEqual(json.clientExtensionResults, {});
  assert.deepEqual(json.response, { clientDataJSON: "CQ", authenticatorData: "CA", signature: "Bw", userHandle: null });
});

// ------------------------------------------------------------------ routing

test("routes match with decoded parameters and a query", () => {
  const match = createMatcher([{ path: "/overview" }, { path: "/datasets/:id" }, { path: "/datasets" }]);
  assert.equal(match("#/overview").route.path, "/overview");
  const found = match("#/datasets/a%2Fb?tab=records&cursor=xyz");
  assert.equal(found.route.path, "/datasets/:id");
  assert.deepEqual(found.params, { id: "a/b" });
  assert.deepEqual(found.query, { tab: "records", cursor: "xyz" });
  assert.equal(match("#/datasets").route.path, "/datasets");
  assert.equal(match("#/nowhere"), null);
  assert.equal(match("#/datasets/1/extra"), null);
  assert.equal(match(""), null);
});

test("href builds fragments and drops empty parameters", () => {
  assert.equal(href("/audit", { action: "auth.login", cursor: "", result: null }), "#/audit?action=auth.login");
  assert.equal(href("/overview"), "#/overview");
});

test("an entry point is read once and wiped from the address bar", () => {
  const replaced = [];
  const history = { replaceState: (_state, _title, url) => replaced.push(url) };
  const entry = takeEntry({ pathname: "/complete-signup", hash: "#token=s3cr3t", search: "" }, history);
  assert.deepEqual([entry.path, entry.token], ["/complete-signup", "s3cr3t"]);
  assert.deepEqual(replaced, ["/"]);
  const sso = takeEntry({ pathname: "/sso/callback", hash: "", search: "?code=c0de&state=st4te" }, history);
  assert.deepEqual([sso.code, sso.state, sso.token], ["c0de", "st4te", null]);
  assert.equal(takeEntry({ pathname: "/", hash: "#/overview", search: "" }, history), null);
  assert.equal(replaced.length, 2);
  assert.deepEqual([...ENTRY_PATHS], ["/complete-signup", "/reset-password", "/accept-invitation", "/sso/callback"]);
});

// ------------------------------------------------------------------ session

function memoryStorage() {
  const items = new Map();
  return {
    items,
    getItem: (key) => (items.has(key) ? items.get(key) : null),
    setItem: (key, value) => items.set(key, String(value)),
    removeItem: (key) => items.delete(key),
  };
}

const TOKENS = { access_token: "a1", refresh_token: "r1", expires_in: 600, organization_id: "org-1" };

test("tokens stay in memory unless the person asked to stay signed in", () => {
  const storage = memoryStorage();
  const session = createSession({ storage, now: () => 0 });
  session.start(TOKENS);
  assert.equal(session.accessToken, "a1");
  assert.equal(storage.items.size, 0);
  session.start(TOKENS, { persist: true, sso: true });
  const kept = [...storage.items.values()].join("");
  assert.match(kept, /r1/);
  assert.doesNotMatch(kept, /a1/, "never the access token");
  session.rotate({ ...TOKENS, access_token: "a2", refresh_token: "r2" });
  assert.deepEqual(session.stored(), { refresh: "r2", sso: true });
  session.end();
  assert.equal(storage.items.size, 0);
  assert.equal(session.signedIn, false);
});

test("expiry is judged with a margin", () => {
  let now = 0;
  const session = createSession({ storage: memoryStorage(), now: () => now });
  assert.equal(session.expiresSoon(), true);
  session.start(TOKENS); // 600 s
  assert.equal(session.expiresSoon(), false);
  now = 571_000;
  assert.equal(session.expiresSoon(), true);
});

// ------------------------------------------------------------------ API client

function fakeFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init, body: init.body ? JSON.parse(init.body) : undefined });
    const [status, body, headers = {}] = await handler(url, init, calls.length);
    return new Response(status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json", ...headers },
    });
  };
  return { calls, fetchImpl };
}

test("requests carry the bearer token and never cookies", async () => {
  const session = createSession({ storage: memoryStorage() });
  session.start(TOKENS);
  const { calls, fetchImpl } = fakeFetch(() => [200, { id: "u1" }]);
  const api = createApi({ session, fetchImpl });
  assert.deepEqual(await api.get("/users/me", { limit: 5, cursor: null }), { id: "u1" });
  assert.equal(calls[0].url, "/api/v1/users/me?limit=5");
  assert.equal(calls[0].init.headers.Authorization, "Bearer a1");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.cache, "no-store");
});

test("an expired access token is refreshed once for concurrent requests", async () => {
  let now = 0;
  const session = createSession({ storage: memoryStorage(), now: () => now });
  session.start(TOKENS);
  now = 599_000; // about to expire
  const { calls, fetchImpl } = fakeFetch((url) => {
    if (url.endsWith("/auth/refresh")) return [200, { ...TOKENS, access_token: "a2", refresh_token: "r2" }];
    return [200, { ok: true }];
  });
  const api = createApi({ session, fetchImpl });
  await Promise.all([api.get("/projects"), api.get("/datasets"), api.get("/sources")]);
  const refreshes = calls.filter((call) => call.url.endsWith("/auth/refresh"));
  assert.equal(refreshes.length, 1);
  assert.deepEqual(refreshes[0].body, { refresh_token: "r1" });
  assert.equal(refreshes[0].init.headers.Authorization, undefined, "refresh is not bearer-authenticated");
  for (const call of calls.filter((c) => !c.url.endsWith("/auth/refresh"))) {
    assert.equal(call.init.headers.Authorization, "Bearer a2");
  }
});

test("a 401 is retried after one refresh; a refused refresh ends the session", async () => {
  const session = createSession({ storage: memoryStorage(), now: () => 0 });
  session.start(TOKENS);
  let ended = null;
  const { calls, fetchImpl } = fakeFetch((url) => {
    if (url.endsWith("/auth/refresh")) return [401, { error: "invalid_token", message: "Invalid or expired credentials." }];
    return [401, { error: "invalid_token", message: "Invalid or expired credentials." }];
  });
  const api = createApi({ session, fetchImpl, onSessionEnded: (error) => (ended = error) });
  await assert.rejects(api.get("/users/me"), (error) => error instanceof ApiError && error.code === "invalid_token");
  assert.equal(calls.length, 2); // the request, then one refresh - no loop
  assert.equal(session.signedIn, false);
  assert.equal(ended.code, "invalid_token");
});

test("errors keep the API's code, request id, details and Retry-After", async () => {
  const session = createSession({ storage: memoryStorage(), now: () => 0 });
  session.start(TOKENS);
  const { fetchImpl } = fakeFetch(() => [
    429,
    { error: "rate_limited", message: "Too many requests; slow down.", request_id: "r-1", details: null },
    { "Retry-After": "12" },
  ]);
  const api = createApi({ session, fetchImpl });
  await assert.rejects(api.post("/reports", { format: "pdf" }), (error) => {
    assert.equal(error.status, 429);
    assert.equal(error.code, "rate_limited");
    assert.equal(error.requestId, "r-1");
    assert.equal(error.retryAfter, "12");
    return true;
  });
});

test("an unreachable service is a network error, not an exception from fetch", async () => {
  const session = createSession({ storage: memoryStorage() });
  const api = createApi({
    session,
    fetchImpl: async () => {
      throw new TypeError("Failed to fetch");
    },
  });
  await assert.rejects(api.post("/auth/login", { email: "a@b.c", password: "x" }, { auth: false }), (error) => error.code === "network_error" && error.status === 0);
});

test("attachment names come from Content-Disposition and cannot carry paths", () => {
  assert.equal(attachmentName('attachment; filename="report.pdf"'), "report.pdf");
  assert.equal(attachmentName("attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.csv"), "résumé.csv");
  assert.equal(attachmentName('attachment; filename="../../etc/passwd"'), ".._.._etc_passwd");
  assert.equal(attachmentName(null, "export.jsonl"), "export.jsonl");
});

// ------------------------------------------------------------------ formatting

test("formatting helpers", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(null), "—");
  assert.equal(humanize("api_keys:manage"), "Api keys: manage");
  assert.equal(dayBoundary("2026-09-26"), "2026-09-26T00:00:00Z");
  assert.equal(dayBoundary("2026-09-26", true), "2026-09-26T23:59:59Z");
  assert.equal(dayBoundary("26/09/2026"), null);
});
