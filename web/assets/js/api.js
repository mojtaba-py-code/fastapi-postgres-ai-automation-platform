// The console's only way to the platform: same-origin requests to /api/v1 with
// the session's bearer token. No cookies are ever sent (credentials: "omit"), so
// there is nothing for another site to ride on.

export class ApiError extends Error {
  constructor(status, body = {}, retryAfter = null) {
    super(body.message || (status ? `The request failed (HTTP ${status}).` : "The service could not be reached."));
    this.name = "ApiError";
    this.status = status;
    this.code = body.error || (status ? "http_error" : "network_error");
    this.details = Array.isArray(body.details) ? body.details : null;
    this.requestId = body.request_id || null;
    this.retryAfter = retryAfter;
  }
}

function query(params) {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(name, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

/** The file name of an attachment, from ``Content-Disposition`` (RFC 6266). */
export function attachmentName(header, fallback = "download") {
  if (!header) return fallback;
  const extended = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(header);
  if (extended) {
    try {
      return sanitizeName(decodeURIComponent(extended[1].trim()), fallback);
    } catch {
      // fall through to the plain parameter
    }
  }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(header);
  return plain ? sanitizeName(plain[1].trim(), fallback) : fallback;
}

function sanitizeName(name, fallback) {
  const cleaned = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").slice(0, 200);
  return cleaned || fallback;
}

export function createApi({ session, fetchImpl = globalThis.fetch.bind(globalThis), base = "/api/v1", onSessionEnded = () => {} }) {
  let refreshing = null;

  async function send(method, path, { body, form, params, auth = true, headers = {} } = {}) {
    const init = {
      method,
      headers: { Accept: "application/json", ...headers },
      credentials: "omit",
      cache: "no-store",
      mode: "same-origin",
      redirect: "error",
    };
    if (form) {
      init.body = form; // the browser sets the multipart boundary
    } else if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    if (auth && session.accessToken) init.headers.Authorization = `Bearer ${session.accessToken}`;
    try {
      return await fetchImpl(`${base}${path}${query(params)}`, init);
    } catch {
      throw new ApiError(0);
    }
  }

  async function failure(response) {
    let body = {};
    try {
      body = await response.json();
    } catch {
      // not the API's JSON (an edge error page, say): status only
    }
    return new ApiError(response.status, body, response.headers.get("Retry-After"));
  }

  /** Rotate the tokens once, however many requests are waiting for it. */
  function refresh() {
    if (!refreshing) {
      refreshing = (async () => {
        const token = session.refreshToken;
        if (!token) throw new ApiError(401, { error: "invalid_token", message: "Sign in again." });
        const response = await send("POST", "/auth/refresh", { body: { refresh_token: token }, auth: false });
        if (!response.ok) throw await failure(response);
        session.rotate(await response.json());
      })().finally(() => {
        refreshing = null;
      });
    }
    return refreshing;
  }

  async function authorized(method, path, options) {
    if (options.auth !== false && session.refreshToken && session.expiresSoon()) {
      await refreshOrEnd();
    }
    let response = await send(method, path, options);
    if (response.status === 401 && options.auth !== false && session.refreshToken) {
      await refreshOrEnd();
      response = await send(method, path, options);
    }
    return response;
  }

  async function refreshOrEnd() {
    try {
      await refresh();
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
        session.end();
        onSessionEnded(error);
      }
      throw error;
    }
  }

  async function request(method, path, options = {}) {
    const response = await authorized(method, path, options);
    if (!response.ok) throw await failure(response);
    if (response.status === 204) return null;
    const type = response.headers.get("Content-Type") || "";
    return type.includes("json") ? response.json() : response.text();
  }

  /** Fetch an attachment with the session's token and hand it to the browser as a file. */
  async function download(path, params) {
    const response = await authorized("GET", path, { params, headers: { Accept: "*/*" } });
    if (!response.ok) throw await failure(response);
    const blob = await response.blob();
    const name = attachmentName(response.headers.get("Content-Disposition"));
    const url = URL.createObjectURL(blob);
    try {
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.rel = "noopener";
      document.body.append(link);
      link.click();
      link.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    }
    return name;
  }

  return {
    request,
    download,
    refresh: refreshOrEnd,
    get: (path, params, options = {}) => request("GET", path, { ...options, params }),
    post: (path, body, options = {}) => request("POST", path, { ...options, body }),
    put: (path, body, options = {}) => request("PUT", path, { ...options, body }),
    patch: (path, body, options = {}) => request("PATCH", path, { ...options, body }),
    delete: (path, options = {}) => request("DELETE", path, options),
    upload: (path, file, options = {}) => {
      const form = new FormData();
      form.append("file", file);
      return request("POST", path, { ...options, form });
    },
  };
}
