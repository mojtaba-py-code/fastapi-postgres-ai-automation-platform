// Routing. The app's pages live in the URL fragment (#/datasets/…), so the edge
// serves one document for them all. Four real paths are entry points that
// e-mails and identity providers send people to; the edge serves the same
// document there, and the console handles them once, then leaves them.

/** Paths the platform links to from outside (e-mails, the identity provider). */
export const ENTRY_PATHS = Object.freeze([
  "/complete-signup",
  "/reset-password",
  "/accept-invitation",
  "/sso/callback",
]);

function compile(pattern) {
  const names = [];
  const source = pattern
    .split("/")
    .map((part) => {
      if (part.startsWith(":")) {
        names.push(part.slice(1));
        return "([^/]+)";
      }
      return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("/");
  return { regex: new RegExp(`^${source}$`), names };
}

/**
 * Build a matcher for ``routes`` (``[{path: "/datasets/:id", ...}]``). It takes
 * a fragment such as ``#/datasets/42?tab=records`` and returns
 * ``{route, params, query}`` - or ``null`` when nothing matches.
 */
export function createMatcher(routes) {
  const compiled = routes.map((route) => ({ route, ...compile(route.path) }));
  return function match(hash) {
    const raw = (hash || "").replace(/^#/, "") || "/";
    const [path, search = ""] = raw.split("?", 2);
    for (const { route, regex, names } of compiled) {
      const found = regex.exec(path);
      if (!found) continue;
      const params = {};
      names.forEach((name, index) => {
        try {
          params[name] = decodeURIComponent(found[index + 1]);
        } catch {
          params[name] = found[index + 1];
        }
      });
      return { route, params, query: Object.fromEntries(new URLSearchParams(search)) };
    }
    return null;
  };
}

/** ``#/path?query`` for a route path and query parameters. */
export function href(path, params = {}) {
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(name, String(value));
  }
  const text = search.toString();
  return `#${path}${text ? `?${text}` : ""}`;
}

/** Read and forget the entry point this page was opened on (its token or code). */
export function takeEntry(location = globalThis.location, history = globalThis.history) {
  const path = location.pathname.replace(/\/+$/, "") || "/";
  if (!ENTRY_PATHS.includes(path)) return null;
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ""));
  const search = new URLSearchParams(location.search);
  const entry = {
    path,
    token: fragment.get("token"),
    code: search.get("code"),
    state: search.get("state"),
    error: search.get("error"),
    errorDescription: search.get("error_description"),
  };
  // Out of the address bar and the history at once: a token or an
  // authorization code must not linger where others (or a Back) can find it.
  history.replaceState(null, "", "/");
  return entry;
}
