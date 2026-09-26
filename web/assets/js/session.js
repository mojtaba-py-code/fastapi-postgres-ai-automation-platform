// The signed-in session: tokens in memory. Only when the person asks to stay
// signed in does the refresh token (never the access token) go to this tab's
// sessionStorage - gone when the tab closes, and removed at sign-out. Refresh
// tokens rotate on every use, and reusing a spent one ends the whole session.

const STORE_KEY = "nexusflow.console.session";

/** sessionStorage, or an in-memory stand-in where it is unavailable. */
export function tabStorage() {
  try {
    const storage = globalThis.sessionStorage;
    const probe = "nexusflow.console.probe";
    storage.setItem(probe, "1");
    storage.removeItem(probe);
    return storage;
  } catch {
    const items = new Map();
    return {
      getItem: (key) => (items.has(key) ? items.get(key) : null),
      setItem: (key, value) => items.set(key, String(value)),
      removeItem: (key) => items.delete(key),
    };
  }
}

export function createSession({ storage = tabStorage(), now = () => Date.now() } = {}) {
  let tokens = null; // {access, refresh, expiresAt, organizationId}
  let sso = false;
  let persist = false;
  const listeners = new Set();

  function save() {
    if (persist && tokens) {
      storage.setItem(STORE_KEY, JSON.stringify({ refresh: tokens.refresh, sso }));
    } else {
      storage.removeItem(STORE_KEY);
    }
  }

  function accept(response) {
    if (!response?.access_token || !response?.refresh_token) {
      throw new Error("The sign-in answer has no tokens");
    }
    tokens = {
      access: response.access_token,
      refresh: response.refresh_token,
      expiresAt: now() + Number(response.expires_in || 0) * 1000,
      organizationId: response.organization_id ?? null,
    };
  }

  const session = {
    get signedIn() {
      return tokens !== null;
    },
    get accessToken() {
      return tokens?.access ?? null;
    },
    get refreshToken() {
      return tokens?.refresh ?? null;
    },
    get organizationId() {
      return tokens?.organizationId ?? null;
    },
    /** Opened by an organization's identity provider (bound to that organization). */
    get sso() {
      return sso;
    },
    get persist() {
      return persist;
    },
    /** Whether the access token expires within ``marginMs`` (or there is none). */
    expiresSoon(marginMs = 30_000) {
      return !tokens || tokens.expiresAt - now() < marginMs;
    },
    /** A new sign-in: ``options.sso`` for a single sign-on, ``options.persist`` to stay signed in in this tab. */
    start(response, options = {}) {
      sso = Boolean(options.sso);
      persist = Boolean(options.persist);
      accept(response);
      save();
      notify();
    },
    /** Rotated tokens for the same session (refresh, organization switch, password change). */
    rotate(response) {
      accept(response);
      save();
      notify();
    },
    /** What an earlier page load of this tab kept: ``{refresh, sso}`` or ``null``. */
    stored() {
      try {
        const value = JSON.parse(storage.getItem(STORE_KEY) ?? "null");
        return value && typeof value.refresh === "string" ? { refresh: value.refresh, sso: Boolean(value.sso) } : null;
      } catch {
        return null;
      }
    },
    /** Resume from what this tab kept (the caller refreshes at once). */
    resume(stored) {
      tokens = { access: null, refresh: stored.refresh, expiresAt: 0, organizationId: null };
      sso = stored.sso;
      persist = true;
    },
    end() {
      tokens = null;
      sso = false;
      persist = false;
      storage.removeItem(STORE_KEY);
      notify();
    },
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };

  function notify() {
    for (const listener of listeners) listener(session);
  }

  return session;
}
