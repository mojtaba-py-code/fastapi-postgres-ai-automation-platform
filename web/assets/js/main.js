// The NexusFlow console: boots the session, reads an entry point (a link from
// an e-mail, the identity provider's redirect), then renders the page the URL
// fragment names inside the signed-in shell.

import { createApi } from "./api.js";
import { h, mount, svg } from "./dom.js";
import { permissionsFor } from "./permissions.js";
import { createMatcher, href, takeEntry } from "./router.js";
import { createSession } from "./session.js";
import { errorMessage, loading, notice, notify, showError } from "./ui.js";

import { forgotPasswordPage, signInPage, signUpPage } from "./pages/auth.js";
import { entryPage } from "./pages/entry.js";
import { overviewPage } from "./pages/overview.js";
import { projectsPage } from "./pages/projects.js";
import { datasetPage, datasetsPage } from "./pages/datasets.js";
import { sourcePage, sourcesPage } from "./pages/sources.js";
import { workflowsPage } from "./pages/workflows.js";
import { alertsPage } from "./pages/alerts.js";
import { alertRulesPage, channelsPage } from "./pages/alerting.js";
import { reportsPage } from "./pages/reports.js";
import { membersPage } from "./pages/members.js";
import { apiKeysPage } from "./pages/apikeys.js";
import { auditPage } from "./pages/audit.js";
import { integrationsPage } from "./pages/integrations.js";
import { organizationPage } from "./pages/organization.js";
import { ssoPage } from "./pages/sso.js";
import { accountPage } from "./pages/account.js";

const ROUTES = [
  { path: "/sign-in", page: signInPage, public: true, title: "Sign in" },
  { path: "/sign-up", page: signUpPage, public: true, title: "Create an account" },
  { path: "/forgot-password", page: forgotPasswordPage, public: true, title: "Reset your password" },
  { path: "/overview", page: overviewPage, title: "Overview" },
  { path: "/projects", page: projectsPage, permission: "projects:read", title: "Projects" },
  { path: "/datasets", page: datasetsPage, permission: "datasets:read", title: "Datasets" },
  { path: "/datasets/:id", page: datasetPage, permission: "datasets:read", title: "Dataset", nav: "/datasets" },
  { path: "/sources", page: sourcesPage, permission: "sources:read", title: "Sources" },
  { path: "/sources/:id", page: sourcePage, permission: "sources:read", title: "Source", nav: "/sources" },
  { path: "/workflows", page: workflowsPage, permission: "workflows:read", title: "Workflows" },
  { path: "/alerts", page: alertsPage, permission: "alerts:read", title: "Alerts" },
  { path: "/alert-rules", page: alertRulesPage, permission: "alerts:read", title: "Alert rules" },
  { path: "/reports", page: reportsPage, permission: "reports:read", title: "Reports" },
  { path: "/members", page: membersPage, permission: "members:read", title: "Members" },
  { path: "/api-keys", page: apiKeysPage, permission: "api_keys:manage", title: "API keys" },
  { path: "/audit", page: auditPage, permission: "audit:read", title: "Audit log" },
  { path: "/channels", page: channelsPage, permission: "channels:read", title: "Notification channels" },
  { path: "/integrations", page: integrationsPage, permission: "integrations:read", title: "Integrations" },
  { path: "/organization", page: organizationPage, permission: "org:update", title: "Organization settings" },
  { path: "/sso", page: ssoPage, permission: "org:update", title: "Single sign-on" },
  { path: "/account", page: accountPage, account: true, title: "Your account" },
];

const NAVIGATION = [
  { items: [{ label: "Overview", path: "/overview" }] },
  {
    group: "Data",
    items: [
      { label: "Projects", path: "/projects", permission: "projects:read" },
      { label: "Datasets", path: "/datasets", permission: "datasets:read" },
      { label: "Sources", path: "/sources", permission: "sources:read" },
      { label: "Workflows", path: "/workflows", permission: "workflows:read" },
      { label: "Alerts", path: "/alerts", permission: "alerts:read" },
      { label: "Alert rules", path: "/alert-rules", permission: "alerts:read" },
      { label: "Reports", path: "/reports", permission: "reports:read" },
    ],
  },
  {
    group: "Organization",
    items: [
      { label: "Members", path: "/members", permission: "members:read" },
      { label: "API keys", path: "/api-keys", permission: "api_keys:manage" },
      { label: "Audit log", path: "/audit", permission: "audit:read" },
      { label: "Channels", path: "/channels", permission: "channels:read" },
      { label: "Integrations", path: "/integrations", permission: "integrations:read" },
      { label: "Settings", path: "/organization", permission: "org:update" },
      { label: "Single sign-on", path: "/sso", permission: "org:update" },
    ],
  },
];

const match = createMatcher(ROUTES);
const root = document.getElementById("app");
const session = createSession();

// What the signed-in person may see: their account, organizations and role.
const context = {
  user: null,
  organizations: [],
  organization: null, // GET /organizations/current, when the session reaches one
  role: null,
  permissions: new Set(),
  blocked: null, // why the session cannot reach its organization (MFA, SSO, network)
  loaded: false,
  reset() {
    Object.assign(this, { user: null, organizations: [], organization: null, role: null, permissions: new Set(), blocked: null, loaded: false });
  },
};

const api = createApi({
  session,
  onSessionEnded: () => {
    context.reset();
    notify("Your session has ended. Sign in again.", { kind: "warning" });
    navigate("/sign-in");
  },
});

let intended = null; // where to go after signing in
let ticket = 0; // the latest render; older ones stop when they notice

function navigate(path, params) {
  const target = href(path, params);
  if (location.hash === target) {
    render();
  } else {
    location.hash = target;
  }
}

async function loadContext() {
  const [user, organizations] = await Promise.all([api.get("/users/me"), api.get("/organizations")]);
  context.user = user;
  context.organizations = organizations;
  const summary = organizations.find((organization) => organization.id === session.organizationId) || null;
  context.role = summary?.role ?? null;
  context.permissions = permissionsFor(context.role);
  context.organization = null;
  context.blocked = null;
  if (summary) {
    try {
      context.organization = await api.get("/organizations/current");
    } catch (error) {
      context.blocked = error; // the account still works (e.g. to set up MFA)
      context.permissions = new Set();
    }
  }
  context.loaded = true;
}

const app = {
  api,
  session,
  context,
  navigate,
  /** Render the current page again (after a change it shows). */
  refresh: () => render(),
  can: (permission) => context.permissions.has(permission),
  /** A completed sign-in: tokens in, the person's context loaded, on to where they were going. */
  async signedIn(tokens, { sso = false, persist = false } = {}) {
    session.start(tokens, { sso, persist });
    await loadContext();
    const target = intended || href("/overview");
    intended = null;
    if (location.hash === target) render();
    else location.hash = target;
  },
  async reloadContext() {
    await loadContext();
    render();
  },
  async switchOrganization(organizationId) {
    const tokens = await api.post("/auth/switch-organization", { organization_id: organizationId });
    session.rotate(tokens);
    await loadContext();
    navigate("/overview");
  },
  async signOut() {
    try {
      await api.post("/auth/logout");
    } catch {
      // signed out locally either way
    }
    session.end();
    context.reset();
    navigate("/sign-in");
  },
};

// ------------------------------------------------------------------ shell

function brandMark() {
  return svg(
    "svg",
    { class: "brand-mark", viewBox: "0 0 32 32", "aria-hidden": "true" },
    svg("rect", { width: 32, height: 32, rx: 7, fill: "#256abf" }),
    svg("path", { d: "M9 23V9l14 14V9", fill: "none", stroke: "#ffffff", "stroke-width": 3, "stroke-linecap": "round", "stroke-linejoin": "round" }),
  );
}

// A link to the page already shown reloads it, as people expect of a sidebar:
// the address does not change, so no hashchange would. A click that opens a
// new tab or window keeps its default.
function reloadIfCurrent(event) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  if (event.currentTarget.getAttribute("href") !== location.hash) return;
  event.preventDefault();
  render();
}

function sidebar(active) {
  return h(
    "nav",
    { class: "sidebar", "aria-label": "Main" },
    h("a", { class: "brand", href: href("/overview"), onClick: reloadIfCurrent }, brandMark(), h("span", {}, "NexusFlow")),
    NAVIGATION.map((group) => {
      const items = group.items.filter((item) => !item.permission || app.can(item.permission));
      if (!items.length) return null;
      return h(
        "div",
        { class: "nav-group" },
        group.group && h("p", { class: "nav-heading" }, group.group),
        h("ul", {}, items.map((item) => h("li", {}, h("a", { href: href(item.path), class: ["nav-link", active === item.path && "active"], "aria-current": active === item.path ? "page" : null, onClick: reloadIfCurrent }, item.label)))),
      );
    }),
  );
}

function organizationSwitcher() {
  const current = context.organizations.find((organization) => organization.id === session.organizationId);
  if (session.sso || context.organizations.length < 2) {
    return h("span", { class: "org-name" }, current?.name ?? "No organization");
  }
  const control = h("select", { class: "input org-select", "aria-label": "Organization" });
  if (!current) control.append(h("option", { value: "", selected: true }, "Choose an organization"));
  for (const organization of context.organizations) {
    control.append(h("option", { value: organization.id, selected: organization.id === current?.id }, organization.name));
  }
  control.addEventListener("change", async () => {
    try {
      await app.switchOrganization(control.value);
    } catch (error) {
      showError(error);
      control.value = current?.id ?? "";
    }
  });
  return control;
}

function userMenu() {
  const user = context.user;
  return h(
    "details",
    { class: "user-menu" },
    h("summary", { "aria-label": "Your account" }, h("span", { class: "avatar", "aria-hidden": "true" }, (user?.full_name || user?.email || "?").trim().charAt(0).toUpperCase()), h("span", { class: "user-name" }, user?.full_name || user?.email)),
    h(
      "div",
      { class: "user-menu-panel" },
      h("p", { class: "user-email" }, user?.email),
      context.role && h("p", { class: "muted" }, `Role: ${context.role}`),
      session.sso && h("p", { class: "muted" }, "Signed in through single sign-on"),
      h("a", { href: href("/account") }, "Your account"),
      h("button", { type: "button", class: "link-button", onClick: () => app.signOut() }, "Sign out"),
    ),
  );
}

function shell(active, content) {
  const menuToggle = h("button", { class: "menu-toggle button button-ghost", type: "button", "aria-label": "Menu", "aria-expanded": "false" }, "☰");
  const layout = h(
    "div",
    { class: "shell" },
    sidebar(active),
    h(
      "div",
      { class: "main-column" },
      h("header", { class: "topbar" }, menuToggle, organizationSwitcher(), h("div", { class: "topbar-spacer" }), userMenu()),
      context.blocked && h("div", { class: "blocked" }, notice(errorMessage(context.blocked), { kind: "warning", title: "This organization is not available to this session." })),
      h("main", { id: "main", class: "content", tabindex: "-1" }, content),
    ),
  );
  menuToggle.addEventListener("click", () => {
    const open = layout.classList.toggle("nav-open");
    menuToggle.setAttribute("aria-expanded", String(open));
  });
  return layout;
}

function publicLayout(content) {
  return h(
    "div",
    { class: "public" },
    h("div", { class: "public-brand" }, brandMark(), h("span", {}, "NexusFlow")),
    h("main", { id: "main", class: "public-card", tabindex: "-1" }, content),
    h("p", { class: "public-footer muted" }, "NexusFlow AI · secure business automation"),
  );
}

function focusHeading() {
  const heading = root.querySelector("h1");
  (heading || root.querySelector("main"))?.focus({ preventScroll: false });
}

// ------------------------------------------------------------------ rendering

async function render() {
  const current = ++ticket;
  const found = match(location.hash);
  if (!found) {
    navigate(session.signedIn ? "/overview" : "/sign-in");
    return;
  }
  const { route, params, query } = found;
  document.title = `${route.title} · NexusFlow`;

  if (route.public) {
    if (session.signedIn && context.loaded) {
      navigate("/overview");
      return;
    }
    mount(root, publicLayout(await route.page(app, { params, query })));
    focusHeading();
    return;
  }
  if (!session.signedIn) {
    intended = location.hash;
    navigate("/sign-in");
    return;
  }
  if (!context.loaded) {
    mount(root, publicLayout(loading("Signing you in…")));
    try {
      await loadContext();
    } catch (error) {
      if (current !== ticket) return;
      mount(root, publicLayout(notice(errorMessage(error), { kind: "danger" })));
      return;
    }
    if (current !== ticket) return;
  }
  const active = route.nav || route.path;
  if (route.permission && !app.can(route.permission)) {
    mount(root, shell(active, notice("Your role in this organization does not include this page.", { kind: "warning", title: "Not available." })));
    focusHeading();
    return;
  }
  mount(root, shell(active, loading()));
  let content;
  try {
    content = await route.page(app, { params, query });
  } catch (error) {
    content = notice(errorMessage(error), { kind: "danger" });
  }
  if (current !== ticket) return;
  mount(root.querySelector("#main"), content);
  focusHeading();
}

async function boot() {
  const entry = takeEntry();
  if (entry) {
    // An e-mail link or the identity provider's redirect: its own page, once.
    mount(root, publicLayout(await entryPage(app, entry)));
    focusHeading();
    window.addEventListener("hashchange", render);
    return;
  }
  const stored = session.stored();
  if (stored) {
    session.resume(stored);
    try {
      await api.refresh();
    } catch {
      session.end();
    }
  }
  window.addEventListener("hashchange", render);
  await render();
}

boot().catch((error) => {
  mount(root, publicLayout(notice(errorMessage(error), { kind: "danger" })));
});
