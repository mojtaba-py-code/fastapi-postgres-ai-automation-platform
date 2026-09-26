// The organization at a glance: counts, change activity, open alerts and the
// latest changes - each only where the person's role may read it.

import { changeVolumeChart } from "../chart.js";
import { projectChoice } from "../choices.js";
import { formatNumber, humanize } from "../format.js";
import { href } from "../router.js";
import { badge, button, deferred, emptyState, h, link, mount, notice, pageHeader, section, select, table, time } from "../ui.js";

const PAGE = 200;

function countLabel(page) {
  return page.next_cursor ? `${formatNumber(page.items.length)}+` : formatNumber(page.items.length);
}

function statTile(label, value, note, target) {
  const body = [h("p", { class: "stat-label" }, label), h("p", { class: "stat-value" }, value), note && h("p", { class: "stat-note" }, note)];
  return target ? h("a", { class: "stat", href: target }, body) : h("div", { class: "stat" }, body);
}

function noOrganization(app) {
  const { context } = app;
  return h(
    "div",
    { class: "stack" },
    pageHeader("Welcome", { description: "This session does not reach an organization yet." }),
    context.blocked && notice(context.blocked.message, { kind: "warning" }),
    context.organizations.length
      ? section(
          "Your organizations",
          {},
          table(
            [
              { title: "Organization", render: (row) => row.name },
              { title: "Your role", render: (row) => badge(row.role, "neutral") },
              { title: "", class: "actions", render: (row) => (app.session.sso ? null : button("Open", () => app.switchOrganization(row.id), { kind: "primary" })) },
            ],
            context.organizations,
          ),
        )
      : emptyState("You are not a member of an organization.", "Ask an administrator to invite you, or create an account for a new organization."),
    link("Your account and security", href("/account"), { kind: "secondary" }),
  );
}

async function counts(app) {
  const requests = [];
  const tiles = [];
  if (app.can("projects:read")) {
    requests.push(app.api.get("/projects", { limit: PAGE }).then((page) => tiles.push(statTile("Projects", countLabel(page), null, href("/projects")))));
  }
  if (app.can("datasets:read")) {
    requests.push(app.api.get("/datasets", { limit: PAGE }).then((page) => tiles.push(statTile("Datasets", countLabel(page), null, href("/datasets")))));
  }
  if (app.can("sources:read")) {
    requests.push(
      app.api.get("/sources", { limit: PAGE }).then((page) => {
        const failing = page.items.filter((source) => source.status === "error" || source.consecutive_failures > 0).length;
        tiles.push(statTile("Sources", countLabel(page), failing ? `${formatNumber(failing)} failing` : "All healthy", href("/sources")));
      }),
    );
  }
  if (app.can("alerts:read")) {
    requests.push(app.api.get("/alerts", { status: "open", limit: PAGE }).then((page) => tiles.push(statTile("Open alerts", countLabel(page), null, href("/alerts", { status: "open" })))));
  }
  await Promise.all(requests);
  const order = ["Projects", "Datasets", "Sources", "Open alerts"];
  tiles.sort((a, b) => order.indexOf(a.querySelector(".stat-label").textContent) - order.indexOf(b.querySelector(".stat-label").textContent));
  return tiles;
}

function activity(app) {
  const body = h("div", { class: "stack" });
  const container = section("Change activity", { description: "Changes detected per day over the last 30 days." }, body);
  (async () => {
    const listed = (await app.api.get("/projects", { limit: PAGE })).items;
    if (!listed.length) {
      mount(body, emptyState("No projects yet.", "Create a project, add a dataset and a source; changes appear here."));
      return;
    }
    // Open on the project with the most datasets - the one most likely to have activity.
    const datasets = app.can("datasets:read") ? (await app.api.get("/datasets", { limit: PAGE })).items : [];
    const { projects, preferred } = projectChoice(listed, datasets);
    const chooser = select(projects.map((project) => [project.id, project.name]), { "aria-label": "Project", class: "input compact", value: preferred });
    const chart = h("div", { class: "chart-slot" });
    async function load() {
      chart.classList.add("refreshing"); // hold the previous render while the next loads
      try {
        const analytics = await app.api.get("/analytics/changes", { project_id: chooser.value });
        const totals = analytics.totals || {};
        mount(
          chart,
          h(
            "div",
            { class: "figures" },
            h("div", {}, h("p", { class: "stat-label" }, "Changes"), h("p", { class: "stat-value small" }, formatNumber(totals.changes ?? 0))),
            ["created", "updated", "deleted"].map((type) => h("div", {}, h("p", { class: "stat-label" }, humanize(type)), h("p", { class: "stat-value small" }, formatNumber(totals[type] ?? 0)))),
          ),
          changeVolumeChart(analytics.daily, { unusual: analytics.unusual_days, title: "Changes per day" }),
          analytics.trend_note && h("p", { class: "muted" }, analytics.trend_note),
        );
      } catch (error) {
        mount(chart, notice(error.message, { kind: "danger" }));
      } finally {
        chart.classList.remove("refreshing");
      }
    }
    chooser.addEventListener("change", load);
    mount(body, h("div", { class: "toolbar" }, chooser), chart);
    await load();
  })().catch((error) => mount(body, notice(error.message, { kind: "danger" })));
  return container;
}

export async function overviewPage(app) {
  const { context } = app;
  if (!context.organization) return noOrganization(app);

  const tiles = h("div", { class: "stats" });
  counts(app)
    .then((items) => mount(tiles, items))
    .catch(() => mount(tiles));

  return h(
    "div",
    { class: "stack" },
    pageHeader(context.organization.name, { description: `Your role: ${context.role}. Everything below is scoped to this organization.` }),
    context.organization.settings.automation_frozen && notice("Automation is frozen for this organization: scheduled work and outbound actions are paused.", { kind: "warning" }),
    tiles,
    app.can("changes:read") && app.can("projects:read") && activity(app),
    h(
      "div",
      { class: "columns" },
      app.can("alerts:read") &&
        section(
          "Open alerts",
          { actions: link("All alerts", href("/alerts"), { kind: "ghost" }) },
          deferred(
            () => app.api.get("/alerts", { status: "open", limit: 5 }),
            (page) =>
              table(
                [
                  { title: "Alert", render: (row) => row.title },
                  { title: "Severity", render: (row) => badge(row.severity) },
                  { title: "Raised", render: (row) => time(row.triggered_at) },
                ],
                page.items,
                { empty: "No open alerts." },
              ),
          ),
        ),
      app.can("changes:read") &&
        section(
          "Latest changes",
          {},
          deferred(
            () => app.api.get("/changes", { limit: 8 }),
            (page) =>
              table(
                [
                  { title: "Record", render: (row) => h("a", { href: href(`/datasets/${row.dataset_id}`) }, row.record_key) },
                  { title: "Change", render: (row) => badge(row.change_type, "neutral") },
                  { title: "Significance", render: (row) => badge(row.significance) },
                  { title: "Detected", render: (row) => time(row.detected_at) },
                ],
                page.items,
                { empty: "No changes detected yet." },
              ),
          ),
        ),
    ),
  );
}
