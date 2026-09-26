// The organization's audit trail: every security-relevant action, hash-chained.

import { dayBoundary, formatNumber } from "../format.js";
import { badge, button, code, definitionList, field, form, h, infoDialog, input, jsonBlock, mount, notice, pageHeader, pagedTable, section, select, time } from "../ui.js";

const RESULTS = [
  ["", "Any result"],
  ["success", "Success"],
  ["failure", "Failure"],
  ["denied", "Denied"],
];

async function memberNames(app) {
  if (!app.can("members:read")) return new Map();
  const names = new Map();
  let cursor = null;
  for (let page = 0; page < 5; page += 1) {
    const result = await app.api.get("/organizations/current/members", { limit: 200, cursor });
    for (const member of result.items) names.set(member.user_id, member.email);
    cursor = result.next_cursor;
    if (!cursor) break;
  }
  return names;
}

function actorLabel(entry, names) {
  if (!entry.actor_id) return h("span", { class: "muted" }, entry.actor_type);
  const name = entry.actor_type === "user" ? names.get(entry.actor_id) : null;
  return h("span", { title: entry.actor_id }, name || `${entry.actor_type} ${entry.actor_id.slice(0, 8)}`);
}

function details(entry, names) {
  infoDialog(
    entry.action,
    h(
      "div",
      { class: "stack" },
      definitionList([
        ["When", time(entry.occurred_at, { relative: false })],
        ["Sequence", formatNumber(entry.seq)],
        ["Actor", h("span", {}, actorLabel(entry, names), " (", entry.actor_type, ")")],
        ["Result", badge(entry.result)],
        ["Resource", entry.resource_type ? h("span", {}, entry.resource_type, " ", code(entry.resource_id || "")) : "—"],
        ["Address", entry.ip || "—"],
        ["Browser", entry.user_agent || "—"],
        ["Request", entry.request_id ? code(entry.request_id) : "—"],
      ]),
      h("h3", {}, "Details"),
      jsonBlock(entry.metadata),
    ),
  );
}

export async function auditPage(app, { query }) {
  const names = await memberNames(app);
  const verification = h("div", { class: "verification" });

  const filters = form(
    {
      submitLabel: "Filter",
      submitKind: "secondary",
      className: "form-inline filters",
      onSubmit: async (values) => {
        app.navigate("/audit", { action: values.action.trim(), result: values.result, since: values.since, until: values.until });
      },
    },
    field("Action", input({ name: "action", value: query.action || "", placeholder: "e.g. auth.login.failed", spellcheck: "false" })),
    field("Result", select(RESULTS, { name: "result", value: query.result || "" })),
    field("From", input({ name: "since", type: "date", value: query.since || "" })),
    field("To", input({ name: "until", type: "date", value: query.until || "" })),
  );

  const list = pagedTable(
    [
      { title: "When", render: (row) => time(row.occurred_at) },
      { title: "Action", render: (row) => code(row.action) },
      { title: "Actor", render: (row) => actorLabel(row, names) },
      { title: "Result", render: (row) => badge(row.result) },
      { title: "Address", render: (row) => row.ip || "—" },
      { title: "", class: "actions", render: (row) => button("Details", () => details(row, names), { kind: "ghost" }) },
    ],
    (cursor) =>
      app.api.get("/audit", {
        action: query.action || null,
        result: query.result || null,
        since: dayBoundary(query.since),
        until: dayBoundary(query.until, true),
        limit: 50,
        cursor,
      }),
    { empty: "No entries match." },
  );

  return h(
    "div",
    { class: "stack" },
    pageHeader("Audit log", {
      description: "Append-only and hash-chained: each entry seals the one before it, so a changed or deleted entry breaks the chain.",
      actions: button("Verify the chain", async () => {
        const result = await app.api.get("/audit/verify");
        mount(
          verification,
          result.ok
            ? notice(`The chain is intact: ${formatNumber(result.checked)} entries verified${result.complete ? "" : " (the most recent part)"}.`, { kind: "success" })
            : notice(`The chain is broken at entry ${result.first_invalid_seq}: ${result.reason}. Treat this as a security incident.`, { kind: "danger" }),
        );
      }),
    }),
    verification,
    section(null, {}, filters, list),
  );
}
