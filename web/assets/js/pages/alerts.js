// Alerts raised by the organization's alert rules.

import { href } from "../router.js";
import { badge, button, h, notify, pageHeader, pagedTable, section, time } from "../ui.js";

const STATUSES = [
  ["open", "Open"],
  ["acknowledged", "Acknowledged"],
  ["resolved", "Resolved"],
  ["", "All"],
];

export function alertsPage(app, { query }) {
  const status = ["open", "acknowledged", "resolved", "all"].includes(query.status) ? query.status : "open";
  const canAck = app.can("alerts:ack");

  const act = (alert, resolve) =>
    button(resolve ? "Resolve" : "Acknowledge", async () => {
      await app.api.post(`/alerts/${alert.id}/acknowledge`, { resolve });
      notify(`${alert.title}: ${resolve ? "resolved" : "acknowledged"}.`, { kind: "success" });
      app.refresh();
    }, { kind: resolve ? "secondary" : "ghost" });

  const list = pagedTable(
    [
      {
        title: "Alert",
        render: (row) =>
          h("details", { class: "alert-body" }, h("summary", {}, row.title), h("p", { class: "pre-line" }, row.body)),
      },
      { title: "Severity", render: (row) => badge(row.severity) },
      { title: "Status", render: (row) => badge(row.status) },
      { title: "Raised", render: (row) => time(row.triggered_at) },
      {
        title: "",
        class: "actions",
        render: (row) =>
          canAck && row.status !== "resolved"
            ? h("div", { class: "button-row" }, row.status === "open" && act(row, false), act(row, true))
            : null,
      },
    ],
    (cursor) => app.api.get("/alerts", { status: status === "all" ? null : status, limit: 50, cursor }),
    { empty: status === "open" ? "No open alerts. All quiet." : "No alerts here." },
  );

  return h(
    "div",
    { class: "stack" },
    pageHeader("Alerts", { description: "Raised by alert rules when changes or runs match their conditions. Sensitive values are masked." }),
    h(
      "nav",
      { class: "tabs", "aria-label": "Alert status" },
      STATUSES.map(([value, label]) => {
        const key = value || "all";
        return h("a", { href: href("/alerts", { status: key }), class: ["tab", status === key && "active"], "aria-current": status === key ? "page" : null }, label);
      }),
    ),
    section(null, {}, list),
  );
}
