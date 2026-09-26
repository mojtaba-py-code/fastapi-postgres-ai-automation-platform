// Workflows: scheduled collection -> detection -> analysis -> alerting.

import { formatNumber, humanize } from "../format.js";
import { badge, button, h, infoDialog, notify, pageHeader, pagedTable, promptDialog, section, table, time } from "../ui.js";

function idempotencyKey() {
  return `console:${crypto.randomUUID()}`;
}

async function changeStatus(app, workflow, status) {
  let reason = null;
  if (status === "disabled") {
    reason = await promptDialog({
      title: `Stop ${workflow.name}?`,
      message: "An emergency stop: the workflow stops at once and stays off until someone activates it again.",
      label: "Reason (recorded in the audit log)",
      confirmLabel: "Stop it",
      danger: true,
    });
    if (reason === null) return;
  }
  await app.api.post(`/workflows/${workflow.id}/status`, { status, reason });
  notify(`${workflow.name}: ${status}.`, { kind: "success" });
  app.refresh();
}

async function showRuns(app, workflow) {
  const page = await app.api.get(`/workflows/${workflow.id}/runs`, { limit: 20 });
  infoDialog(
    `Runs of ${workflow.name}`,
    table(
      [
        { title: "Started", render: (row) => time(row.created_at) },
        { title: "Trigger", render: (row) => humanize(row.trigger) },
        { title: "Status", render: (row) => badge(row.status) },
        { title: "Step", render: (row) => humanize(row.current_step || "") },
        { title: "Error", render: (row) => (row.error_code ? humanize(row.error_code) : "") },
        { title: "Finished", render: (row) => time(row.finished_at) },
      ],
      page.items,
      { empty: "No runs yet." },
    ),
  );
}

export function workflowsPage(app) {
  const canExecute = app.can("workflows:execute");
  const canWrite = app.can("workflows:write");
  const canDisable = app.can("workflows:disable");
  const list = pagedTable(
    [
      { title: "Workflow", render: (row) => h("div", {}, h("strong", {}, row.name), row.description && h("p", { class: "muted small" }, row.description)) },
      { title: "Schedule", render: (row) => (row.trigger === "schedule" && row.schedule_interval_minutes ? `Every ${formatNumber(row.schedule_interval_minutes)} min` : "Manual") },
      { title: "Steps", render: (row) => ["Collect", "detect", row.analyze && "analyze", row.alert && "alert"].filter(Boolean).join(" → ") },
      { title: "Status", render: (row) => h("span", {}, badge(row.status), row.disabled_reason ? h("span", { class: "muted small" }, ` ${row.disabled_reason}`) : null) },
      { title: "Next run", render: (row) => time(row.next_run_at) },
      {
        title: "",
        class: "actions",
        render: (row) =>
          h(
            "div",
            { class: "button-row" },
            button("Runs", () => showRuns(app, row), { kind: "ghost" }),
            canExecute && row.status === "active" &&
              button("Run now", async () => {
                await app.api.request("POST", `/workflows/${row.id}/runs`, { headers: { "Idempotency-Key": idempotencyKey() } });
                notify(`${row.name} started.`, { kind: "success" });
              }),
            canWrite && row.status === "active" && button("Pause", () => changeStatus(app, row, "paused")),
            canWrite && row.status !== "active" && button("Activate", () => changeStatus(app, row, "active")),
            canDisable && row.status !== "disabled" && button("Stop", () => changeStatus(app, row, "disabled"), { kind: "danger-ghost" }),
          ),
      },
    ],
    (cursor) => app.api.get("/workflows", { limit: 50, cursor }),
    { empty: "No workflows yet. They are defined through the API (POST /api/v1/workflows)." },
  );
  return h(
    "div",
    { class: "stack" },
    pageHeader("Workflows", { description: "Scheduled collection, change detection, analysis and alerting." }),
    section(null, {}, list),
  );
}
