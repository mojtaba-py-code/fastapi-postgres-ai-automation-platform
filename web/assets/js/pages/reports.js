// Reports: a project's (or one dataset's) changes, alerts and insights for a
// period, generated in the background as JSON, CSV, XLSX or PDF.

import { projectChoice } from "../choices.js";
import { dayBoundary, formatBytes, formatDay } from "../format.js";
import { badge, button, field, form, h, input, notify, pageHeader, pagedTable, section, select, time } from "../ui.js";

const FORMATS = [
  ["pdf", "PDF - summary, trend chart and tables"],
  ["xlsx", "Excel - summary, trend chart and tables"],
  ["csv", "CSV - the listed changes"],
  ["json", "JSON - everything, for other tools"],
];

function isoDay(date) {
  return date.toISOString().slice(0, 10);
}

export async function reportsPage(app) {
  const projects = (await app.api.get("/projects", { limit: 200 })).items;
  const projectNames = new Map(projects.map((project) => [project.id, project.name]));

  const list = pagedTable(
    [
      { title: "Report", render: (row) => h("div", {}, h("strong", {}, row.title), h("p", { class: "muted small" }, projectNames.get(row.project_id) || "")) },
      { title: "Format", render: (row) => row.format.toUpperCase() },
      { title: "Period", render: (row) => `${formatDay(row.period_start)} – ${formatDay(row.period_end)}` },
      { title: "Status", render: (row) => h("span", {}, badge(row.status), row.error_code ? h("span", { class: "muted small" }, ` ${row.error_code}`) : null) },
      { title: "Size", render: (row) => formatBytes(row.size_bytes), class: "numeric" },
      { title: "Requested", render: (row) => time(row.created_at) },
      {
        title: "",
        class: "actions",
        render: (row) =>
          row.status === "ready" && app.can("reports:download")
            ? button("Download", async () => {
                const name = await app.api.download(`/reports/${row.id}/download`);
                notify(`${name} downloaded.`, { kind: "success" });
              })
            : null,
      },
    ],
    (cursor) => app.api.get("/reports", { limit: 50, cursor }),
    { empty: "No reports yet." },
  );

  let creation = null;
  if (app.can("reports:generate") && projects.length) {
    const today = new Date();
    const monthAgo = new Date(today.getTime() - 30 * 24 * 3600 * 1000);
    const choice = projectChoice(projects, app.can("datasets:read") ? (await app.api.get("/datasets", { limit: 200 })).items : []);
    const projectSelect = select(choice.projects.map((project) => [project.id, project.name]), { name: "project_id", required: true, value: choice.preferred });
    const datasetSelect = select([["", "Every dataset of the project"]], { name: "dataset_id" });
    const refillDatasets = async () => {
      const page = await app.api.get("/datasets", { project_id: projectSelect.value, limit: 200 });
      datasetSelect.replaceChildren(h("option", { value: "" }, "Every dataset of the project"), ...page.items.map((dataset) => h("option", { value: dataset.id }, dataset.name)));
    };
    projectSelect.addEventListener("change", () => refillDatasets().catch(() => {}));
    refillDatasets().catch(() => {});
    creation = section(
      "New report",
      { description: "Generated in the background; it appears below when it is ready. A period is at most a year." },
      form(
        {
          submitLabel: "Generate",
          onSubmit: async (values) => {
            const report = await app.api.request("POST", "/reports", {
              headers: { "Idempotency-Key": `console:${crypto.randomUUID()}` },
              body: {
                project_id: values.project_id,
                dataset_id: values.dataset_id || null,
                title: values.title.trim() || null,
                format: values.format,
                period_start: dayBoundary(values.period_start),
                period_end: dayBoundary(values.period_end, true),
              },
            });
            notify(`Report requested (${report.status}).`, { kind: "success" });
            app.refresh();
          },
        },
        h(
          "div",
          { class: "grid-2" },
          field("Project", projectSelect),
          field("Dataset", datasetSelect),
          field("From", input({ name: "period_start", type: "date", required: true, value: isoDay(monthAgo) })),
          field("To", input({ name: "period_end", type: "date", required: true, value: isoDay(today) })),
          field("Format", select(FORMATS, { name: "format", value: "pdf" })),
          field("Title", input({ name: "title", maxlength: "200" }), { hint: "Optional." }),
        ),
      ),
    );
  }

  return h(
    "div",
    { class: "stack" },
    pageHeader("Reports", { description: "Change, alert and insight reports; downloads are recorded in the audit log.", actions: button("Refresh", () => app.refresh(), { kind: "ghost" }) }),
    creation,
    section(null, {}, list),
  );
}
