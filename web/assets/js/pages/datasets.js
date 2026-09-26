// Datasets: typed schemas, their current records (with version history),
// exports and AI analyses.

import { formatNumber, humanize } from "../format.js";
import { href } from "../router.js";
import {
  badge,
  button,
  code,
  deferred,
  definitionList,
  emptyState,
  errorMessage,
  field,
  form,
  h,
  infoDialog,
  input,
  jsonBlock,
  loading,
  mount,
  notice,
  notify,
  pageHeader,
  pagedTable,
  section,
  select,
  table,
  textarea,
  time,
} from "../ui.js";

const FIELD_TYPES = ["string", "text", "integer", "decimal", "boolean", "datetime", "url", "enum"];
const CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"];

async function projectOptions(app) {
  const page = await app.api.get("/projects", { limit: 200 });
  return page.items.map((project) => [project.id, project.name]);
}

// ------------------------------------------------------------------ schema builder

let rowCounter = 0;

function schemaBuilder() {
  const rows = h("div", { class: "schema-rows" });
  const keySelect = select([], { "aria-label": "Key field" });

  function syncKeys() {
    const names = [...rows.children].map((row) => row.read().name).filter(Boolean);
    const current = keySelect.value;
    keySelect.replaceChildren(...names.map((name) => h("option", { value: name }, name)));
    if (names.includes(current)) keySelect.value = current;
  }

  function addRow(defaults = {}) {
    const name = input({ value: defaults.name || "", placeholder: "field_name", required: true, "aria-label": "Field name", spellcheck: "false" });
    const type = select(FIELD_TYPES, { value: defaults.type || "string", "aria-label": "Field type" });
    const values = input({ placeholder: "value one, value two", "aria-label": "Allowed values", hidden: type.value !== "enum" });
    rowCounter += 1;
    const required = h("input", { type: "checkbox", id: `schema-required-${rowCounter}`, checked: Boolean(defaults.required) });
    const sensitive = h("input", { type: "checkbox", id: `schema-sensitive-${rowCounter}`, checked: Boolean(defaults.sensitive) });
    const row = h(
      "div",
      { class: "schema-row" },
      name,
      type,
      values,
      h("div", { class: "checkbox" }, required, h("label", { for: required.id }, "Required")),
      h("div", { class: "checkbox" }, sensitive, h("label", { for: sensitive.id }, "Sensitive")),
      button("Remove", () => {
        row.remove();
        syncKeys();
      }, { kind: "ghost" }),
    );
    row.read = () => ({
      name: name.value.trim(),
      type: type.value,
      required: required.checked,
      sensitive: sensitive.checked,
      ...(type.value === "enum" ? { enum_values: values.value.split(",").map((value) => value.trim()).filter(Boolean) } : {}),
    });
    type.addEventListener("change", () => (values.hidden = type.value !== "enum"));
    name.addEventListener("input", syncKeys);
    rows.append(row);
    syncKeys();
  }

  addRow({ name: "sku", type: "string", required: true });
  addRow({ name: "title", type: "string" });
  addRow({ name: "price", type: "decimal" });
  return {
    element: h(
      "fieldset",
      { class: "schema" },
      h("legend", {}, "Schema"),
      h("p", { class: "hint" }, "Each record is checked against these fields. Sensitive fields are encrypted at rest and masked for people without access to sensitive data; the key field cannot be sensitive."),
      rows,
      button("Add a field", () => addRow(), { kind: "ghost" }),
      field("Key field", keySelect, { hint: "The field that identifies a record, like a SKU or an ID." }),
    ),
    value: () => ({ fields: [...rows.children].map((row) => row.read()), key_field: keySelect.value }),
  };
}

// ------------------------------------------------------------------ list

export async function datasetsPage(app, { query }) {
  const projects = await projectOptions(app);
  const projectFilter = select([["", "All projects"], ...projects], { value: query.project || "", "aria-label": "Filter by project" });
  projectFilter.addEventListener("change", () => app.navigate("/datasets", { project: projectFilter.value }));
  const projectNames = new Map(projects);

  const list = pagedTable(
    [
      { title: "Dataset", render: (row) => h("a", { href: href(`/datasets/${row.id}`) }, row.name) },
      { title: "Project", render: (row) => projectNames.get(row.project_id) || "—" },
      { title: "Fields", render: (row) => formatNumber(row.schema?.fields?.length ?? 0), class: "numeric" },
      { title: "Classification", render: (row) => badge(row.classification) },
      { title: "Retention", render: (row) => `${formatNumber(row.retention_days)} days` },
      { title: "Updated", render: (row) => time(row.updated_at) },
    ],
    (cursor) => app.api.get("/datasets", { project_id: query.project || null, limit: 50, cursor }),
    { empty: "No datasets yet." },
  );

  let creation = null;
  if (app.can("datasets:write") && projects.length) {
    const builder = schemaBuilder();
    creation = section(
      "New dataset",
      { description: "A typed table the platform keeps current from its sources, with a version history for every record." },
      form(
        {
          submitLabel: "Create the dataset",
          onSubmit: async (values) => {
            const dataset = await app.api.post("/datasets", {
              project_id: values.project_id,
              name: values.name.trim(),
              description: values.description.trim() || null,
              classification: values.classification,
              retention_days: Number(values.retention_days),
              schema: builder.value(),
            });
            notify(`${dataset.name} was created.`, { kind: "success" });
            app.navigate(`/datasets/${dataset.id}`);
          },
        },
        h(
          "div",
          { class: "grid-2" },
          field("Project", select(projects, { name: "project_id", required: true, value: query.project || projects[0][0] })),
          field("Name", input({ name: "name", required: true, maxlength: "200" })),
          field("Classification", select(CLASSIFICATIONS, { name: "classification", value: "internal" }), { hint: "Restricted data never leaves the platform (no AI, no notifications)." }),
          field("Retention (days)", input({ name: "retention_days", type: "number", min: "7", max: "3650", value: "180", required: true })),
        ),
        field("Description", textarea({ name: "description", rows: 2, maxlength: "2000" }), { hint: "Optional." }),
        builder.element,
      ),
    );
  }

  return h(
    "div",
    { class: "stack" },
    pageHeader("Datasets", { description: "Typed tables kept current from their sources.", actions: projectFilter }),
    !projects.length && notice("Create a project first: datasets belong to a project.", { kind: "info" }),
    section(null, {}, list),
    creation,
  );
}

// ------------------------------------------------------------------ one dataset

function display(value) {
  if (value === null || value === undefined || value === "") return h("span", { class: "muted" }, "—");
  if (typeof value === "object") return code(JSON.stringify(value));
  return String(value);
}

async function showHistory(app, record) {
  const history = await app.api.get(`/records/${record.id}/history`, { limit: 25 });
  infoDialog(
    `History of ${record.record_key}`,
    table(
      [
        { title: "Version", render: (row) => formatNumber(row.version), class: "numeric" },
        { title: "Captured", render: (row) => time(row.captured_at, { relative: false }) },
        { title: "", render: (row) => (row.is_deletion ? badge("deleted", "danger") : null) },
        { title: "Data", render: (row) => jsonBlock(row.data) },
      ],
      history.versions,
      { empty: "No versions recorded." },
    ),
  );
}

function insightsSection(app, dataset) {
  const body = h("div", {}, loading());
  const refresh = async () => {
    const page = await app.api.get("/intelligence/insights", { dataset_id: dataset.id, limit: 10 });
    mount(
      body,
      page.items.length
        ? h(
            "div",
            { class: "insights" },
            page.items.map((insight) =>
              h(
                "article",
                { class: "insight" },
                h(
                  "div",
                  { class: "insight-header" },
                  badge(insight.status),
                  insight.risk_level && badge(`${insight.risk_level} risk`, insight.risk_level === "low" ? "neutral" : insight.risk_level === "medium" ? "warning" : "danger"),
                  time(insight.created_at),
                  insight.model && h("span", { class: "muted small" }, insight.model),
                ),
                insight.summary && h("p", {}, insight.summary),
                insight.findings?.length > 0 && h("ul", {}, insight.findings.map((finding) => h("li", {}, typeof finding === "string" ? finding : finding.title || finding.summary || JSON.stringify(finding)))),
                insight.recommendations?.length > 0 && h("div", {}, h("p", { class: "stat-label" }, "Recommendations"), h("ul", {}, insight.recommendations.map((text) => h("li", {}, text)))),
                insight.error_code && notice(humanize(insight.error_code), { kind: "warning" }),
              ),
            ),
          )
        : emptyState("No analyses yet.", app.can("insights:generate") ? "Ask for one: the platform summarises the dataset's recent changes." : null),
    );
  };
  refresh().catch((error) => mount(body, notice(errorMessage(error), { kind: "danger" })));
  return section(
    "AI analyses",
    {
      description: "Summaries of recent changes. Sensitive fields are dropped and personal data redacted before anything reaches an AI provider, and only if your organization allows external processing.",
      actions: app.can("insights:generate")
        ? button("Analyze now", async () => {
            await app.api.post("/intelligence/analyses", { dataset_id: dataset.id });
            notify("Analysis queued. It appears here when it is done.", { kind: "success" });
            await refresh();
          }, { kind: "secondary" })
        : null,
    },
    body,
  );
}

export async function datasetPage(app, { params }) {
  const dataset = await app.api.get(`/datasets/${params.id}`);
  const fields = dataset.schema?.fields ?? [];
  const key = dataset.schema?.key_field;
  const shown = fields.filter((spec) => spec.name !== key).slice(0, 5);

  const exportButtons = app.can("datasets:export")
    ? ["csv", "jsonl"].map((format) =>
        button(`Export ${format.toUpperCase()}`, async () => {
          const name = await app.api.download(`/datasets/${dataset.id}/export`, { format });
          notify(`${name} downloaded. Exports are recorded in the audit log.`, { kind: "success" });
        }),
      )
    : null;

  const records = pagedTable(
    [
      { title: key || "Key", render: (row) => h("strong", {}, row.record_key) },
      ...shown.map((spec) => ({ title: spec.name, render: (row) => display(row.data?.[spec.name]) })),
      { title: "Version", render: (row) => formatNumber(row.version), class: "numeric" },
      { title: "Last seen", render: (row) => time(row.last_seen_at) },
      app.can("records:read") && { title: "", class: "actions", render: (row) => button("History", () => showHistory(app, row), { kind: "ghost" }) },
    ].filter(Boolean),
    (cursor) => app.api.get(`/datasets/${dataset.id}/records`, { limit: 50, cursor }),
    { empty: "No records yet: they arrive from this dataset's sources." },
  );

  return h(
    "div",
    { class: "stack" },
    h("p", { class: "breadcrumb" }, h("a", { href: href("/datasets") }, "← Datasets")),
    pageHeader(dataset.name, { description: dataset.description, actions: exportButtons }),
    section(
      null,
      {},
      definitionList([
        ["Classification", badge(dataset.classification)],
        ["Key field", code(key || "—")],
        ["Retention", `${formatNumber(dataset.retention_days)} days`],
        ["Created", time(dataset.created_at, { relative: false })],
      ]),
    ),
    section("Records", { description: "The current version of every record. Sensitive values are masked unless your role may read them." }, records),
    section(
      "Schema",
      {},
      table(
        [
          { title: "Field", render: (row) => h("span", {}, code(row.name), row.name === key ? h("span", { class: "muted small" }, " key") : null) },
          { title: "Type", render: (row) => humanize(row.type) },
          { title: "Required", render: (row) => (row.required ? "Yes" : "No") },
          { title: "Sensitive", render: (row) => (row.sensitive ? badge("sensitive", "warning") : "No") },
          { title: "Details", render: (row) => row.description || (row.enum_values?.length ? row.enum_values.join(", ") : "") },
        ],
        fields,
      ),
    ),
    app.can("insights:read") && insightsSection(app, dataset),
    app.can("sources:read") &&
      section(
        "Sources",
        {},
        deferred(
          () => app.api.get("/sources", { dataset_id: dataset.id, limit: 50 }),
          (page) =>
            table(
              [
                { title: "Source", render: (row) => h("a", { href: href(`/sources/${row.id}`) }, row.name) },
                { title: "Kind", render: (row) => humanize(row.kind) },
                { title: "Status", render: (row) => badge(row.status) },
                { title: "Last run", render: (row) => time(row.last_run_at) },
              ],
              page.items,
              { empty: "No sources feed this dataset yet." },
            ),
        ),
      ),
  );
}
