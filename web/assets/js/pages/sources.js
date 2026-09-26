// Sources: where a dataset's records come from (a website, a REST API, a
// signed webhook, uploaded files), their runs and uploads.

import { formatBytes, formatNumber, humanize } from "../format.js";
import { href } from "../router.js";
import {
  badge,
  button,
  confirmDialog,
  definitionList,
  field,
  form,
  h,
  input,
  jsonBlock,
  mount,
  notice,
  notify,
  pageHeader,
  pagedTable,
  section,
  secretDialog,
  select,
  table,
  textarea,
  time,
} from "../ui.js";

const KINDS = [
  ["website", "Website (scraped with CSS selectors)"],
  ["rest_api", "REST API (polled)"],
  ["webhook", "Webhook (pushed to a signed endpoint)"],
  ["file_upload", "File upload (CSV or XLSX)"],
];

/** A starting configuration for ``kind``, mapping the dataset's own fields. */
export function configTemplate(kind, fieldNames) {
  const names = fieldNames.length ? fieldNames : ["id", "title"];
  const identity = Object.fromEntries(names.map((name) => [name, name]));
  switch (kind) {
    case "website":
      return { kind, url: "https://www.example.com/catalogue", item_selector: ".product", fields: Object.fromEntries(names.map((name) => [name, `.${name}`])), render_javascript: false };
    case "rest_api":
      return { kind, url: "https://api.example.com/v1/items", method: "GET", items_path: "items", field_mapping: identity };
    case "webhook":
      return { kind, items_path: "items", field_mapping: identity };
    default:
      return { kind: "file_upload", format: "csv", column_mapping: Object.fromEntries(names.map((name) => [name, name.charAt(0).toUpperCase() + name.slice(1)])) };
  }
}

const AUTH_KINDS = new Set(["http_bearer", "http_basic", "http_header"]);

function idempotencyKey() {
  return `console:${crypto.randomUUID()}`;
}

// ------------------------------------------------------------------ list

export async function sourcesPage(app) {
  const datasets = (await app.api.get("/datasets", { limit: 200 })).items;
  const datasetNames = new Map(datasets.map((dataset) => [dataset.id, dataset.name]));

  const list = pagedTable(
    [
      { title: "Source", render: (row) => h("a", { href: href(`/sources/${row.id}`) }, row.name) },
      { title: "Kind", render: (row) => humanize(row.kind) },
      { title: "Dataset", render: (row) => datasetNames.get(row.dataset_id) || "—" },
      { title: "Status", render: (row) => badge(row.status) },
      { title: "Last success", render: (row) => time(row.last_success_at) },
      { title: "Failures", render: (row) => (row.consecutive_failures ? badge(`${row.consecutive_failures} in a row`, "danger") : "—") },
    ],
    (cursor) => app.api.get("/sources", { limit: 50, cursor }),
    { empty: "No sources yet." },
  );

  let creation = null;
  if (app.can("sources:write") && datasets.length) {
    const datasetSelect = select(datasets.map((dataset) => [dataset.id, dataset.name]), { name: "dataset_id", required: true });
    const kindSelect = select(KINDS, { name: "kind", value: "website" });
    const config = textarea({ name: "config", rows: 12, spellcheck: "false", class: "input mono" });
    // Credentials a REST API source may send (bearer, basic or a header), from Integrations.
    const credentials = app.can("integrations:read")
      ? (await app.api.get("/integrations", { limit: 200 })).items.filter((item) => AUTH_KINDS.has(item.kind) && item.status === "active")
      : [];
    const credentialsField = field(
      "Credentials",
      select([["", "None (a public API)"], ...credentials.map((item) => [item.id, `${item.name} (${humanize(item.kind)})`])], { name: "integration_id" }),
      { hint: "Sent only by the integrations worker, only to this source's address." },
    );
    const refill = () => {
      const dataset = datasets.find((item) => item.id === datasetSelect.value);
      config.value = JSON.stringify(configTemplate(kindSelect.value, (dataset?.schema?.fields ?? []).map((spec) => spec.name)), null, 2);
      credentialsField.hidden = kindSelect.value !== "rest_api";
    };
    datasetSelect.addEventListener("change", refill);
    kindSelect.addEventListener("change", refill);
    refill();
    creation = section(
      "New source",
      { description: "Outbound requests go through the platform's SSRF guard (public HTTPS addresses only); pages and files are parsed in an isolated sandbox." },
      form(
        {
          submitLabel: "Create the source",
          onSubmit: async (values) => {
            let parsed;
            try {
              parsed = JSON.parse(values.config);
            } catch {
              throw new Error("The configuration is not valid JSON.");
            }
            const dataset = datasets.find((item) => item.id === values.dataset_id);
            const integration = values.kind === "rest_api" && values.integration_id ? values.integration_id : null;
            const source = await app.api.post("/sources", { project_id: dataset.project_id, dataset_id: dataset.id, name: values.name.trim(), config: parsed, integration_id: integration });
            notify(`${source.name} was created.`, { kind: "success" });
            app.navigate(`/sources/${source.id}`);
          },
        },
        h("div", { class: "grid-2" }, field("Name", input({ name: "name", required: true, maxlength: "200" })), field("Dataset", datasetSelect), field("Kind", kindSelect), credentialsField),
        field("Configuration", config, { hint: "JSON. The template maps this dataset's fields; adjust the selectors, paths or columns to your data." }),
      ),
    );
  }

  return h(
    "div",
    { class: "stack" },
    pageHeader("Sources", { description: "Where each dataset's records come from." }),
    !datasets.length && notice("Create a dataset first: every source feeds one dataset.", { kind: "info" }),
    section(null, {}, list),
    creation,
  );
}

// ------------------------------------------------------------------ one source

export async function sourcePage(app, { params }) {
  const source = await app.api.get(`/sources/${params.id}`);
  const pulls = source.kind === "website" || source.kind === "rest_api";

  const actions = [];
  if (pulls && app.can("sources:run")) {
    actions.push(
      button("Run now", async () => {
        const run = await app.api.request("POST", `/sources/${source.id}/runs`, { headers: { "Idempotency-Key": idempotencyKey() } });
        notify(`Run ${run.status}.`, { kind: "success" });
        app.refresh();
      }, { kind: "primary" }),
    );
  }
  if (app.can("sources:write")) {
    const paused = source.status === "paused";
    actions.push(
      button(paused ? "Resume" : "Pause", async () => {
        if (!paused && !(await confirmDialog({ title: `Pause ${source.name}?`, message: "Scheduled runs and deliveries to it stop until it is resumed.", confirmLabel: "Pause" }))) return;
        await app.api.patch(`/sources/${source.id}`, { status: paused ? "active" : "paused" });
        app.refresh();
      }),
    );
  }

  const uploads = source.kind === "file_upload"
    ? section(
        "Uploads",
        { description: "CSV or XLSX up to 25 MB. Files are checked for hostile content, scanned and parsed in the sandbox." },
        app.can("uploads:write") &&
          form(
            {
              submitLabel: "Upload",
              onSubmit: async ({ file }, element) => {
                if (!file) throw new Error("Choose a file.");
                const upload = await app.api.upload(`/sources/${source.id}/uploads`, file);
                notify(`${upload.original_filename}: ${upload.status}.`, { kind: upload.status === "rejected" ? "error" : "success" });
                element.reset();
                app.refresh();
              },
              className: "form-inline",
            },
            field("File", input({ name: "file", type: "file", accept: ".csv,.xlsx,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", required: true })),
          ),
        pagedTable(
          [
            { title: "File", render: (row) => row.original_filename },
            { title: "Size", render: (row) => formatBytes(row.size_bytes), class: "numeric" },
            { title: "Rows", render: (row) => formatNumber(row.row_count), class: "numeric" },
            { title: "Status", render: (row) => h("span", {}, badge(row.status), row.rejection_reason ? h("span", { class: "muted small" }, ` ${humanize(row.rejection_reason)}`) : null) },
            { title: "Uploaded", render: (row) => time(row.created_at) },
          ],
          (cursor) => app.api.get(`/sources/${source.id}/uploads`, { limit: 20, cursor }),
          { empty: "No uploads yet." },
        ),
      )
    : null;

  const endpoints = source.kind === "webhook" && app.can("webhooks:read") ? endpointsSection(app, source) : null;

  return h(
    "div",
    { class: "stack" },
    h("p", { class: "breadcrumb" }, h("a", { href: href("/sources") }, "← Sources")),
    pageHeader(source.name, { description: humanize(source.kind), actions }),
    source.status === "quarantined" && notice("The source is quarantined after repeated failures; fix its configuration, then resume it.", { kind: "warning" }),
    section(
      null,
      {},
      definitionList([
        ["Status", badge(source.status)],
        ["Dataset", h("a", { href: href(`/datasets/${source.dataset_id}`) }, "Open the dataset")],
        ["Last run", time(source.last_run_at)],
        ["Last success", time(source.last_success_at)],
        ["Failures in a row", formatNumber(source.consecutive_failures)],
      ]),
    ),
    uploads,
    endpoints,
    section(
      "Runs",
      {},
      pagedTable(
        [
          { title: "Started", render: (row) => time(row.started_at || row.created_at) },
          { title: "Trigger", render: (row) => humanize(row.trigger) },
          { title: "Status", render: (row) => badge(row.status) },
          { title: "Received", render: (row) => formatNumber(row.stats?.received ?? null), class: "numeric" },
          {
            title: "Outcome",
            render: (row) =>
              row.stats && "created" in row.stats
                ? `${formatNumber(row.stats.created)} new · ${formatNumber(row.stats.updated)} changed · ${formatNumber(row.stats.deleted)} removed${row.stats.invalid ? ` · ${formatNumber(row.stats.invalid)} invalid` : ""}`
                : "",
          },
          { title: "Error", render: (row) => (row.error_code ? humanize(row.error_code) : "") },
          { title: "Finished", render: (row) => time(row.finished_at) },
        ],
        (cursor) => app.api.get(`/sources/${source.id}/runs`, { limit: 20, cursor }),
        { empty: "No runs yet." },
      ),
    ),
    section("Configuration", {}, jsonBlock(source.config)),
  );
}

// ------------------------------------------------------------------ webhook endpoints

function endpointsSection(app, source) {
  const canWrite = app.can("webhooks:write");
  const body = h("div", { class: "stack" });
  const showSecret = (endpoint, title) =>
    secretDialog({
      title,
      secret: endpoint.secret,
      details: [["Endpoint URL", endpoint.url]],
      note: "Give the URL and the secret to the sender now: the secret is shown only once. Every delivery must be signed with it (HMAC-SHA256 over the timestamp, the delivery ID and the body; see docs/API.md).",
    });
  const render = async () => {
    const page = await app.api.get("/webhook-endpoints", { limit: 200 });
    const own = page.items.filter((endpoint) => endpoint.source_id === source.id);
    mount(
      body,
      table(
        [
          { title: "Endpoint", render: (row) => h("strong", {}, row.name) },
          { title: "Status", render: (row) => badge(row.status) },
          { title: "Last delivery", render: (row) => time(row.last_received_at) },
          { title: "Created", render: (row) => time(row.created_at) },
          {
            title: "",
            class: "actions",
            render: (row) =>
              canWrite &&
              h(
                "div",
                { class: "button-row" },
                button("Rotate the secret", async () => {
                  const confirmed = await confirmDialog({
                    title: `Rotate the secret of ${row.name}?`,
                    message: "The old secret keeps working for 24 hours, so the sender can switch without losing deliveries.",
                    confirmLabel: "Rotate",
                  });
                  if (!confirmed) return;
                  await showSecret(await app.api.post(`/webhook-endpoints/${row.id}/rotate-secret`), `New secret for ${row.name}`);
                  await render();
                }, { kind: "ghost" }),
                button(row.status === "active" ? "Disable" : "Enable", async () => {
                  await app.api.post(`/webhook-endpoints/${row.id}/status`, { status: row.status === "active" ? "disabled" : "active" });
                  await render();
                }, { kind: row.status === "active" ? "danger-ghost" : "ghost" }),
              ),
          },
        ],
        own,
        { empty: "No endpoint yet: create one to receive deliveries." },
      ),
      canWrite &&
        form(
          {
            submitLabel: "Create an endpoint",
            className: "form-inline",
            onSubmit: async ({ name }, element) => {
              const created = await app.api.post("/webhook-endpoints", { source_id: source.id, name: name.trim() });
              await showSecret(created, `${created.name} is ready`);
              element.reset();
              await render();
            },
          },
          field("Name", input({ name: "name", required: true, maxlength: "100", placeholder: "partner-feed" })),
        ),
    );
  };
  render().catch((error) => mount(body, notice(error.message, { kind: "danger" })));
  return section("Endpoints", { description: "Senders post signed deliveries here. Unsigned, stale or replayed deliveries are refused." }, body);
}
