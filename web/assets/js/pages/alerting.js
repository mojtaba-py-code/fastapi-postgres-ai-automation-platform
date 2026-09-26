// Alert rules (what raises an alert) and notification channels (where alerts go).

import { projectChoice } from "../choices.js";
import { humanize } from "../format.js";
import { badge, button, checkbox, confirmDialog, emptyState, field, form, h, input, mount, notice, notify, pageHeader, section, select, table, textarea, time } from "../ui.js";

const CONDITIONS = [
  ["significance_at_least", "A change of at least a significance"],
  ["numeric_change", "A number moves by a percentage"],
  ["field_changed", "A field changes"],
  ["change_type", "Records are created or deleted"],
  ["insight_risk_at_least", "An AI analysis reports a risk"],
  ["run_failed", "A collection run fails"],
];
const LEVELS = ["low", "medium", "high", "critical"];

export function describeCondition(condition) {
  switch (condition?.type) {
    case "significance_at_least":
      return `Change of ${condition.level} significance or more`;
    case "numeric_change": {
      const direction = { increase: "rises", decrease: "falls", any: "moves" }[condition.direction || "any"];
      return `${condition.field} ${direction} by ${condition.min_pct || 0} % or more`;
    }
    case "field_changed":
      return `${condition.field} changes`;
    case "change_type":
      return `Records ${condition.change_types.join(" or ")}`;
    case "insight_risk_at_least":
      return `AI analysis reports ${condition.level} risk or more`;
    case "run_failed":
      return "A collection run fails";
    default:
      return JSON.stringify(condition);
  }
}

// ------------------------------------------------------------------ rules

function conditionFields(type, fieldNames) {
  const fieldControl = () =>
    fieldNames.length
      ? select(fieldNames, { name: "field", required: true })
      : input({ name: "field", required: true, spellcheck: "false", placeholder: "price" });
  switch (type) {
    case "significance_at_least":
      return [field("At least", select(LEVELS, { name: "level", value: "high" }))];
    case "numeric_change":
      return [
        field("Field", fieldControl(), { hint: "A number field of the dataset." }),
        field("Direction", select([["increase", "Rises"], ["decrease", "Falls"], ["any", "Either way"]], { name: "direction", value: "increase" })),
        field("By at least (%)", input({ name: "min_pct", type: "number", min: "0", step: "0.1", value: "10", required: true })),
      ];
    case "field_changed":
      return [field("Field", fieldControl())];
    case "change_type":
      return [
        h(
          "fieldset",
          {},
          h("legend", {}, "Records that are"),
          checkbox("Created", { name: "change_types", value: "created", checked: true, dataset: { group: "true" } }),
          checkbox("Deleted", { name: "change_types", value: "deleted", dataset: { group: "true" } }),
        ),
      ];
    case "insight_risk_at_least":
      return [field("At least", select(LEVELS, { name: "level", value: "high" }))];
    default:
      return [];
  }
}

function conditionFrom(type, values) {
  switch (type) {
    case "significance_at_least":
    case "insight_risk_at_least":
      return { type, level: values.level };
    case "numeric_change":
      return { type, field: values.field, direction: values.direction, min_pct: Number(values.min_pct) };
    case "field_changed":
      return { type, field: values.field };
    case "change_type":
      return { type, change_types: values.change_types };
    default:
      return { type };
  }
}

async function ruleForm(app) {
  const [projects, datasets, channels] = await Promise.all([
    app.api.get("/projects", { limit: 200 }),
    app.api.get("/datasets", { limit: 200 }),
    app.can("channels:read") ? app.api.get("/channels", { limit: 200 }) : { items: [] },
  ]);
  if (!projects.items.length) return notice("Create a project first: rules belong to a project.", { kind: "info" });
  const choice = projectChoice(projects.items, datasets.items);
  const projectSelect = select(choice.projects.map((project) => [project.id, project.name]), { name: "project_id", value: choice.preferred });
  const datasetSelect = select([], { name: "dataset_id" });
  const typeSelect = select(CONDITIONS, { name: "type", value: "significance_at_least" });
  const conditionSlot = h("div", { class: "grid-2" });
  const refreshDatasets = () => {
    const own = datasets.items.filter((dataset) => dataset.project_id === projectSelect.value);
    datasetSelect.replaceChildren(h("option", { value: "" }, "Every dataset of the project"), ...own.map((dataset) => h("option", { value: dataset.id }, dataset.name)));
  };
  const refreshCondition = () => {
    const dataset = datasets.items.find((item) => item.id === datasetSelect.value);
    const names = (dataset?.schema?.fields ?? []).map((spec) => spec.name);
    mount(conditionSlot, conditionFields(typeSelect.value, names));
  };
  projectSelect.addEventListener("change", () => {
    refreshDatasets();
    refreshCondition();
  });
  datasetSelect.addEventListener("change", refreshCondition);
  typeSelect.addEventListener("change", refreshCondition);
  refreshDatasets();
  refreshCondition();

  return form(
    {
      submitLabel: "Create the rule",
      onSubmit: async (values) => {
        if (typeSelect.value === "change_type" && !values.change_types?.length) throw new Error("Choose created, deleted or both.");
        await app.api.post("/alert-rules", {
          project_id: values.project_id,
          dataset_id: values.dataset_id || null,
          name: values.name.trim(),
          severity: values.severity,
          cooldown_minutes: Number(values.cooldown_minutes),
          channel_ids: values.channel_ids ?? [],
          condition: conditionFrom(typeSelect.value, values),
        });
        notify("The rule was created.", { kind: "success" });
        app.refresh();
      },
    },
    h(
      "div",
      { class: "grid-2" },
      field("Name", input({ name: "name", required: true, maxlength: "200", placeholder: "Price up 10 % or more" })),
      field("Severity", select([["info", "Info"], ["warning", "Warning"], ["critical", "Critical"]], { name: "severity", value: "warning" })),
      field("Project", projectSelect),
      field("Dataset", datasetSelect),
      field("When", typeSelect),
      field("Quiet period (minutes)", input({ name: "cooldown_minutes", type: "number", min: "0", max: "10080", value: "60", required: true }), {
        hint: "The same rule does not alert again for the same record within this time.",
      }),
    ),
    conditionSlot,
    channels.items.length
      ? h(
          "fieldset",
          {},
          h("legend", {}, "Notify"),
          channels.items.map((channel) => checkbox(`${channel.name} (${humanize(channel.kind)})`, { name: "channel_ids", value: channel.id, dataset: { group: "true" } })),
        )
      : notice("No notification channels yet: alerts appear in the console only until you add one.", { kind: "info" }),
  );
}

export async function alertRulesPage(app) {
  const canWrite = app.can("alerts:write");
  const [rules, channels] = await Promise.all([
    app.api.get("/alert-rules", { limit: 200 }),
    app.can("channels:read") ? app.api.get("/channels", { limit: 200 }) : { items: [] },
  ]);
  const channelNames = new Map(channels.items.map((channel) => [channel.id, channel.name]));

  const list = table(
    [
      { title: "Rule", render: (row) => h("div", {}, h("strong", {}, row.name), h("p", { class: "muted small" }, describeCondition(row.condition))) },
      { title: "Severity", render: (row) => badge(row.severity) },
      { title: "Notifies", render: (row) => (row.channel_ids.length ? row.channel_ids.map((id) => channelNames.get(id) || "a channel").join(", ") : h("span", { class: "muted" }, "Console only")) },
      { title: "Status", render: (row) => (row.enabled ? badge("active") : badge("paused")) },
      {
        title: "",
        class: "actions",
        render: (row) =>
          canWrite &&
          h(
            "div",
            { class: "button-row" },
            button(row.enabled ? "Pause" : "Resume", async () => {
              await app.api.patch(`/alert-rules/${row.id}`, { enabled: !row.enabled });
              app.refresh();
            }, { kind: "ghost" }),
            button("Delete", async () => {
              if (!(await confirmDialog({ title: `Delete ${row.name}?`, message: "Alerts it raised stay; it raises no more.", confirmLabel: "Delete", danger: true }))) return;
              await app.api.delete(`/alert-rules/${row.id}`);
              notify(`${row.name} was deleted.`, { kind: "success" });
              app.refresh();
            }, { kind: "ghost" }),
          ),
      },
    ],
    rules.items,
    { empty: "No alert rules yet." },
  );

  return h(
    "div",
    { class: "stack" },
    pageHeader("Alert rules", { description: "Conditions on changes, AI analyses and collection runs. A rule sees the complete change; its alert shows sensitive values masked." }),
    section(null, {}, list),
    canWrite && section("New rule", {}, await ruleForm(app)),
  );
}

// ------------------------------------------------------------------ channels

function channelTarget(channel) {
  const config = channel.config || {};
  if (channel.kind === "email") return (config.recipients || []).join(", ");
  if (channel.kind === "telegram") return `Chat ${config.chat_id}`;
  if (channel.kind === "webhook") return config.url;
  return "Slack incoming webhook";
}

export async function channelsPage(app) {
  const canWrite = app.can("channels:write");
  const channels = await app.api.get("/channels", { limit: 200 });
  const integrations = canWrite && app.can("integrations:read") ? (await app.api.get("/integrations", { limit: 200 })).items : [];

  const list = table(
    [
      { title: "Channel", render: (row) => h("div", {}, h("strong", {}, row.name), h("p", { class: "muted small" }, channelTarget(row))) },
      { title: "Kind", render: (row) => humanize(row.kind) },
      { title: "Status", render: (row) => (row.enabled ? badge("active") : badge("paused")) },
      { title: "Added", render: (row) => time(row.created_at) },
      {
        title: "",
        class: "actions",
        render: (row) =>
          canWrite &&
          h(
            "div",
            { class: "button-row" },
            button(row.enabled ? "Pause" : "Resume", async () => {
              await app.api.patch(`/channels/${row.id}`, { enabled: !row.enabled });
              app.refresh();
            }, { kind: "ghost" }),
            button("Delete", async () => {
              if (!(await confirmDialog({ title: `Delete ${row.name}?`, message: "Rules stop notifying it.", confirmLabel: "Delete", danger: true }))) return;
              await app.api.delete(`/channels/${row.id}`);
              app.refresh();
            }, { kind: "ghost" }),
          ),
      },
    ],
    channels.items,
    { empty: "No channels yet." },
  );

  let creation = null;
  if (canWrite) {
    const kindSelect = select([["email", "E-mail"], ["slack", "Slack"], ["telegram", "Telegram"], ["webhook", "Signed webhook"]], { name: "kind", value: "email" });
    const slot = h("div", { class: "stack" });
    const needs = { slack: "slack_webhook", telegram: "telegram_bot", webhook: "webhook_signing" };
    const refill = () => {
      const kind = kindSelect.value;
      const usable = integrations.filter((item) => item.kind === needs[kind] && item.status === "active");
      const integrationField = needs[kind]
        ? usable.length
          ? field("Credentials", select(usable.map((item) => [item.id, `${item.name} (…${item.secret_hint})`]), { name: "integration_id" }), { hint: "Stored, encrypted, under Integrations." })
          : notice(`Add a ${humanize(needs[kind])} integration first (Integrations): it holds the secret this channel uses.`, { kind: "info" })
        : null;
      mount(
        slot,
        kind === "email" && field("Recipients", textarea({ name: "recipients", rows: 2, required: true, spellcheck: "false", placeholder: "pricing-team@example.com" }), { hint: "One address per line." }),
        kind === "telegram" && field("Chat ID", input({ name: "chat_id", required: true, spellcheck: "false" })),
        kind === "webhook" && field("URL", input({ name: "url", type: "url", required: true, placeholder: "https://hooks.example.com/nexusflow" }), { hint: "Public HTTPS only; every delivery is signed." }),
        integrationField,
      );
    };
    kindSelect.addEventListener("change", refill);
    refill();
    creation = section(
      "New channel",
      { description: "Restricted data never leaves the platform; sensitive values are masked in every notification." },
      form(
        {
          submitLabel: "Add the channel",
          onSubmit: async (values) => {
            const kind = values.kind;
            const config =
              kind === "email"
                ? { kind, recipients: values.recipients.split(/[\s,]+/).map((address) => address.trim()).filter(Boolean) }
                : kind === "telegram"
                  ? { kind, chat_id: values.chat_id.trim() }
                  : kind === "webhook"
                    ? { kind, url: values.url.trim() }
                    : { kind };
            if (kind !== "email" && !values.integration_id) throw new Error("This kind of channel needs its credentials: add an integration first.");
            await app.api.post("/channels", { name: values.name.trim(), config, integration_id: values.integration_id || null });
            notify("The channel was added.", { kind: "success" });
            app.refresh();
          },
        },
        h("div", { class: "grid-2" }, field("Name", input({ name: "name", required: true, maxlength: "200", placeholder: "Pricing team" })), field("Kind", kindSelect)),
        slot,
      ),
    );
  }

  return h(
    "div",
    { class: "stack" },
    pageHeader("Notification channels", { description: "Where alerts are sent. Each channel is rate-limited, and outbound requests pass the SSRF guard." }),
    section(null, {}, channels.items.length ? list : emptyState("No channels yet.", "Alerts still appear in the console.")),
    creation,
    !canWrite && notice("Your role can see channels but not change them.", { kind: "info" }),
  );
}

