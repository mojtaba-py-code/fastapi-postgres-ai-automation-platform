// Integrations: the credentials sources and channels use (API tokens, Slack
// webhooks, Telegram bots, signing secrets). Secrets are write-only: stored
// encrypted, used only by the integrations worker, never shown again.

import { formatDate, humanize } from "../format.js";
import { badge, button, code, field, form, formDialog, h, input, mount, notify, pageHeader, promptDialog, secretDialog, section, select, table, time } from "../ui.js";

const KINDS = [
  ["http_bearer", "HTTP bearer token (REST API sources)"],
  ["http_basic", "HTTP basic authentication (REST API sources)"],
  ["http_header", "HTTP header (REST API sources)"],
  ["slack_webhook", "Slack incoming webhook"],
  ["telegram_bot", "Telegram bot token"],
  ["webhook_signing", "Webhook signing secret"],
];

const SECRET_HINTS = {
  http_bearer: "The token (8 or more printable characters).",
  http_basic: "The password.",
  http_header: "The header's value.",
  slack_webhook: "The https://hooks.slack.com/services/… address.",
  telegram_bot: "The bot token from @BotFather.",
  webhook_signing: "At least 32 characters - or leave it empty and the platform generates one.",
};

export async function integrationsPage(app) {
  const canWrite = app.can("integrations:write");
  const page = await app.api.get("/integrations", { limit: 200 });

  const list = table(
    [
      { title: "Integration", render: (row) => h("div", {}, h("strong", {}, row.name), h("p", { class: "muted small" }, humanize(row.kind))) },
      { title: "Secret", render: (row) => h("span", { title: `Fingerprint ${row.secret_fingerprint}` }, code(`…${row.secret_hint}`)) },
      { title: "Status", render: (row) => badge(row.status) },
      { title: "Last used", render: (row) => time(row.last_used_at) },
      { title: "Rotated", render: (row) => (row.rotated_at ? formatDate(row.rotated_at) : "Never") },
      {
        title: "",
        class: "actions",
        render: (row) =>
          canWrite &&
          row.status !== "revoked" &&
          h(
            "div",
            { class: "button-row" },
            button("Rotate", async () => {
              const answer = await formDialog({
                title: `Rotate ${row.name}`,
                message: "The new secret replaces the old one at once.",
                fields: [{ name: "secret", label: "New secret", type: "password", autocomplete: "new-password", hint: SECRET_HINTS[row.kind] }],
                confirmLabel: "Rotate",
              });
              if (!answer) return;
              await app.api.post(`/integrations/${row.id}/rotate`, { secret: answer.secret });
              notify(`${row.name} was rotated.`, { kind: "success" });
              app.refresh();
            }, { kind: "ghost" }),
            ...["quarantined", "revoked"]
              .filter((status) => status !== row.status)
              .map((status) =>
                button(status === "revoked" ? "Revoke" : "Quarantine", async () => {
                  const reason = await promptDialog({
                    title: `${status === "revoked" ? "Revoke" : "Quarantine"} ${row.name}?`,
                    message: status === "revoked" ? "It stops working for good." : "It stops working until it is rotated.",
                    label: "Reason (recorded in the audit log)",
                    confirmLabel: status === "revoked" ? "Revoke" : "Quarantine",
                    danger: true,
                  });
                  if (reason === null) return;
                  await app.api.post(`/integrations/${row.id}/status`, { status, reason });
                  app.refresh();
                }, { kind: "danger-ghost" }),
              ),
          ),
      },
    ],
    page.items,
    { empty: "No integrations yet." },
  );

  let creation = null;
  if (canWrite) {
    const kindSelect = select(KINDS, { name: "kind", value: "http_bearer" });
    const extra = h("div", {});
    const secretField = input({ name: "secret", type: "password", autocomplete: "new-password" });
    const secretHint = h("p", { class: "hint" });
    const refill = () => {
      const kind = kindSelect.value;
      secretField.required = kind !== "webhook_signing";
      secretHint.textContent = SECRET_HINTS[kind];
      mount(
        extra,
        kind === "http_basic" && field("Username", input({ name: "username", required: true, maxlength: "200", autocomplete: "off" })),
        kind === "http_header" && field("Header name", input({ name: "header_name", required: true, placeholder: "X-Api-Key", spellcheck: "false" })),
      );
    };
    kindSelect.addEventListener("change", refill);
    refill();
    creation = section(
      "New integration",
      { description: "The secret is encrypted at rest (AES-256-GCM), bound to this integration, and never returned by the API." },
      form(
        {
          submitLabel: "Save the integration",
          onSubmit: async (values, element) => {
            const metadata = values.kind === "http_basic" ? { username: values.username } : values.kind === "http_header" ? { header_name: values.header_name } : {};
            const created = await app.api.post("/integrations", { name: values.name.trim(), kind: values.kind, secret: values.secret || null, metadata });
            if (created.generated_secret) {
              await secretDialog({ title: `${created.name}: the signing secret`, secret: created.generated_secret, note: "Give it to the receiving side now: it is shown only once." });
            } else {
              notify(`${created.name} was saved.`, { kind: "success" });
            }
            element.reset();
            app.refresh();
          },
        },
        h("div", { class: "grid-2" }, field("Name", input({ name: "name", required: true, maxlength: "200" })), field("Kind", kindSelect)),
        extra,
        h("div", { class: "field" }, h("label", { for: "integration-secret" }, "Secret"), Object.assign(secretField, { id: "integration-secret" }), secretHint),
      ),
    );
  }

  return h(
    "div",
    { class: "stack" },
    pageHeader("Integrations", { description: "Credentials for REST API sources and notification channels. Only the integrations worker ever reads a secret." }),
    section(null, {}, list),
    creation,
  );
}
