// API keys: machine access for integrations, scoped to a subset of a role.

import { formatDate, humanize } from "../format.js";
import { permissionsFor, ROLES, roleCovers } from "../permissions.js";
import { badge, button, checkbox, code, confirmDialog, field, form, h, input, mount, notify, pageHeader, pagedTable, secretDialog, section, select, time } from "../ui.js";

function scopePicker(role) {
  const box = h("fieldset", { class: "scopes" }, h("legend", {}, "Scopes"));
  const fill = (selectedRole) => {
    const permissions = [...permissionsFor(selectedRole)].sort();
    mount(
      box,
      h("legend", {}, "Scopes"),
      h("p", { class: "hint" }, "What the key may do: a subset of the role's permissions. Give it only what the integration needs."),
      h("div", { class: "scope-grid" }, permissions.map((permission) => checkbox(humanize(permission), { name: "scopes", value: permission, dataset: { group: "true" } }))),
    );
  };
  fill(role);
  return { element: box, fill };
}

export function apiKeysPage(app) {
  const myRole = app.context.role;
  const roles = ROLES.filter((role) => role !== "owner" && roleCovers(myRole, role));
  const picker = scopePicker(roles.includes("viewer") ? "viewer" : roles[0]);
  const roleSelect = select(roles, { name: "role", value: roles.includes("viewer") ? "viewer" : roles[0] });
  roleSelect.addEventListener("change", () => picker.fill(roleSelect.value));

  const list = pagedTable(
    [
      { title: "Key", render: (row) => h("div", {}, h("strong", {}, row.name), h("p", { class: "muted small" }, code(`${row.prefix}…`))) },
      { title: "Role", render: (row) => badge(row.role, "neutral") },
      { title: "Scopes", render: (row) => h("details", { class: "compact" }, h("summary", {}, `${row.scopes.length} scopes`), h("ul", { class: "plain" }, row.scopes.map((scope) => h("li", {}, code(scope))))) },
      { title: "Last used", render: (row) => time(row.last_used_at) },
      { title: "Expires", render: (row) => (row.expires_at ? formatDate(row.expires_at) : "Never") },
      { title: "Status", render: (row) => (row.revoked_at ? badge("revoked", "danger") : row.expires_at && new Date(row.expires_at) < new Date() ? badge("expired") : badge("active")) },
      {
        title: "",
        class: "actions",
        render: (row) =>
          row.revoked_at
            ? null
            : button("Revoke", async () => {
                const confirmed = await confirmDialog({
                  title: `Revoke ${row.name}?`,
                  message: "Every request with this key fails from now on. This cannot be undone.",
                  confirmLabel: "Revoke the key",
                  danger: true,
                });
                if (!confirmed) return;
                await app.api.delete(`/api-keys/${row.id}`);
                notify(`${row.name} was revoked.`, { kind: "success" });
                app.refresh();
              }, { kind: "ghost" }),
      },
    ],
    (cursor) => app.api.get("/api-keys", { limit: 50, cursor }),
    { empty: "No API keys yet." },
  );

  return h(
    "div",
    { class: "stack" },
    pageHeader("API keys", {
      description: "For integrations. A key is shown once and stored only as a keyed hash; its permissions never exceed its creator's current membership.",
    }),
    section(
      "New API key",
      {},
      form(
        {
          submitLabel: "Create the key",
          onSubmit: async (values, element) => {
            if (!values.scopes?.length) throw new Error("Choose at least one scope.");
            const created = await app.api.post("/api-keys", {
              name: values.name.trim(),
              role: values.role,
              scopes: values.scopes,
              expires_in_days: Number(values.expires_in_days),
            });
            await secretDialog({ title: `${created.name} is ready`, secret: created.token, note: "Copy the key now: it is shown only once. Send it as 'Authorization: Bearer <key>'." });
            element.reset();
            app.refresh();
          },
        },
        h(
          "div",
          { class: "grid-2" },
          field("Name", input({ name: "name", required: true, maxlength: "100" }), { hint: "What uses it, e.g. \"Warehouse sync\"." }),
          field("Role", roleSelect),
          field("Expires after (days)", input({ name: "expires_in_days", type: "number", min: "1", max: "365", value: "90", required: true })),
        ),
        picker.element,
      ),
    ),
    section("Keys", {}, list),
  );
}
