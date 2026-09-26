// Members, their roles, and invitations.

import { ROLES, roleCovers } from "../permissions.js";
import { badge, button, confirmDialog, field, form, h, input, notify, pageHeader, pagedTable, section, select, time } from "../ui.js";

export function membersPage(app) {
  const manage = app.can("members:manage");
  const myRole = app.context.role;
  const assignable = ROLES.filter((role) => role !== "owner" && roleCovers(myRole, role));

  const roleControl = (member) => {
    if (!manage || member.user_id === app.context.user.id || !roleCovers(myRole, member.role) || member.role === "owner") {
      return badge(member.role, "neutral");
    }
    const control = select(assignable, { value: member.role, "aria-label": `Role of ${member.email}`, class: "input compact" });
    control.addEventListener("change", async () => {
      try {
        await app.api.patch(`/organizations/current/members/${member.membership_id}`, { role: control.value });
        notify(`${member.email} is now ${control.value}.`, { kind: "success" });
      } catch (error) {
        control.value = member.role;
        throw error;
      }
    });
    return control;
  };

  const members = pagedTable(
    [
      { title: "Member", render: (row) => h("div", {}, h("strong", {}, row.full_name), h("p", { class: "muted small" }, row.email)) },
      { title: "Role", render: roleControl },
      { title: "Two-step", render: (row) => (row.mfa_enabled ? badge("on", "success") : badge("off", "neutral")) },
      { title: "Joined", render: (row) => time(row.joined_at) },
      manage && {
        title: "",
        class: "actions",
        render: (row) =>
          row.user_id !== app.context.user.id && row.role !== "owner" && roleCovers(myRole, row.role)
            ? button("Remove", async () => {
                const confirmed = await confirmDialog({
                  title: `Remove ${row.email}?`,
                  message: "They lose access to this organization at once, and their API keys here stop working. Their account itself stays.",
                  confirmLabel: "Remove the member",
                  danger: true,
                });
                if (!confirmed) return;
                await app.api.delete(`/organizations/current/members/${row.membership_id}`);
                notify(`${row.email} was removed.`, { kind: "success" });
                app.refresh();
              }, { kind: "ghost" })
            : null,
      },
    ].filter(Boolean),
    (cursor) => app.api.get("/organizations/current/members", { limit: 50, cursor }),
    { empty: "No members." },
  );

  const invitations = manage
    ? section(
        "Invitations",
        { description: "An invitation is a link sent to the address; it expires, and you can revoke it until it is used." },
        form(
          {
            submitLabel: "Invite",
            className: "form-inline",
            onSubmit: async ({ email, role }, element) => {
              await app.api.post("/organizations/current/invitations", { email: email.trim(), role });
              notify(`Invitation sent to ${email.trim()}.`, { kind: "success" });
              element.reset();
              app.refresh();
            },
          },
          field("E-mail address", input({ name: "email", type: "email", required: true, autocomplete: "off" })),
          field("Role", select(assignable, { name: "role", value: assignable.includes("viewer") ? "viewer" : assignable[0] })),
        ),
        pagedTable(
          [
            { title: "Invited", render: (row) => row.email },
            { title: "Role", render: (row) => badge(row.role, "neutral") },
            { title: "Sent", render: (row) => time(row.created_at) },
            { title: "Expires", render: (row) => time(row.expires_at) },
            {
              title: "",
              class: "actions",
              render: (row) =>
                button("Revoke", async () => {
                  await app.api.delete(`/organizations/current/invitations/${row.id}`);
                  notify(`The invitation to ${row.email} was revoked.`, { kind: "success" });
                  app.refresh();
                }, { kind: "ghost" }),
            },
          ],
          (cursor) => app.api.get("/organizations/current/invitations", { limit: 50, cursor }),
          { empty: "No pending invitations." },
        ),
      )
    : null;

  return h(
    "div",
    { class: "stack" },
    pageHeader("Members", { description: "Who can reach this organization, and with which role. Owners are appointed and removed by owners." }),
    section(null, {}, members),
    invitations,
  );
}
