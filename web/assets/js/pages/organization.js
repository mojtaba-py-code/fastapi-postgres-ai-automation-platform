// Organization settings: name, security policy, automation kill switch, deletion.

import { formatDate } from "../format.js";
import { href } from "../router.js";
import { badge, button, checkbox, confirmDialog, definitionList, field, form, h, input, link, notice, notify, pageHeader, promptDialog, section, textarea } from "../ui.js";

function lines(text) {
  return text
    .split(/[\n,]+/)
    .map((line) => line.trim())
    .filter(Boolean);
}

export async function organizationPage(app) {
  const organization = await app.api.get("/organizations/current");
  const settings = organization.settings;
  const owner = app.context.role === "owner";

  const general = section(
    "General",
    {},
    definitionList([
      ["Slug", h("code", {}, organization.slug)],
      ["Status", badge(organization.status)],
      ["Created", formatDate(organization.created_at)],
    ]),
    form(
      {
        submitLabel: "Rename",
        className: "form-inline",
        onSubmit: async ({ name }) => {
          await app.api.patch("/organizations/current", { name: name.trim() });
          notify("The organization was renamed.", { kind: "success" });
          await app.reloadContext();
        },
      },
      field("Name", input({ name: "name", required: true, maxlength: "200", value: organization.name })),
    ),
  );

  const policy = section(
    "Security policy",
    { description: "Applied to every member's session and every API key of the organization, on every request." },
    form(
      {
        submitLabel: "Save the policy",
        onSubmit: async (values) => {
          await app.api.patch("/organizations/current", {
            settings: {
              require_mfa: values.require_mfa,
              allowed_ip_ranges: lines(values.allowed_ip_ranges).length ? lines(values.allowed_ip_ranges) : null,
              allowed_source_domains: lines(values.allowed_source_domains).length ? lines(values.allowed_source_domains) : null,
              ai_external_processing: values.ai_external_processing,
              default_retention_days: Number(values.default_retention_days),
            },
          });
          notify("The policy was saved.", { kind: "success" });
          await app.reloadContext();
        },
      },
      checkbox("Require two-step verification", { name: "require_mfa", checked: settings.require_mfa }, {
        hint: "Members reach the organization only from a session that passed a second factor (a passkey or an authenticator app). Members without one are asked to set it up.",
      }),
      field(
        "Allowed networks",
        textarea({ name: "allowed_ip_ranges", rows: 3, spellcheck: "false", class: "input mono", value: (settings.allowed_ip_ranges || []).join("\n") }),
        { hint: "One CIDR range per line (IPv4 or IPv6), e.g. 203.0.113.0/24. Leave empty to allow any network. A list that would shut out your own address is refused." },
      ),
      field(
        "Allowed source domains",
        textarea({ name: "allowed_source_domains", rows: 3, spellcheck: "false", class: "input mono", value: (settings.allowed_source_domains || []).join("\n") }),
        { hint: "Sources may fetch only from these domains (one per line). Leave empty for any public address." },
      ),
      field("Default retention (days)", input({ name: "default_retention_days", type: "number", min: "7", max: "3650", required: true, value: String(settings.default_retention_days) })),
      checkbox("Allow external AI processing", { name: "ai_external_processing", checked: settings.ai_external_processing }, {
        hint: "Off by default. When on, AI analyses may send redacted change summaries to the configured AI provider; restricted data never leaves.",
      }),
    ),
  );

  const automation = app.can("workflows:disable")
    ? section(
        "Automation kill switch",
        { description: "Freezing stops scheduled work and outbound automation for the whole organization, at once." },
        settings.automation_frozen ? notice("Automation is frozen.", { kind: "warning" }) : h("p", { class: "muted" }, "Automation is running."),
        button(settings.automation_frozen ? "Unfreeze automation" : "Freeze automation", async () => {
          const reason = await promptDialog({
            title: settings.automation_frozen ? "Unfreeze automation?" : "Freeze all automation?",
            label: "Reason (recorded in the audit log)",
            confirmLabel: settings.automation_frozen ? "Unfreeze" : "Freeze",
            danger: !settings.automation_frozen,
          });
          if (reason === null) return;
          await app.api.post("/organizations/current/automation-freeze", { frozen: !settings.automation_frozen, reason });
          notify(settings.automation_frozen ? "Automation resumed." : "Automation frozen.", { kind: "success" });
          await app.reloadContext();
        }, { kind: settings.automation_frozen ? "secondary" : "danger" }),
      )
    : null;

  const danger = owner && app.can("org:delete")
    ? section(
        "Delete the organization",
        { description: "Everything the organization holds is purged after a 7-day grace period. Members lose access at once." },
        organization.status === "pending_deletion"
          ? notice("Deletion is scheduled. Contact the platform operator within the grace period to stop it.", { kind: "warning" })
          : button("Delete the organization…", async () => {
              const confirmed = await confirmDialog({
                title: `Delete ${organization.name}?`,
                message: "Its projects, datasets, records, files, reports and audit trail are purged after 7 days. This cannot be undone after that.",
                confirmLabel: "Delete",
                danger: true,
                requireText: organization.slug,
              });
              if (!confirmed) return;
              await app.api.post("/organizations/current/deletion", { confirm_slug: organization.slug });
              notify("Deletion is scheduled.", { kind: "success" });
              await app.reloadContext();
            }, { kind: "danger" }),
      )
    : null;

  return h(
    "div",
    { class: "stack" },
    pageHeader("Organization settings", { actions: link("Single sign-on", href("/sso"), { kind: "ghost" }) }),
    general,
    policy,
    automation,
    danger,
  );
}
