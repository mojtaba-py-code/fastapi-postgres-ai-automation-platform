// Single sign-on (the organization's OpenID Connect provider, its proven
// domains) and SCIM provisioning tokens.

import { ApiError } from "../api.js";
import { formatDate } from "../format.js";
import {
  badge,
  button,
  checkbox,
  code,
  confirmDialog,
  copyButton,
  definitionList,
  field,
  form,
  h,
  input,
  mount,
  notice,
  notify,
  pageHeader,
  secretDialog,
  section,
  select,
  table,
  textarea,
  time,
} from "../ui.js";

const CHECK_TEXT = {
  verified: "Verified now",
  already_verified: "Already verified",
  record_not_found: "Record not found yet (DNS can take a while)",
  lookup_failed: "The DNS lookup failed; try again",
};

function providerForm(app, configuration) {
  const editing = Boolean(configuration);
  return form(
    {
      submitLabel: editing ? "Save the provider" : "Connect the provider",
      onSubmit: async (values) => {
        await app.api.put("/organizations/current/sso", {
          issuer: values.issuer.trim(),
          client_id: values.client_id.trim(),
          client_secret: values.client_secret ? values.client_secret : null,
          allowed_domains: values.allowed_domains.split(/[\s,]+/).map((domain) => domain.trim()).filter(Boolean),
          default_role: values.default_role,
          sso_required: values.sso_required,
          trust_idp_mfa: values.trust_idp_mfa,
        });
        notify(editing ? "The provider was saved." : "The provider is connected. Publish the TXT records below to prove your domains.", { kind: "success" });
        app.refresh();
      },
    },
    h(
      "div",
      { class: "grid-2" },
      field("Issuer", input({ name: "issuer", type: "url", required: true, value: configuration?.issuer || "", placeholder: "https://login.microsoftonline.com/<tenant-id>/v2.0", spellcheck: "false" }), {
        hint: "Exactly as your provider's discovery document names it.",
      }),
      field("Client ID", input({ name: "client_id", required: true, value: configuration?.client_id || "", spellcheck: "false", autocomplete: "off" })),
      field("Client secret", input({ name: "client_secret", type: "password", required: !editing, autocomplete: "new-password" }), {
        hint: editing ? "Leave empty to keep the stored secret. It is sealed and never shown again." : "Sealed at rest and never shown again.",
      }),
      field("Role for new members", select([["viewer", "Viewer"], ["analyst", "Analyst"]], { name: "default_role", value: configuration?.default_role || "viewer" }), {
        hint: "An identity provider never grants more; roles are changed in Members.",
      }),
    ),
    field("E-mail domains", textarea({ name: "allowed_domains", rows: 2, required: true, spellcheck: "false", class: "input mono", value: (configuration?.allowed_domains || []).join("\n") }), {
      hint: "One per line. The provider speaks only for addresses in domains you prove with a DNS TXT record.",
    }),
    checkbox("Trust the provider's MFA", { name: "trust_idp_mfa", checked: configuration?.trust_idp_mfa }, {
      hint: "When the organization requires two-step verification, accept the provider's own MFA (its ID token must report it in 'amr').",
    }),
    checkbox("Require single sign-on", { name: "sso_required", checked: configuration?.sso_required }, {
      hint: "Members reach the organization only through the provider. Needs a verified domain, and your own session must come from the provider (owners: or from a password sign-in with MFA).",
    }),
  );
}

function domainsSection(app, configuration) {
  const results = h("div", {});
  return section(
    "Domains",
    {
      description: "Publish each TXT record at your DNS host, then check. The provider can sign in only addresses in verified domains.",
      actions: button("Check the DNS records", async () => {
        const outcome = await app.api.post("/organizations/current/sso/domains/verify");
        mount(
          results,
          notice(outcome.checks.map((check) => `${check.domain}: ${CHECK_TEXT[check.result] || check.result}`).join(" · "), {
            kind: outcome.checks.every((check) => check.result === "verified" || check.result === "already_verified") ? "success" : "info",
          }),
        );
        if (outcome.checks.some((check) => check.result === "verified")) setTimeout(() => app.refresh(), 1500);
      }, { kind: "secondary" }),
    },
    results,
    table(
      [
        { title: "Domain", render: (row) => h("strong", {}, row.domain) },
        { title: "Status", render: (row) => (row.verified ? badge("verified") : badge("pending", "warning")) },
        { title: "TXT record name", render: (row) => h("div", { class: "copyable" }, code(row.txt_record_name), copyButton(row.txt_record_name)) },
        { title: "Value", render: (row) => h("div", { class: "copyable" }, code(row.txt_record_value), copyButton(row.txt_record_value)) },
      ],
      configuration.domains,
    ),
  );
}

function scimSection(app) {
  const body = h("div", {});
  const base = `${location.origin}/scim/v2`;
  const render = async () => {
    const tokens = await app.api.get("/organizations/current/scim-tokens");
    mount(
      body,
      definitionList([["SCIM base URL", h("div", { class: "copyable" }, code(base), copyButton(base))]]),
      form(
        {
          submitLabel: "Create a token",
          className: "form-inline",
          onSubmit: async ({ name, expires_in_days }, element) => {
            const created = await app.api.post("/organizations/current/scim-tokens", { name: name.trim(), expires_in_days: Number(expires_in_days) });
            await secretDialog({ title: `SCIM token ${created.name}`, secret: created.token, note: "Paste it into your identity provider's provisioning settings now: it is shown only once." });
            element.reset();
            await render();
          },
        },
        field("Name", input({ name: "name", required: true, maxlength: "100", placeholder: "Okta provisioning" })),
        field("Expires after (days)", input({ name: "expires_in_days", type: "number", min: "1", max: "365", value: "365", required: true })),
      ),
      table(
        [
          { title: "Token", render: (row) => h("div", {}, h("strong", {}, row.name), h("p", { class: "muted small" }, code(`${row.prefix}…`))) },
          { title: "Last used", render: (row) => time(row.last_used_at) },
          { title: "Expires", render: (row) => formatDate(row.expires_at) },
          { title: "Status", render: (row) => (row.revoked_at ? badge("revoked", "danger") : badge("active")) },
          {
            title: "",
            class: "actions",
            render: (row) =>
              row.revoked_at
                ? null
                : button("Revoke", async () => {
                    if (!(await confirmDialog({ title: `Revoke ${row.name}?`, message: "Provisioning with this token stops at once.", confirmLabel: "Revoke", danger: true }))) return;
                    await app.api.delete(`/organizations/current/scim-tokens/${row.id}`);
                    notify(`${row.name} was revoked.`, { kind: "success" });
                    await render();
                  }, { kind: "ghost" }),
          },
        ],
        tokens,
        { empty: "No SCIM tokens." },
      ),
    );
  };
  render().catch((error) => mount(body, notice(error.message, { kind: "danger" })));
  return section(
    "SCIM provisioning",
    { description: "Let your identity provider create, update and deactivate members (viewer or analyst; never owners). Tokens work on /scim/v2 only, for this organization." },
    body,
  );
}

export async function ssoPage(app) {
  let configuration = null;
  try {
    configuration = await app.api.get("/organizations/current/sso");
  } catch (error) {
    if (!(error instanceof ApiError && error.code === "sso_not_configured")) throw error;
  }
  const owner = app.context.role === "owner";

  if (!configuration) {
    return h(
      "div",
      { class: "stack" },
      pageHeader("Single sign-on", { description: "Sign members in through your organization's OpenID Connect provider (Okta, Microsoft Entra ID, Google Workspace, Keycloak…)." }),
      notice("Register NexusFlow at your provider as a web application first; its redirect URI is shown here once the provider is connected. The guide is docs/SSO.md.", { kind: "info" }),
      section("Connect a provider", {}, providerForm(app, null)),
    );
  }

  return h(
    "div",
    { class: "stack" },
    pageHeader("Single sign-on", {
      description: "Your organization's OpenID Connect provider.",
      actions: button("Remove single sign-on", async () => {
        const confirmed = await confirmDialog({
          title: "Remove single sign-on?",
          message: "Every session the provider opened ends, its links to accounts are forgotten and SSO stops being required. Accounts it created remain.",
          confirmLabel: "Remove",
          danger: true,
        });
        if (!confirmed) return;
        await app.api.delete("/organizations/current/sso");
        notify("Single sign-on was removed.", { kind: "success" });
        app.refresh();
      }, { kind: "danger-ghost" }),
    }),
    section(
      "Provider",
      {},
      definitionList([
        ["Issuer", code(configuration.issuer)],
        ["Redirect URI", h("div", { class: "copyable" }, code(configuration.redirect_uri), copyButton(configuration.redirect_uri))],
        ["Sign-in page", `Members choose "Sign in with your organization's identity provider" and enter the organization's slug.`],
        ["Required", configuration.sso_required ? badge("required", "warning") : "No"],
        ["Provider MFA trusted", configuration.trust_idp_mfa ? "Yes" : "No"],
        ["Updated", time(configuration.updated_at)],
      ]),
    ),
    domainsSection(app, configuration),
    section("Settings", {}, providerForm(app, configuration)),
    owner ? scimSection(app) : notice("SCIM tokens are managed by owners.", { kind: "info" }),
  );
}
