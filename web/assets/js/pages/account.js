// Your account: profile, password and second factors (passkeys, an
// authenticator app, recovery codes), signed-in sessions, and your data.
//
// A session opened by an organization's identity provider speaks for that
// organization only, so the account's password, second factors and deletion
// are managed from a password sign-in (the API refuses them otherwise).

import { ApiError } from "../api.js";
import { formatDateTime } from "../format.js";
import { href } from "../router.js";
import {
  badge,
  button,
  confirmDialog,
  copyButton,
  definitionList,
  errorMessage,
  field,
  form,
  formDialog,
  h,
  input,
  mount,
  notice,
  notify,
  pageHeader,
  promptDialog,
  qrCode,
  recoveryCodesDialog,
  section,
  table,
  time,
} from "../ui.js";
import { createPasskey, describePasskeyError, passkeysSupported } from "../webauthn.js";
import { PASSWORD_HINT } from "./auth.js";

const TABS = [
  ["profile", "Profile"],
  ["security", "Security"],
  ["sessions", "Sessions"],
  ["data", "Your data"],
];

// The factor a session signed in with, where the API reports it.
const FACTORS = { webauthn: "passkey", totp: "authenticator app", recovery_code: "recovery code" };

const SSO_NOTE =
  "You signed in through your organization's identity provider. That session speaks for the organization only, so your account's password, second factors and deletion are managed from a password sign-in (use a password reset link if the account has no password yet).";

// ------------------------------------------------------------------ profile

function profileTab(app) {
  const user = app.context.user;
  return section(
    "Profile",
    {},
    definitionList([
      ["E-mail address", user.email],
      ["Two-step verification", user.mfa_enabled ? badge("on", "success") : badge("off", "neutral")],
      ["Member since", formatDateTime(user.created_at)],
      ["Last sign-in", time(user.last_login_at)],
    ]),
    form(
      {
        submitLabel: "Save",
        className: "form-inline",
        onSubmit: async ({ full_name }) => {
          await app.api.patch("/users/me", { full_name: full_name.trim() });
          notify("Your name was saved.", { kind: "success" });
          await app.reloadContext();
        },
      },
      field("Your name", input({ name: "full_name", required: true, maxlength: "200", autocomplete: "name", value: user.full_name })),
    ),
  );
}

// ------------------------------------------------------------------ security

function passwordSection(app) {
  const password = input({ name: "new_password", type: "password", required: true, minlength: "12", maxlength: "128", autocomplete: "new-password" });
  const repeat = input({ name: "repeat", type: "password", required: true, autocomplete: "new-password" });
  const check = () => repeat.setCustomValidity(repeat.value && repeat.value !== password.value ? "The passwords are not the same." : "");
  password.addEventListener("input", check);
  repeat.addEventListener("input", check);
  return section(
    "Password",
    { description: "Changing it signs out every other session of your account." },
    form(
      {
        submitLabel: "Change the password",
        onSubmit: async (values, element) => {
          const tokens = await app.api.post("/auth/password/change", { current_password: values.current_password, new_password: values.new_password });
          app.session.rotate(tokens);
          element.reset();
          notify("Your password was changed; other sessions were signed out.", { kind: "success" });
        },
      },
      field("Current password", input({ name: "current_password", type: "password", required: true, autocomplete: "current-password" })),
      field("New password", password, { hint: PASSWORD_HINT }),
      field("Repeat the new password", repeat),
    ),
  );
}

function passkeysSection(app) {
  const body = h("div", {});
  const render = async () => {
    const passkeys = await app.api.get("/auth/webauthn/credentials");
    mount(
      body,
      table(
        [
          { title: "Passkey", render: (row) => h("div", {}, h("strong", {}, row.name), h("p", { class: "muted small" }, row.backed_up ? "Synced (backed up by its provider)" : row.backup_eligible ? "Can be synced" : "On this authenticator only")) },
          { title: "Added", render: (row) => time(row.created_at) },
          { title: "Last used", render: (row) => time(row.last_used_at) },
          {
            title: "",
            class: "actions",
            render: (row) =>
              h(
                "div",
                { class: "button-row" },
                button("Rename", async () => {
                  const name = await promptDialog({ title: "Rename the passkey", label: "Name", value: row.name, confirmLabel: "Rename", maxLength: 100 });
                  if (name === null) return;
                  await app.api.patch(`/auth/webauthn/credentials/${row.id}`, { name });
                  await render();
                }, { kind: "ghost" }),
                button("Remove", async () => {
                  const answer = await formDialog({
                    title: `Remove ${row.name}?`,
                    message: "It can no longer sign you in. Your last second factor cannot be removed this way.",
                    fields: [{ name: "password", label: "Your password", type: "password" }],
                    confirmLabel: "Remove",
                    danger: true,
                  });
                  if (!answer) return;
                  await app.api.post(`/auth/webauthn/credentials/${row.id}/delete`, { password: answer.password });
                  notify(`${row.name} was removed.`, { kind: "success" });
                  await app.reloadContext();
                }, { kind: "ghost" }),
              ),
          },
        ],
        passkeys,
        { empty: "No passkeys yet." },
      ),
    );
  };
  render().catch((error) => mount(body, notice(errorMessage(error), { kind: "danger" })));

  const add = passkeysSupported()
    ? button("Add a passkey", async () => {
        const answer = await formDialog({
          title: "Add a passkey",
          message: "Your device will ask you to confirm with its screen lock, fingerprint, face or security key.",
          fields: [
            { name: "password", label: "Your password", type: "password" },
            { name: "name", label: "Name", hint: "So you can tell your passkeys apart, e.g. \"Work laptop\".", required: false, value: "Passkey", maxLength: 100 },
          ],
          confirmLabel: "Continue",
        });
        if (!answer) return;
        const { options } = await app.api.post("/auth/webauthn/register/begin", { password: answer.password });
        let credential;
        try {
          credential = await createPasskey(options);
        } catch (error) {
          throw new Error(describePasskeyError(error));
        }
        const registered = await app.api.post("/auth/webauthn/register/finish", { name: answer.name || null, credential });
        notify(`${registered.passkey.name} was added.`, { kind: "success" });
        if (registered.recovery_codes?.length) await recoveryCodesDialog(registered.recovery_codes);
        await app.reloadContext();
      }, { kind: "primary" })
    : notice("This browser cannot create passkeys.", { kind: "warning" });

  return section(
    "Passkeys",
    {
      description: "The strongest second factor: it works only on this site, so a look-alike page cannot capture it, and there is nothing to type or intercept.",
      actions: add,
    },
    body,
  );
}

function authenticatorSection(app) {
  const body = h("div", { class: "stack" });
  const intro = () =>
    mount(
      body,
      h("p", { class: "muted" }, "Six-digit codes from an app such as Microsoft Authenticator, Google Authenticator or 1Password. A code is refused if it was already used."),
      h(
        "div",
        { class: "button-row" },
        button("Set up an authenticator app", async () => {
          const answer = await formDialog({ title: "Set up an authenticator app", fields: [{ name: "password", label: "Your password", type: "password" }], confirmLabel: "Continue" });
          if (!answer) return;
          try {
            const enrollment = await app.api.post("/auth/mfa/enroll", { password: answer.password });
            enroll(enrollment);
          } catch (error) {
            if (error instanceof ApiError && error.code === "mfa_enabled") {
              notify("An authenticator app is set up already. To replace it, turn two-step verification off and on again.", { kind: "info" });
              return;
            }
            throw error;
          }
        }),
      ),
    );

  const enroll = (enrollment) => {
    const grouped = enrollment.secret.replace(/(.{4})(?=.)/g, "$1 ");
    mount(
      body,
      h(
        "div",
        { class: "enroll" },
        h("div", { class: "enroll-qr" }, qrCode(enrollment.provisioning_uri, "QR code for your authenticator app")),
        h(
          "div",
          { class: "stack" },
          h("p", {}, "Scan the code with your authenticator app, or enter the key by hand:"),
          h("div", { class: "copyable" }, h("code", { class: "secret-value" }, grouped), copyButton(enrollment.secret, "Copy the key")),
          h("p", { class: "muted small" }, "On a phone, ", h("a", { href: enrollment.provisioning_uri }, "open the app directly"), "."),
          form(
            {
              submitLabel: "Turn it on",
              onSubmit: async ({ code }) => {
                const result = await app.api.post("/auth/mfa/confirm", { code: code.replace(/\s+/g, "") });
                notify("Your authenticator app is on.", { kind: "success" });
                await recoveryCodesDialog(result.recovery_codes);
                await app.reloadContext();
              },
            },
            field("The code your app shows now", input({ name: "code", required: true, inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}", maxlength: "7" })),
          ),
          button("Cancel", () => intro(), { kind: "ghost" }),
        ),
      ),
    );
  };

  intro();
  return section("Authenticator app", {}, body);
}

function disableSection(app) {
  return section(
    "Turn two-step verification off",
    { description: "Removes the authenticator app, every passkey and the recovery codes, and signs out every session. Organizations that require it will refuse this account until it is on again." },
    button("Turn it off…", async () => {
      const answer = await formDialog({
        title: "Turn two-step verification off?",
        fields: [
          { name: "password", label: "Your password", type: "password" },
          { name: "code", label: "A code from your authenticator app, or a recovery code", autocomplete: "one-time-code" },
        ],
        confirmLabel: "Turn it off",
        danger: true,
      });
      if (!answer) return;
      await app.api.post("/auth/mfa/disable", { password: answer.password, code: answer.code.replace(/\s+/g, "") });
      notify("Two-step verification is off. Sign in again.", { kind: "success" });
      app.session.end();
      app.context.reset();
      app.navigate("/sign-in");
    }, { kind: "danger" }),
  );
}

function securityTab(app) {
  if (app.session.sso) return notice(SSO_NOTE, { kind: "info" });
  return h(
    "div",
    { class: "stack" },
    passwordSection(app),
    passkeysSection(app),
    authenticatorSection(app),
    app.context.user.mfa_enabled && disableSection(app),
  );
}

// ------------------------------------------------------------------ sessions

function sessionsTab(app) {
  const body = h("div", {});
  const render = async () => {
    const sessions = await app.api.get("/users/me/sessions");
    mount(
      body,
      table(
        [
          { title: "Device", render: (row) => h("div", {}, h("strong", {}, row.device), row.current && h("span", {}, " ", badge("this session", "info"))) },
          { title: "Address", render: (row) => row.ip || "—" },
          { title: "Signed in", render: (row) => time(row.created_at) },
          { title: "Last active", render: (row) => time(row.last_used_at) },
          {
            title: "Second factor",
            render: (row) => (row.mfa_verified ? badge(FACTORS[row.mfa_method] || "passed", "success") : badge("no", "neutral")),
          },
          {
            title: "",
            class: "actions",
            render: (row) =>
              row.current
                ? null
                : button("End", async () => {
                    await app.api.delete(`/users/me/sessions/${row.id}`);
                    notify("The session was ended.", { kind: "success" });
                    await render();
                  }, { kind: "ghost" }),
          },
        ],
        sessions,
      ),
    );
  };
  render().catch((error) => mount(body, notice(errorMessage(error), { kind: "danger" })));
  return section(
    "Signed-in sessions",
    {
      description: app.session.sso
        ? "The sessions your organization's identity provider opened."
        : "Every device signed in to your account. Ending a session stops its tokens at once.",
      actions: button("Sign out everywhere", async () => {
        const confirmed = await confirmDialog({ title: "Sign out everywhere?", message: "Every session ends, this one included.", confirmLabel: "Sign out everywhere", danger: true });
        if (!confirmed) return;
        await app.api.post("/auth/logout-all");
        app.session.end();
        app.context.reset();
        app.navigate("/sign-in");
      }, { kind: "secondary" }),
    },
    body,
  );
}

// ------------------------------------------------------------------ data

function dataTab(app) {
  return h(
    "div",
    { class: "stack" },
    section(
      "A copy of your data",
      { description: "What the platform holds about you as a person: your account, memberships, sessions, passkeys (names and dates, no key material), the API keys you created, single sign-on links and your recent activity. Organizations' business data is theirs and not included." },
      app.session.sso
        ? notice(SSO_NOTE, { kind: "info" })
        : button("Download my data (JSON)", async () => {
            const name = await app.api.download("/users/me/export");
            notify(`${name} downloaded.`, { kind: "success" });
          }),
    ),
    section(
      "Delete your account",
      { description: "Your personal data is erased and every session ends. If you are an organization's only owner, appoint another owner or delete that organization first." },
      app.session.sso
        ? notice(SSO_NOTE, { kind: "info" })
        : button("Delete my account…", async () => {
            const answer = await formDialog({
              title: "Delete your account?",
              message: "This cannot be undone. Type your password to confirm.",
              fields: [{ name: "password", label: "Your password", type: "password" }],
              confirmLabel: "Delete my account",
              danger: true,
            });
            if (!answer) return;
            await app.api.post("/users/me/delete", { password: answer.password });
            app.session.end();
            app.context.reset();
            notify("Your account was deleted.", { kind: "success" });
            app.navigate("/sign-in");
          }, { kind: "danger" }),
    ),
  );
}

export function accountPage(app, { query }) {
  const tab = TABS.some(([key]) => key === query.tab) ? query.tab : "profile";
  const content = { profile: profileTab, security: securityTab, sessions: sessionsTab, data: dataTab }[tab](app);
  return h(
    "div",
    { class: "stack" },
    pageHeader("Your account", { description: app.context.user.email }),
    h(
      "nav",
      { class: "tabs", "aria-label": "Account" },
      TABS.map(([key, label]) => h("a", { href: href("/account", { tab: key }), class: ["tab", tab === key && "active"], "aria-current": tab === key ? "page" : null }, label)),
    ),
    content,
  );
}
