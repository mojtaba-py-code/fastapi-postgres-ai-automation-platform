// Signing in (password, then a second factor if the account has one), single
// sign-on, sign-up and password reset requests.

import { isSafeUrl } from "../dom.js";
import { href } from "../router.js";
import { tabStorage } from "../session.js";
import { button, checkbox, errorMessage, field, form, h, input, link, mount, notice } from "../ui.js";
import { describePasskeyError, passkeysSupported, usePasskey } from "../webauthn.js";

const SSO_PENDING_KEY = "nexusflow.console.sso";
export const PASSWORD_HINT = "At least 12 characters; a long passphrase is best. Common and breached passwords are refused.";

// ------------------------------------------------------------------ second factor

/**
 * The second step of a sign-in: a passkey, an authenticator code or a
 * recovery code, as ``challenge.methods`` allows. ``onTokens(tokens)`` runs
 * with the completed sign-in.
 */
export function secondFactorStep(app, challenge, onTokens) {
  const methods = new Set(challenge.methods || ["totp", "recovery_code"]);
  const container = h("div", { class: "stack" });
  const withPasskey = methods.has("webauthn") && passkeysSupported();

  async function passkey() {
    const { options } = await app.api.post("/auth/mfa/webauthn/begin", { mfa_token: challenge.mfa_token }, { auth: false });
    let credential;
    try {
      credential = await usePasskey(options);
    } catch (error) {
      throw new Error(describePasskeyError(error));
    }
    await onTokens(await app.api.post("/auth/mfa/webauthn/verify", { mfa_token: challenge.mfa_token, credential }, { auth: false }));
  }

  const codeForm = (label, hint, props) =>
    form(
      {
        submitLabel: "Verify",
        onSubmit: async ({ code }) => onTokens(await app.api.post("/auth/mfa/verify", { mfa_token: challenge.mfa_token, code: code.replace(/\s+/g, "") }, { auth: false })),
      },
      field(label, input({ name: "code", required: true, autocomplete: "one-time-code", spellcheck: "false", ...props }), { hint }),
    );

  const totp = methods.has("totp")
    ? codeForm("Code from your authenticator app", "The six digits your app shows now.", { inputmode: "numeric", pattern: "[0-9 ]{6,7}", maxlength: "7" })
    : null;
  const recovery = methods.has("recovery_code") ? codeForm("Recovery code", "One of the codes you saved when you set up two-step verification. Each works once.", { maxlength: "32" }) : null;
  const recoveryToggle = recovery && totp ? h("details", { class: "disclosure" }, h("summary", {}, "Use a recovery code instead"), recovery) : recovery;

  mount(
    container,
    h("h1", { tabindex: "-1" }, "Two-step verification"),
    h("p", { class: "muted" }, "Confirm it is you with your second factor."),
    withPasskey && button("Use a passkey", passkey, { kind: "primary" }),
    withPasskey && (totp || recovery) && h("p", { class: "divider" }, h("span", {}, "or")),
    methods.has("webauthn") && !passkeysSupported() && notice("This browser cannot use passkeys; use another of your factors.", { kind: "warning" }),
    totp,
    recoveryToggle,
    h("p", { class: "muted small" }, `This step expires in ${Math.max(1, Math.round((challenge.expires_in || 300) / 60))} minutes.`),
  );
  return container;
}

// ------------------------------------------------------------------ sign-in

/** A password sign-in form, with the second-factor step where needed. */
export function passwordSignIn(app, { onTokens, submitLabel = "Sign in", email = "" } = {}) {
  const container = h("div", { class: "stack" });
  let persist = false;
  const signInForm = form(
    {
      submitLabel,
      onSubmit: async (values) => {
        persist = Boolean(values.persist);
        const answer = await app.api.post("/auth/login", { email: values.email.trim(), password: values.password }, { auth: false });
        if (answer.mfa_required) {
          mount(container, secondFactorStep(app, answer, (tokens) => onTokens(tokens, { persist })));
          container.querySelector("h1")?.focus();
        } else {
          await onTokens(answer, { persist });
        }
      },
    },
    field("E-mail address", input({ name: "email", type: "email", required: true, autocomplete: "username", value: email })),
    field("Password", input({ name: "password", type: "password", required: true, autocomplete: "current-password" })),
    checkbox("Stay signed in in this tab", { name: "persist" }, { hint: "Keeps you signed in when you reload; ends when you close the tab." }),
  );
  mount(container, signInForm);
  return container;
}

function singleSignOn(app) {
  return form(
    {
      submitLabel: "Continue with single sign-on",
      submitKind: "secondary",
      onSubmit: async ({ organization, persist }) => {
        const started = await app.api.post("/auth/sso/start", { organization: organization.trim().toLowerCase() }, { auth: false });
        if (!isSafeUrl(started.authorization_url) || !started.authorization_url.startsWith("https://")) {
          throw new Error("The identity provider's address is not a secure one.");
        }
        // The state and the binding secret wait in this tab only, for the redirect back.
        tabStorage().setItem(SSO_PENDING_KEY, JSON.stringify({ state: started.state, binding: started.binding, persist: Boolean(persist), at: Date.now() }));
        location.assign(started.authorization_url);
        await new Promise(() => {}); // leaving the page
      },
    },
    field("Organization", input({ name: "organization", required: true, autocomplete: "organization", spellcheck: "false", pattern: "[A-Za-z0-9-]{1,63}", placeholder: "your-organization" }), {
      hint: "Your organization's short name (its slug), from your administrator.",
    }),
    checkbox("Stay signed in in this tab", { name: "persist" }),
  );
}

/** The pending single sign-on of this tab, taken (it is single-use). */
export function takePendingSso() {
  const storage = tabStorage();
  try {
    return JSON.parse(storage.getItem(SSO_PENDING_KEY) ?? "null");
  } catch {
    return null;
  } finally {
    storage.removeItem(SSO_PENDING_KEY);
  }
}

export function signInPage(app) {
  return h(
    "div",
    { class: "stack" },
    h("h1", { tabindex: "-1" }, "Sign in"),
    passwordSignIn(app, { onTokens: (tokens, options) => app.signedIn(tokens, options) }),
    h("p", { class: "links" }, h("a", { href: href("/forgot-password") }, "Forgot your password?"), h("a", { href: href("/sign-up") }, "Create an account")),
    h("details", { class: "disclosure" }, h("summary", {}, "Sign in with your organization's identity provider"), singleSignOn(app)),
  );
}

// ------------------------------------------------------------------ sign-up and reset

export function signUpPage(app) {
  const container = h("div", { class: "stack" });
  mount(
    container,
    h("h1", { tabindex: "-1" }, "Create an account"),
    h("p", { class: "muted" }, "Start with your e-mail address. We send it a link to finish: that proves the address is yours before any account exists."),
    form(
      {
        submitLabel: "Send the link",
        onSubmit: async ({ email }) => {
          await app.api.post("/auth/register", { email: email.trim() }, { auth: false });
          mount(
            container,
            h("h1", { tabindex: "-1" }, "Check your inbox"),
            notice("If the address can be used, a link to finish is on its way. It works for 24 hours.", { kind: "success" }),
            h("p", { class: "muted" }, "Already have an account at this address? The e-mail says so instead, and you can sign in or reset your password."),
            link("Back to sign in", href("/sign-in"), { kind: "secondary" }),
          );
          container.querySelector("h1")?.focus();
        },
      },
      field("E-mail address", input({ name: "email", type: "email", required: true, autocomplete: "email" })),
    ),
    h("p", { class: "links" }, h("a", { href: href("/sign-in") }, "I already have an account")),
  );
  return container;
}

export function forgotPasswordPage(app) {
  const container = h("div", { class: "stack" });
  mount(
    container,
    h("h1", { tabindex: "-1" }, "Reset your password"),
    h("p", { class: "muted" }, "We send a link to set a new password. Every session of the account ends when it is used."),
    form(
      {
        submitLabel: "Send the link",
        onSubmit: async ({ email }) => {
          await app.api.post("/auth/password/reset-request", { email: email.trim() }, { auth: false });
          mount(
            container,
            h("h1", { tabindex: "-1" }, "Check your inbox"),
            notice("If an account uses this address, a reset link is on its way. It works for 30 minutes.", { kind: "success" }),
            link("Back to sign in", href("/sign-in"), { kind: "secondary" }),
          );
          container.querySelector("h1")?.focus();
        },
      },
      field("E-mail address", input({ name: "email", type: "email", required: true, autocomplete: "email" })),
    ),
    h("p", { class: "links" }, h("a", { href: href("/sign-in") }, "Back to sign in")),
  );
  return container;
}

export { errorMessage };
