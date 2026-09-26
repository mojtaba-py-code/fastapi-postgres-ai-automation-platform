// The pages behind links from outside: finishing a sign-up, resetting a
// password, accepting an invitation (e-mails) and the identity provider's
// redirect back after single sign-on. The router already took the token or
// code out of the address bar.

import { href } from "../router.js";
import { field, form, h, input, link, loading, mount, notice, errorMessage } from "../ui.js";
import { PASSWORD_HINT, passwordSignIn, secondFactorStep, takePendingSso } from "./auth.js";

function passwordPair() {
  const password = input({ name: "password", type: "password", required: true, minlength: "12", maxlength: "128", autocomplete: "new-password" });
  const repeat = input({ name: "password_repeat", type: "password", required: true, autocomplete: "new-password" });
  const check = () => repeat.setCustomValidity(repeat.value && repeat.value !== password.value ? "The passwords are not the same." : "");
  password.addEventListener("input", check);
  repeat.addEventListener("input", check);
  return [field("Password", password, { hint: PASSWORD_HINT }), field("Repeat the password", repeat)];
}

function brokenLink(what) {
  return h(
    "div",
    { class: "stack" },
    h("h1", { tabindex: "-1" }, "This link is incomplete"),
    notice(`The ${what} link is missing its token. Open the link from the e-mail again, or ask for a new one.`, { kind: "warning" }),
    link("Go to sign in", href("/sign-in"), { kind: "secondary" }),
  );
}

// ------------------------------------------------------------------ sign-up

function completeSignup(app, token) {
  if (!token) return brokenLink("sign-up");
  return h(
    "div",
    { class: "stack" },
    h("h1", { tabindex: "-1" }, "Finish creating your account"),
    h("p", { class: "muted" }, "Your e-mail address is confirmed. Choose your name, your organization's name and a password."),
    form(
      {
        submitLabel: "Create the account",
        onSubmit: async (values) => {
          const tokens = await app.api.post(
            "/auth/register/complete",
            { token, password: values.password, full_name: values.full_name.trim(), organization_name: values.organization_name.trim() },
            { auth: false },
          );
          await app.signedIn(tokens);
        },
      },
      field("Your name", input({ name: "full_name", required: true, maxlength: "200", autocomplete: "name" })),
      field("Organization name", input({ name: "organization_name", required: true, maxlength: "200", autocomplete: "organization" }), {
        hint: "You become its owner. You can invite others once you are in.",
      }),
      passwordPair(),
    ),
  );
}

// ------------------------------------------------------------------ password reset

function resetPassword(app, token) {
  if (!token) return brokenLink("password reset");
  const container = h("div", { class: "stack" });
  mount(
    container,
    h("h1", { tabindex: "-1" }, "Choose a new password"),
    h("p", { class: "muted" }, "Every session of your account ends when the password changes."),
    form(
      {
        submitLabel: "Set the password",
        onSubmit: async (values) => {
          await app.api.post("/auth/password/reset", { token, new_password: values.password }, { auth: false });
          mount(
            container,
            h("h1", { tabindex: "-1" }, "Your password is changed"),
            notice("Sign in with the new password.", { kind: "success" }),
            link("Sign in", href("/sign-in"), { kind: "primary" }),
          );
          container.querySelector("h1")?.focus();
        },
      },
      passwordPair(),
    ),
  );
  return container;
}

// ------------------------------------------------------------------ invitation

function acceptInvitation(app, token) {
  if (!token) return brokenLink("invitation");
  const container = h("div", { class: "stack" });

  async function acceptAs(tokens, options) {
    app.session.start(tokens, options);
    await app.api.post("/auth/invitations/accept", { token });
    await app.signedIn(tokens, options);
  }

  function existingAccount(message) {
    mount(
      container,
      h("h1", { tabindex: "-1" }, "Sign in to accept"),
      message && notice(message, { kind: "info" }),
      h("p", { class: "muted" }, "Sign in with the account the invitation was sent to; it joins the organization at once."),
      passwordSignIn(app, { submitLabel: "Sign in and accept", onTokens: acceptAs }),
    );
    container.querySelector("h1")?.focus();
  }

  mount(
    container,
    h("h1", { tabindex: "-1" }, "Join your organization"),
    h("p", { class: "muted" }, "You have been invited. Create your account - or, if you already have one, sign in to accept."),
    form(
      {
        submitLabel: "Create the account and join",
        onSubmit: async (values) => {
          try {
            const tokens = await app.api.post("/auth/register/invitation", { token, password: values.password, full_name: values.full_name.trim() }, { auth: false });
            await app.signedIn(tokens);
          } catch (error) {
            if (error.code === "account_exists") {
              existingAccount("An account already uses this address.");
              return;
            }
            throw error;
          }
        },
      },
      field("Your name", input({ name: "full_name", required: true, maxlength: "200", autocomplete: "name" })),
      passwordPair(),
    ),
    h("p", { class: "links" }, h("button", { type: "button", class: "link-button", onClick: () => existingAccount() }, "I already have an account")),
  );
  return container;
}

// ------------------------------------------------------------------ single sign-on

async function ssoCallback(app, entry) {
  const pending = takePendingSso();
  const failure = (message) =>
    h(
      "div",
      { class: "stack" },
      h("h1", { tabindex: "-1" }, "Single sign-on did not finish"),
      notice(message, { kind: "danger" }),
      link("Back to sign in", href("/sign-in"), { kind: "secondary" }),
    );
  if (entry.error) {
    return failure(`Your identity provider answered: ${entry.errorDescription || entry.error}.`);
  }
  if (!pending || !entry.code || !entry.state) {
    return failure("This sign-in was not started in this browser tab, or it expired. Start again.");
  }
  if (pending.state !== entry.state) {
    // Not the answer to this tab's request (a forged or stale redirect).
    return failure("The identity provider's answer does not belong to this sign-in. Start again.");
  }
  const container = h("div", { class: "stack" }, loading("Finishing single sign-on…"));
  const options = { sso: true, persist: Boolean(pending.persist) };
  (async () => {
    try {
      const answer = await app.api.post("/auth/sso/callback", { code: entry.code, state: entry.state, binding: pending.binding }, { auth: false });
      if (answer.mfa_required) {
        mount(container, secondFactorStep(app, answer, (tokens) => app.signedIn(tokens, options)));
        container.querySelector("h1")?.focus();
      } else {
        await app.signedIn(answer, options);
      }
    } catch (error) {
      mount(container, failure(errorMessage(error)));
      container.querySelector("h1")?.focus();
    }
  })();
  return container;
}

export async function entryPage(app, entry) {
  switch (entry.path) {
    case "/complete-signup":
      return completeSignup(app, entry.token);
    case "/reset-password":
      return resetPassword(app, entry.token);
    case "/accept-invitation":
      return acceptInvitation(app, entry.token);
    case "/sso/callback":
      return ssoCallback(app, entry);
    default:
      return brokenLink("e-mail");
  }
}
