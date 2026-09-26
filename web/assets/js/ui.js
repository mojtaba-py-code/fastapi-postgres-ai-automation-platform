// Shared interface pieces. Everything is built with dom.js (text, never HTML).

import { ApiError } from "./api.js";
import { append, h, mount, svg } from "./dom.js";
import { formatDateTime, formatRelative, humanize } from "./format.js";
import { encodeQr } from "./qr.js";

// ------------------------------------------------------------------ messages

// Where the console can add guidance to the API's own (already readable) message.
const GUIDANCE = {
  network_error: "The service could not be reached. Check the connection and try again.",
  mfa_required: "This organization requires two-step verification. Set it up under Account → Security, then sign in with it.",
  sso_required: "This organization requires single sign-on: sign in through its identity provider.",
  sso_session_restricted: "You signed in through your organization's identity provider. Manage your account's password and second factors from a password sign-in.",
  passkey_required: "This organization requires signing in with a passkey. Add one under Account → Security, then sign in with it.",
  // The API names the change it refused; what the person can do about it:
  passkey_session_required: (error) => `${error.message} Sign out, then sign in with a passkey.`,
  ip_not_allowed: "Your network is not on this organization's allowlist.",
  permission_denied: "Your role does not allow this.",
  session_required: "This needs a signed-in session (API keys cannot do it).",
};

export function errorMessage(error) {
  if (error instanceof ApiError) {
    if (error.code === "rate_limited") {
      return `Too many requests. Try again${error.retryAfter ? ` in ${error.retryAfter} seconds` : " shortly"}.`;
    }
    const guidance = GUIDANCE[error.code];
    return (typeof guidance === "function" ? guidance(error) : guidance) || error.message;
  }
  return error?.message || "Something went wrong.";
}

let toastRoot = null;

/** A short-lived message in the corner (errors stay longer and are announced assertively). */
export function notify(message, { kind = "info", detail = null } = {}) {
  toastRoot ??= document.getElementById("toasts");
  if (!toastRoot) return;
  const toast = h(
    "div",
    { class: ["toast", `toast-${kind}`], role: kind === "error" ? "alert" : "status" },
    h("p", { class: "toast-message" }, message),
    detail && h("p", { class: "toast-detail" }, detail),
    h("button", { class: "toast-close", type: "button", "aria-label": "Dismiss", onClick: () => toast.remove() }, "×"),
  );
  toastRoot.append(toast);
  setTimeout(() => toast.remove(), kind === "error" ? 12_000 : 6_000);
}

export function showError(error) {
  notify(errorMessage(error), {
    kind: "error",
    detail: error instanceof ApiError && error.requestId ? `Reference: ${error.requestId}` : null,
  });
}

// ------------------------------------------------------------------ layout

export function pageHeader(title, { description, actions } = {}) {
  return h(
    "header",
    { class: "page-header" },
    h("div", {}, h("h1", { tabindex: "-1" }, title), description && h("p", { class: "page-description" }, description)),
    actions && h("div", { class: "page-actions" }, actions),
  );
}

export function section(title, { description, actions } = {}, ...children) {
  return h(
    "section",
    { class: "card" },
    (title || actions) &&
      h(
        "div",
        { class: "card-header" },
        h("div", {}, title && h("h2", {}, title), description && h("p", { class: "card-description" }, description)),
        actions && h("div", { class: "card-actions" }, actions),
      ),
    h("div", { class: "card-body" }, children),
  );
}

export function loading(label = "Loading…") {
  return h("div", { class: "loading", role: "status" }, h("span", { class: "spinner", "aria-hidden": "true" }), label);
}

export function emptyState(title, text, action) {
  return h("div", { class: "empty" }, h("p", { class: "empty-title" }, title), text && h("p", {}, text), action);
}

export function notice(text, { kind = "info", title } = {}) {
  return h("div", { class: ["notice", `notice-${kind}`], role: kind === "danger" ? "alert" : null }, title && h("strong", {}, title, " "), text);
}

/** Load ``load()`` into a placeholder; the rendered result replaces it. */
export function deferred(load, render, { label } = {}) {
  const slot = h("div", { class: "deferred" }, loading(label));
  (async () => {
    try {
      mount(slot, await render(await load()));
    } catch (error) {
      mount(slot, notice(errorMessage(error), { kind: "danger" }));
    }
  })();
  return slot;
}

// ------------------------------------------------------------------ controls

/** A button whose async handler locks it while it runs and reports its errors. */
export function button(label, onClick, { kind = "secondary", type = "button", disabled = false, title } = {}) {
  const element = h("button", { class: ["button", `button-${kind}`], type, disabled, title }, label);
  if (onClick) {
    element.addEventListener("click", async (event) => {
      if (element.getAttribute("aria-busy") === "true") return;
      element.setAttribute("aria-busy", "true");
      element.disabled = true;
      try {
        await onClick(event);
      } catch (error) {
        showError(error);
      } finally {
        element.removeAttribute("aria-busy");
        element.disabled = disabled;
      }
    });
  }
  return element;
}

export function link(label, target, { kind } = {}) {
  return h("a", { href: target, class: kind ? ["button", `button-${kind}`] : null }, label);
}

let fieldCounter = 0;

/** A labelled control. ``control`` is an input, select or textarea (its id is set here). */
export function field(label, control, { hint, name } = {}) {
  fieldCounter += 1;
  const id = control.id || `field-${fieldCounter}`;
  control.id = id;
  if (name) control.name = name;
  const hintId = hint ? `${id}-hint` : null;
  const errorId = `${id}-error`;
  control.setAttribute("aria-describedby", [hintId, errorId].filter(Boolean).join(" "));
  return h(
    "div",
    { class: "field", dataset: { field: control.name || "" } },
    h("label", { for: id }, label),
    control,
    hint && h("p", { class: "hint", id: hintId }, hint),
    h("p", { class: "field-error", id: errorId, hidden: true }),
  );
}

export function input(props = {}) {
  return h("input", { class: "input", ...props });
}

export function textarea(props = {}) {
  return h("textarea", { class: "input", rows: 4, ...props });
}

export function select(options, props = {}) {
  const element = h("select", { class: "input", ...props });
  for (const option of options) {
    const [value, label] = Array.isArray(option) ? option : [option, humanize(option)];
    element.append(h("option", { value, selected: props.value === value }, label));
  }
  if (props.value !== undefined) element.value = props.value;
  return element;
}

export function checkbox(label, props = {}, { hint } = {}) {
  fieldCounter += 1;
  const id = props.id || `check-${fieldCounter}`;
  const hintId = hint ? `${id}-hint` : null;
  const box = h("input", { type: "checkbox", ...props, id, "aria-describedby": hintId });
  return h(
    "div",
    { class: "checkbox" },
    box,
    h("div", { class: "checkbox-text" }, h("label", { for: id }, label), hint && h("span", { class: "hint", id: hintId }, hint)),
  );
}

/**
 * A form that runs ``onSubmit(values, form)`` once the browser's own validation
 * passes. API validation errors are shown next to their fields (by ``name``),
 * anything else above the buttons.
 */
export function form({ onSubmit, submitLabel = "Save", submitKind = "primary", secondary, className }, ...children) {
  const submit = h("button", { class: ["button", `button-${submitKind}`], type: "submit" }, submitLabel);
  const problem = h("div", { class: "form-error", role: "alert", hidden: true });
  const element = h("form", { class: ["form", className] }, children, problem, h("div", { class: "form-actions" }, submit, secondary));
  element.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.getAttribute("aria-busy") === "true") return;
    clearErrors(element, problem);
    submit.setAttribute("aria-busy", "true");
    submit.disabled = true;
    try {
      await onSubmit(values(element), element);
    } catch (error) {
      showFormError(element, problem, error);
    } finally {
      submit.removeAttribute("aria-busy");
      submit.disabled = false;
    }
  });
  return element;
}

function values(formElement) {
  const result = {};
  for (const control of formElement.elements) {
    if (!control.name || control.disabled) continue;
    if (control.type === "checkbox") {
      if (control.dataset.group) {
        (result[control.name] ??= []);
        if (control.checked) result[control.name].push(control.value);
      } else {
        result[control.name] = control.checked;
      }
    } else if (control.type === "file") {
      result[control.name] = control.files?.[0] ?? null;
    } else if (control.type !== "submit" && control.type !== "button") {
      result[control.name] = control.value;
    }
  }
  return result;
}

function clearErrors(formElement, problem) {
  problem.hidden = true;
  problem.replaceChildren();
  for (const message of formElement.querySelectorAll(".field-error")) {
    message.hidden = true;
    message.replaceChildren();
  }
  for (const control of formElement.querySelectorAll("[aria-invalid]")) control.removeAttribute("aria-invalid");
}

function showFormError(formElement, problem, error) {
  let placed = false;
  const unplaced = [];
  if (error instanceof ApiError && error.details) {
    for (const detail of error.details) {
      // "settings.allowed_ip_ranges.0" -> the first part that names a control
      const control = String(detail.field || "")
        .split(".")
        .map((part) => {
          const found = part ? formElement.elements.namedItem(part) : null;
          return found instanceof RadioNodeList ? found[0] : found;
        })
        .find(Boolean);
      const box = control?.closest?.(".field")?.querySelector(".field-error");
      if (box) {
        box.replaceChildren(detail.message || humanize(detail.code || "invalid"));
        box.hidden = false;
        control.setAttribute("aria-invalid", "true");
        placed = true;
      } else {
        unplaced.push(detail);
      }
    }
  }
  if (!placed || unplaced.length || !(error instanceof ApiError && error.status === 422)) {
    problem.replaceChildren(
      h("p", {}, errorMessage(error)),
      unplaced.length > 0 &&
        h("ul", { class: "problems" }, unplaced.map((detail) => h("li", {}, detail.field ? `${detail.field}: ` : "", detail.message || humanize(detail.code || "invalid")))),
      error instanceof ApiError && error.requestId ? h("p", { class: "hint" }, `Reference: ${error.requestId}`) : null,
    );
    problem.hidden = false;
  }
  (formElement.querySelector("[aria-invalid='true']") || problem).focus?.();
}

// ------------------------------------------------------------------ data display

const TONES = {
  active: "success", succeeded: "success", ready: "success", processed: "success", completed: "success", verified: "success", resolved: "success", success: "success", public: "neutral",
  queued: "info", running: "info", pending: "info", generating: "info", processing: "info", accepted: "info", acknowledged: "info", internal: "info",
  paused: "warning", warning: "warning", medium: "warning", confidential: "warning", archived: "neutral", expired: "neutral", cancelled: "neutral", low: "neutral", info: "info",
  error: "danger", failed: "danger", rejected: "danger", quarantined: "danger", disabled: "danger", critical: "danger", high: "danger", denied: "danger", failure: "danger", open: "danger", restricted: "danger",
};

export function badge(text, tone) {
  return h("span", { class: ["badge", `badge-${tone || TONES[String(text).toLowerCase()] || "neutral"}`] }, humanize(text));
}

export function time(value, { relative = true } = {}) {
  if (!value) return h("span", { class: "muted" }, "—");
  return h("time", { datetime: value, title: `${formatDateTime(value)} (${value})` }, relative ? formatRelative(value) : formatDateTime(value));
}

export function code(text) {
  return h("code", {}, text);
}

/** ``[{title, render(row), class}]`` over ``rows``. */
export function table(columns, rows, { empty = "Nothing here yet.", caption } = {}) {
  if (!rows.length) return emptyState(empty);
  return h(
    "div",
    { class: "table-wrap" },
    h(
      "table",
      { class: "table" },
      caption && h("caption", { class: "visually-hidden" }, caption),
      h("thead", {}, h("tr", {}, columns.map((column) => h("th", { scope: "col", class: column.class }, column.title)))),
      h("tbody", {}, rows.map((row) => h("tr", {}, columns.map((column) => h("td", { class: column.class }, column.render(row)))))),
    ),
  );
}

/** A table that pages with the API's keyset cursors ("Load more"). */
export function pagedTable(columns, fetchPage, { empty, caption } = {}) {
  const rows = [];
  const container = h("div", { class: "paged" }, loading());
  let cursor = null;
  async function more() {
    const page = await fetchPage(cursor);
    rows.push(...page.items);
    cursor = page.next_cursor;
    render();
  }
  function render() {
    mount(
      container,
      table(columns, rows, { empty, caption }),
      cursor && h("div", { class: "table-more" }, button("Load more", more)),
    );
  }
  more().catch((error) => mount(container, notice(errorMessage(error), { kind: "danger" })));
  return container;
}

export function definitionList(pairs) {
  return h("dl", { class: "definitions" }, pairs.filter(Boolean).map(([term, value]) => [h("dt", {}, term), h("dd", {}, value)]));
}

/** Pretty JSON as text (never as HTML). */
export function jsonBlock(value) {
  return h("pre", { class: "json" }, JSON.stringify(value, null, 2));
}

// ------------------------------------------------------------------ clipboard

export function copyButton(text, label = "Copy") {
  return button(label, async (event) => {
    await navigator.clipboard.writeText(text);
    const target = event.currentTarget;
    const original = target.textContent;
    target.textContent = "Copied";
    setTimeout(() => (target.textContent = original), 1500);
  }, { kind: "ghost" });
}

// ------------------------------------------------------------------ dialogs

let dialogCounter = 0;

/**
 * A modal dialog and its one way out: ``dismiss(answer)`` closes it, removes
 * it and hands ``answer`` on - at once, not on the "close" event, which a
 * browser may deliver late (a background tab). Escape dismisses with
 * ``cancelValue``.
 */
function openDialog(title, body, actions, { onDismiss, cancelValue = null, wide = false } = {}) {
  dialogCounter += 1;
  const titleId = `dialog-title-${dialogCounter}`;
  const dialog = h(
    "dialog",
    { class: ["dialog", wide && "dialog-wide"], "aria-labelledby": titleId },
    h("h2", { id: titleId }, title),
    h("div", { class: "dialog-body" }, body),
    actions.length > 0 && h("div", { class: "dialog-actions" }, actions),
  );
  document.body.append(dialog);
  let dismissed = false;
  const dismiss = (answer) => {
    if (dismissed) return;
    dismissed = true;
    if (dialog.open) dialog.close();
    dialog.remove();
    onDismiss?.(answer);
  };
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    dismiss(cancelValue);
  });
  dialog.addEventListener("close", () => dismiss(cancelValue));
  dialog.showModal();
  return { dialog, dismiss };
}

/**
 * Ask before a consequential action. With ``requireText`` the person must type
 * it (an organization's slug before deleting it, say).
 */
export function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false, requireText = null }) {
  return new Promise((resolve) => {
    const typed = requireText ? input({ autocomplete: "off", spellcheck: "false" }) : null;
    const confirmButton = h("button", { class: ["button", danger ? "button-danger" : "button-primary"], type: "button", disabled: Boolean(requireText) }, confirmLabel);
    const cancelButton = h("button", { class: "button button-secondary", type: "button" }, "Cancel");
    const { dismiss } = openDialog(title, [h("p", {}, message), typed && field(`Type ${requireText} to confirm`, typed)], [cancelButton, confirmButton], {
      onDismiss: resolve,
      cancelValue: false,
    });
    typed?.addEventListener("input", () => (confirmButton.disabled = typed.value !== requireText));
    confirmButton.addEventListener("click", () => dismiss(true));
    cancelButton.addEventListener("click", () => dismiss(false));
    (typed || cancelButton).focus();
  });
}

/** Ask for a short text (a reason for the audit log, say); ``null`` when cancelled. */
export function promptDialog({ title, message, label, confirmLabel = "Confirm", danger = false, maxLength = 500, type = "text", value = "" }) {
  return new Promise((resolve) => {
    const text = input({ type, value, maxlength: String(maxLength), autocomplete: type === "password" ? "current-password" : "off" });
    const confirmButton = h("button", { class: ["button", danger ? "button-danger" : "button-primary"], type: "button" }, confirmLabel);
    const cancelButton = h("button", { class: "button button-secondary", type: "button" }, "Cancel");
    const { dismiss } = openDialog(title, [message && h("p", {}, message), field(label, text)], [cancelButton, confirmButton], { onDismiss: resolve });
    const read = () => (type === "password" ? text.value : text.value.trim());
    confirmButton.disabled = !read();
    text.addEventListener("input", () => (confirmButton.disabled = !read()));
    text.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && read()) {
        event.preventDefault();
        dismiss(read());
      }
    });
    confirmButton.addEventListener("click", () => dismiss(read()));
    cancelButton.addEventListener("click", () => dismiss(null));
    text.focus();
  });
}

/**
 * A small form in a dialog: ``fields`` are ``[{name, label, type, hint, value,
 * required, autocomplete, inputmode}]``. Resolves with the values, or ``null``.
 */
export function formDialog({ title, message, fields, confirmLabel = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    const controls = fields.map((spec) =>
      input({
        name: spec.name,
        type: spec.type || "text",
        value: spec.value || "",
        required: spec.required !== false,
        autocomplete: spec.autocomplete || (spec.type === "password" ? "current-password" : "off"),
        inputmode: spec.inputmode,
        maxlength: spec.maxLength ? String(spec.maxLength) : null,
      }),
    );
    const confirmButton = h("button", { class: ["button", danger ? "button-danger" : "button-primary"], type: "submit" }, confirmLabel);
    const cancelButton = h("button", { class: "button button-secondary", type: "button" }, "Cancel");
    const body = h(
      "form",
      { class: "form" },
      message && h("p", {}, message),
      fields.map((spec, index) => field(spec.label, controls[index], { hint: spec.hint })),
      h("div", { class: "dialog-actions" }, cancelButton, confirmButton),
    );
    const { dismiss } = openDialog(title, body, [], { onDismiss: resolve });
    body.addEventListener("submit", (event) => {
      event.preventDefault();
      dismiss(Object.fromEntries(fields.map((spec, index) => [spec.name, spec.type === "password" ? controls[index].value : controls[index].value.trim()])));
    });
    cancelButton.addEventListener("click", () => dismiss(null));
    controls[0]?.focus();
  });
}

/** A read-only dialog (a record's history, an audit entry's details). */
export function infoDialog(title, body) {
  const close = h("button", { class: "button button-primary", type: "button" }, "Close");
  const { dismiss } = openDialog(title, body, [close], { wide: true });
  close.addEventListener("click", () => dismiss(null));
  close.focus();
}

/**
 * Show a secret exactly once (an API key, a SCIM token), with a copy button.
 * ``details`` are further ``[label, value]`` pairs to copy (a webhook's URL).
 */
export function secretDialog({ title, secret, note, details = [] }) {
  return new Promise((resolve) => {
    const done = h("button", { class: "button button-primary", type: "button" }, "I have stored it");
    const { dismiss } = openDialog(title, [
      notice(note || "Copy it now: it is shown only once and cannot be recovered.", { kind: "warning" }),
      details.map(([label, value]) => h("div", { class: "field" }, h("span", { class: "hint" }, label), h("div", { class: "copyable" }, h("code", {}, value), copyButton(value)))),
      h("div", { class: "field" }, details.length > 0 && h("span", { class: "hint" }, "Secret"), h("div", { class: "secret" }, h("code", { class: "secret-value" }, secret), copyButton(secret))),
    ], [done], { onDismiss: () => resolve() });
    done.addEventListener("click", () => dismiss(null));
    done.focus();
  });
}

/** Recovery codes, once: copy or save them as a text file. */
export function recoveryCodesDialog(codes) {
  return new Promise((resolve) => {
    const text = `NexusFlow recovery codes (each works once)\n\n${codes.join("\n")}\n`;
    const save = h("button", { class: "button button-secondary", type: "button" }, "Save as file");
    const done = h("button", { class: "button button-primary", type: "button" }, "I have stored them");
    save.addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
      const anchor = h("a", { href: url, download: "nexusflow-recovery-codes.txt" });
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    });
    const { dismiss } = openDialog("Your recovery codes", [
      notice("Keep these somewhere safe. Each code signs you in once if you lose your second factor. They are shown only now.", { kind: "warning" }),
      h("ol", { class: "recovery-codes" }, codes.map((value) => h("li", {}, h("code", {}, value)))),
      copyButton(codes.join("\n"), "Copy all"),
    ], [save, done], { onDismiss: () => resolve() });
    done.addEventListener("click", () => dismiss(null));
    done.focus();
  });
}

// ------------------------------------------------------------------ QR code

/** A QR code as inline SVG - dark on light whatever the theme, for scanners. */
export function qrCode(text, label = "QR code") {
  const matrix = encodeQr(text);
  const border = 4;
  const size = matrix.length + border * 2;
  let path = "";
  matrix.forEach((row, y) => row.forEach((dark, x) => {
    if (dark) path += `M${x + border} ${y + border}h1v1h-1z`;
  }));
  return svg(
    "svg",
    { class: "qr", viewBox: `0 0 ${size} ${size}`, role: "img", "aria-label": label, "shape-rendering": "crispEdges" },
    svg("rect", { width: size, height: size, fill: "#ffffff" }),
    svg("path", { d: path, fill: "#000000" }),
  );
}

export { append, h, mount };
