// Element builders that never parse HTML. Every string becomes a text node or
// an attribute value, so nothing the API returns can turn into markup or
// script. The console's Content-Security-Policy enforces the same rule in the
// browser (Trusted Types with no policy: the HTML sinks are refused).

const SVG_NS = "http://www.w3.org/2000/svg";

// URL schemes an href may carry: in-app routes, the API's own paths, download
// blobs, the authenticator-app link of a TOTP set-up, and nothing else.
const SAFE_SCHEMES = new Set(["https:", "http:", "blob:", "otpauth:", "mailto:"]);

const PROPERTIES = new Set(["value", "checked", "disabled", "selected", "hidden", "indeterminate"]);

/** Whether ``value`` is a URL the console may link to (never ``javascript:``). */
export function isSafeUrl(value, base = globalThis.location?.origin ?? "https://localhost") {
  if (typeof value !== "string") return false;
  if (value.startsWith("#") || (value.startsWith("/") && !value.startsWith("//"))) return true;
  try {
    return SAFE_SCHEMES.has(new URL(value, base).protocol);
  } catch {
    return false;
  }
}

/** An HTML element: ``h("button", {class: "primary", onClick}, "Save")``. */
export function h(tag, props = {}, ...children) {
  const element = document.createElement(tag);
  setProps(element, props ?? {});
  append(element, children);
  return element;
}

/** An SVG element (attributes only). */
export function svg(tag, attributes = {}, ...children) {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    element.setAttribute(name, String(value));
  }
  append(element, children);
  return element;
}

function setProps(element, props) {
  for (const [name, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (name.startsWith("on") && typeof value === "function") {
      element.addEventListener(name.slice(2).toLowerCase(), value);
    } else if (name === "class") {
      element.className = Array.isArray(value) ? value.filter(Boolean).join(" ") : String(value);
    } else if (name === "dataset") {
      Object.assign(element.dataset, value);
    } else if (PROPERTIES.has(name)) {
      element[name] = value;
    } else if (name === "href" || name === "src" || name === "action") {
      if (!isSafeUrl(String(value))) throw new Error(`Refusing an unsafe URL in ${name}`);
      element.setAttribute(name, String(value));
    } else if (value === true) {
      element.setAttribute(name, "");
    } else {
      element.setAttribute(name, String(value));
    }
  }
}

/** Append children: nodes as they are, strings and numbers as text, arrays flattened. */
export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false || child === true) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

/** Replace everything inside ``parent``. */
export function mount(parent, ...children) {
  parent.replaceChildren();
  return append(parent, children);
}

/** A ``DocumentFragment`` of ``children``. */
export function fragment(...children) {
  return append(document.createDocumentFragment(), children);
}
