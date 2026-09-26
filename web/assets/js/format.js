// Display formatting in the reader's locale. Timestamps from the API are ISO
// 8601 in UTC; the console shows them in local time, with the exact UTC value
// in the element's title.

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const dateOnly = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const number = new Intl.NumberFormat();

function parse(value) {
  if (value === null || value === undefined || value === "") return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(value) {
  const date = parse(value);
  return date ? dateTime.format(date) : "—";
}

export function formatDate(value) {
  const date = parse(value);
  return date ? dateOnly.format(date) : "—";
}

const utcDay = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeZone: "UTC" });

/** A UTC calendar day (report periods, analytics): the same date in every time zone. */
export function formatDay(value) {
  const date = parse(value);
  return date ? utcDay.format(date) : "—";
}

const UNITS = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

/** "3 minutes ago", "in 2 days". */
export function formatRelative(value, now = Date.now()) {
  const date = parse(value);
  if (!date) return "—";
  const seconds = Math.round((date.getTime() - now) / 1000);
  if (Math.abs(seconds) < 45) return relative.format(0, "second");
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size || unit === "second") {
      return relative.format(Math.round(seconds / size), unit);
    }
  }
  return relative.format(seconds, "second");
}

export function formatNumber(value) {
  return value === null || value === undefined ? "—" : number.format(value);
}

export function formatBytes(value) {
  if (value === null || value === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? size : size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
}

/** "api_keys:manage" -> "Api keys: manage"; "rest_api" -> "Rest api". */
export function humanize(value) {
  if (!value) return "";
  const text = String(value).replace(/[_:]+/g, (match) => (match.includes(":") ? ": " : " "));
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** A local date ("2026-09-26") as the ISO instant at the start (or end) of that UTC day. */
export function dayBoundary(localDate, end = false) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(localDate || "")) return null;
  return `${localDate}T${end ? "23:59:59" : "00:00:00"}Z`;
}
