// A column chart of changes per day (one series). Thin columns with rounded
// data ends on one baseline, a 2px gap between neighbours, hairline grid, clean
// y ticks; a tooltip per column on hover and on keyboard focus (arrow keys walk
// the days); unusual days carry a ring above their column, keyed below; the
// numbers are always one click away in a table. Colours come from CSS tokens
// (--series-1, --grid, --axis, --muted), chosen for light and dark separately.

import { h, mount, svg } from "./dom.js";
import { formatNumber } from "./format.js";

const MARGIN = { top: 16, right: 8, bottom: 28, left: 44 };
const PLOT_HEIGHT = 176;
const MAX_BAR = 24;
const GAP = 2;
const RADIUS = 4;

const dayLabel = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", timeZone: "UTC" });
const dayLong = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

function asDate(day) {
  return new Date(`${day}T00:00:00Z`);
}

/** Round tick steps: 1, 2 or 5 times a power of ten. */
export function niceStep(raw) {
  if (!(raw > 0)) return 1;
  const power = 10 ** Math.floor(Math.log10(raw));
  const fraction = raw / power;
  const step = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  return Math.max(1, step * power);
}

/** A column with a rounded top and a square foot on the baseline. */
function columnPath(x, y, width, baseline) {
  const height = baseline - y;
  if (height <= 0) return "";
  const r = Math.min(RADIUS, width / 2, height);
  return `M${x} ${baseline}V${y + r}Q${x} ${y} ${x + r} ${y}H${x + width - r}Q${x + width} ${y} ${x + width} ${y + r}V${baseline}Z`;
}

export function changeVolumeChart(daily, { unusual = [], title = "Changes per day" } = {}) {
  const unusualByDate = new Map(unusual.map((day) => [day.date, day]));
  const figure = h("figure", { class: "chart" });
  const canvas = h("div", { class: "chart-canvas" });
  const tooltip = h("div", { class: "chart-tooltip", role: "status", hidden: true });
  const days = daily.map((day) => ({ ...day, when: asDate(day.date) }));
  const maxValue = Math.max(0, ...days.map((day) => day.changes));
  const step = niceStep(maxValue / 4);
  const top = Math.max(step, Math.ceil(maxValue / step) * step);
  let active = days.length - 1;
  let width = 0;
  let columns = [];

  function showTooltip(index) {
    const day = days[index];
    const column = columns[index];
    if (!day || !column) return;
    columns.forEach((entry, position) => entry.bar.classList.toggle("active", position === index));
    const extra = unusualByDate.get(day.date);
    mount(
      tooltip,
      h("strong", { class: "chart-tooltip-value" }, formatNumber(day.changes)),
      h("span", { class: "chart-tooltip-label" }, day.changes === 1 ? " change" : " changes"),
      h("span", { class: "chart-tooltip-date" }, dayLong.format(day.when)),
      extra && h("span", { class: "chart-tooltip-note" }, `Unusual - usually about ${formatNumber(Math.round(extra.baseline))}`),
    );
    tooltip.hidden = false;
    const tipWidth = tooltip.offsetWidth || 160;
    const left = Math.min(Math.max(column.center - tipWidth / 2, 0), Math.max(0, width - tipWidth));
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${Math.max(0, column.top - 8)}px`;
  }

  function hideTooltip() {
    tooltip.hidden = true;
    columns.forEach((entry) => entry.bar.classList.remove("active"));
  }

  function draw(availableWidth) {
    width = Math.max(260, Math.floor(availableWidth));
    const plotWidth = width - MARGIN.left - MARGIN.right;
    const baseline = MARGIN.top + PLOT_HEIGHT;
    const slot = plotWidth / Math.max(1, days.length);
    const barWidth = Math.max(1, Math.min(MAX_BAR, slot - GAP));
    const y = (value) => baseline - (value / top) * PLOT_HEIGHT;
    const labelEvery = Math.max(1, Math.ceil(days.length / Math.max(2, Math.floor(plotWidth / 72))));

    const grid = [];
    for (let value = 0; value <= top; value += step) {
      const lineY = Math.round(y(value)) + 0.5;
      grid.push(
        svg("line", { x1: MARGIN.left, x2: width - MARGIN.right, y1: lineY, y2: lineY, class: value === 0 ? "chart-baseline" : "chart-grid" }),
        svg("text", { x: MARGIN.left - 8, y: lineY, class: "chart-tick", "text-anchor": "end", "dominant-baseline": "middle" }, formatNumber(value)),
      );
    }

    columns = days.map((day, index) => {
      const x = MARGIN.left + index * slot + (slot - barWidth) / 2;
      const columnTop = y(day.changes);
      const bar = svg("path", { d: columnPath(x, columnTop, barWidth, baseline), class: "chart-bar" });
      const hit = svg("rect", {
        x: MARGIN.left + index * slot,
        y: MARGIN.top,
        width: slot,
        height: PLOT_HEIGHT,
        class: "chart-hit",
        tabindex: index === active ? "0" : "-1",
        role: "img",
        "aria-label": `${dayLong.format(day.when)}: ${formatNumber(day.changes)} ${day.changes === 1 ? "change" : "changes"}${unusualByDate.has(day.date) ? ", unusual" : ""}`,
      });
      const marker = unusualByDate.has(day.date)
        ? svg("circle", { cx: x + barWidth / 2, cy: Math.max(MARGIN.top - 6, columnTop - 8), r: 3.5, class: "chart-marker" })
        : null;
      const label = index % labelEvery === 0
        ? svg("text", { x: x + barWidth / 2, y: baseline + 18, class: "chart-tick", "text-anchor": "middle" }, dayLabel.format(day.when))
        : null;
      hit.addEventListener("pointerenter", () => showTooltip(index));
      hit.addEventListener("pointermove", () => showTooltip(index));
      hit.addEventListener("pointerleave", hideTooltip);
      hit.addEventListener("focus", () => {
        active = index;
        showTooltip(index);
      });
      hit.addEventListener("blur", hideTooltip);
      hit.addEventListener("keydown", (event) => {
        const moves = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
        if (!(event.key in moves)) return;
        event.preventDefault();
        const next = Math.min(days.length - 1, Math.max(0, index + moves[event.key]));
        columns[index].hit.setAttribute("tabindex", "-1");
        columns[next].hit.setAttribute("tabindex", "0");
        columns[next].hit.focus();
      });
      return { bar, hit, marker, label, center: x + barWidth / 2, top: columnTop };
    });

    const chartHeight = MARGIN.top + PLOT_HEIGHT + MARGIN.bottom;
    mount(
      canvas,
      svg(
        "svg",
        { width, height: chartHeight, viewBox: `0 0 ${width} ${chartHeight}`, role: "group", "aria-label": `${title}. Use the arrow keys to move between days.` },
        grid,
        columns.map((column) => column.bar),
        columns.map((column) => column.marker),
        columns.map((column) => column.label),
        columns.map((column) => column.hit),
      ),
      tooltip,
    );
  }

  // Drawn at once at a typical width (scaled by CSS until measured), then at
  // the container's own width - a resize observer does not fire in a tab or
  // window that is not painting, and the chart must not wait for one.
  draw(720);
  const observer = new ResizeObserver((entries) => {
    if (!canvas.isConnected) {
      observer.disconnect(); // the page moved on: let the chart go
      return;
    }
    const next = Math.floor(entries[0].contentRect.width);
    if (next && next !== width) draw(next);
  });
  observer.observe(canvas);

  const table = h(
    "table",
    { class: "table compact" },
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Day"), h("th", { scope: "col", class: "numeric" }, "Changes"), h("th", { scope: "col" }, "Note"))),
    h(
      "tbody",
      {},
      days.map((day) =>
        h(
          "tr",
          {},
          h("td", {}, dayLong.format(day.when)),
          h("td", { class: "numeric" }, formatNumber(day.changes)),
          h("td", {}, unusualByDate.has(day.date) ? `Unusual (usually about ${formatNumber(Math.round(unusualByDate.get(day.date).baseline))})` : ""),
        ),
      ),
    ),
  );

  mount(
    figure,
    canvas,
    unusual.length > 0 &&
      h(
        "p",
        { class: "chart-key" },
        svg("svg", { width: 12, height: 12, viewBox: "0 0 12 12", "aria-hidden": "true" }, svg("circle", { cx: 6, cy: 6, r: 3.5, class: "chart-marker" })),
        " An unusual day: far from the period's typical volume",
      ),
    h("details", { class: "disclosure chart-table" }, h("summary", {}, "Show the numbers"), h("div", { class: "table-wrap" }, table)),
  );
  return figure;
}
