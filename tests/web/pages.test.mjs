// Pure helpers of the console's pages: defaults, descriptions and templates.

import assert from "node:assert/strict";
import { test } from "node:test";

import { ApiError } from "../../web/assets/js/api.js";
import { projectChoice } from "../../web/assets/js/choices.js";
import { describeCondition } from "../../web/assets/js/pages/alerting.js";
import { configTemplate } from "../../web/assets/js/pages/sources.js";
import { errorMessage } from "../../web/assets/js/ui.js";

test("the project to open on is the one with the most datasets, projects sorted by name", () => {
  const projects = [
    { id: "p-supplier", name: "Supplier onboarding" },
    { id: "p-pricing", name: "Competitor pricing" },
    { id: "p-empty", name: "Archive" },
  ];
  const datasets = [{ project_id: "p-pricing" }, { project_id: "p-pricing" }, { project_id: "p-supplier" }];
  const choice = projectChoice(projects, datasets);
  assert.deepEqual(choice.projects.map((project) => project.name), ["Archive", "Competitor pricing", "Supplier onboarding"]);
  assert.equal(choice.preferred, "p-pricing");
  assert.equal(projectChoice(projects).preferred, "p-empty"); // no datasets: the first by name
  assert.equal(projectChoice([]).preferred, null);
});

test("alert conditions read as sentences", () => {
  assert.equal(describeCondition({ type: "numeric_change", field: "price", direction: "increase", min_pct: 10 }), "price rises by 10 % or more");
  assert.equal(describeCondition({ type: "numeric_change", field: "price", direction: "decrease", min_pct: 15 }), "price falls by 15 % or more");
  assert.equal(describeCondition({ type: "numeric_change", field: "stock" }), "stock moves by 0 % or more");
  assert.equal(describeCondition({ type: "significance_at_least", level: "high" }), "Change of high significance or more");
  assert.equal(describeCondition({ type: "field_changed", field: "in_stock" }), "in_stock changes");
  assert.equal(describeCondition({ type: "change_type", change_types: ["created", "deleted"] }), "Records created or deleted");
  assert.equal(describeCondition({ type: "insight_risk_at_least", level: "critical" }), "AI analysis reports critical risk or more");
  assert.equal(describeCondition({ type: "run_failed" }), "A collection run fails");
});

test("a source template maps the dataset's own fields for every kind", () => {
  const fields = ["sku", "price"];
  assert.deepEqual(configTemplate("website", fields).fields, { sku: ".sku", price: ".price" });
  assert.equal(configTemplate("website", fields).render_javascript, false);
  assert.deepEqual(configTemplate("rest_api", fields).field_mapping, { sku: "sku", price: "price" });
  assert.equal(configTemplate("rest_api", fields).url.startsWith("https://"), true);
  assert.deepEqual(configTemplate("webhook", fields), { kind: "webhook", items_path: "items", field_mapping: { sku: "sku", price: "price" } });
  assert.deepEqual(configTemplate("file_upload", fields).column_mapping, { sku: "Sku", price: "Price" });
  assert.deepEqual(configTemplate("webhook", []).field_mapping, { id: "id", title: "title" }); // a dataset without fields yet
});

test("refusals read as what to do: guidance by code, else the API's own message", () => {
  const refusal = (error, message) => new ApiError(403, { error, message });
  assert.match(errorMessage(refusal("passkey_required", "x")), /requires signing in with a passkey/);
  // The API names the refused change; the console adds the way out.
  assert.equal(
    errorMessage(refusal("passkey_session_required", "Add passkeys from a session that signed in with one of your passkeys.")),
    "Add passkeys from a session that signed in with one of your passkeys. Sign out, then sign in with a passkey.",
  );
  assert.equal(errorMessage(refusal("would_lock_you_out", "Requiring passkeys would lock you out.")), "Requiring passkeys would lock you out.");
  assert.equal(errorMessage(new ApiError(429, { error: "rate_limited" }, 30)), "Too many requests. Try again in 30 seconds.");
  assert.equal(errorMessage(new Error("plain")), "plain");
});
