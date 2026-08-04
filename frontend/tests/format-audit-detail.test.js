// Regression coverage for app.js's formatAuditDetail, used by both
// index.html's correction history and passport.html's Timeline: the
// raw JSON.stringify(detail) it replaced dumped brace/quote syntax
// directly in front of a logged-in reviewer/auditor -- functional, but
// visibly rough against an otherwise polished page. Light key: value
// formatting, not a redesign.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const FRONTEND_DIR = path.resolve(__dirname, "..");

function loadAppJs() {
  const dom = new JSDOM("<!DOCTYPE html><html><body></body></html>", { runScripts: "dangerously" });
  dom.window.eval(fs.readFileSync(path.join(FRONTEND_DIR, "app.js"), "utf8"));
  return dom.window;
}

test("formats a flat detail object as readable key: value pairs, not raw JSON", () => {
  const window = loadAppJs();
  const result = window.formatAuditDetail({
    target: "heat",
    sublot_id: null,
    field_name: "mass_kg",
    previous_value: 182.5,
    corrected_value: 49.5,
  });
  assert.ok(!result.includes("{"), `should not contain raw JSON braces:\n${result}`);
  assert.ok(!result.includes('"'), `should not contain raw JSON quotes:\n${result}`);
  assert.ok(result.includes("field name: mass_kg"));
  assert.ok(result.includes("previous value: 182.5"));
  assert.ok(result.includes("corrected value: 49.5"));
  assert.ok(result.includes("sublot id: —"), "null should render as an em dash, not the literal word null");
});

test("empty detail renders as an em dash", () => {
  const window = loadAppJs();
  assert.equal(window.formatAuditDetail({}), "—");
});

test("a nested object/array value falls back to compact JSON for itself only", () => {
  const window = loadAppJs();
  const result = window.formatAuditDetail({
    open_flags_before: [{ issue_type: "compliance_violation", field_name: "origin_country" }],
    open_flags_after: [],
  });
  assert.ok(result.startsWith("open flags before:"));
  assert.ok(result.includes("open flags after: []"));
});
