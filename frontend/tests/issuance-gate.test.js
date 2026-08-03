// Regression coverage for the "Issue credential" panel's blocking-flag
// gate (renderHeatCard, index.html): the backend (main.py's
// issue_credential) is the real enforcement -- it 409s issuance from a
// heat with an open blocking flag regardless of what the UI does. This
// just confirms the UI doesn't invite an action the API would reject:
// a reviewed heat with an open blocking flag should show a blocked
// notice instead of a working "Issue credential" button, and a heat
// with only non-blocking flags (or none) should still show the real
// panel, unaffected.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const FRONTEND_DIR = path.resolve(__dirname, "..");

function loadPageFunctions(htmlFilename) {
  const dom = new JSDOM('<!DOCTYPE html><html><body><form id="upload-form"></form></body></html>', {
    runScripts: "dangerously",
    url: "http://localhost/index.html",
  });
  const window = dom.window;

  const appJs = fs.readFileSync(path.join(FRONTEND_DIR, "app.js"), "utf8");
  window.eval(appJs);

  const html = fs.readFileSync(path.join(FRONTEND_DIR, htmlFilename), "utf8");
  const inlineScripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const pageScript = inlineScripts[inlineScripts.length - 1];
  window.eval(pageScript);

  return window;
}

function baseHeat(overrides) {
  return {
    id: "heat-1",
    heat_id: "H1",
    mass_kg: 50,
    alloy_composition: { Nd: 29.5 },
    test_results: null,
    reviewed: true,
    reviewed_by: "u@example.com",
    reviewed_at: "2026-01-01T00:00:00Z",
    fully_addressed: false,
    flagged_for_review: true,
    credential_id: null,
    flags: [],
    sublots: [],
    nonconformance_refs: [],
    ...overrides,
  };
}

test("a reviewed heat with an open blocking flag shows a blocked notice, not the issue panel", () => {
  const window = loadPageFunctions("index.html");
  window.credentials = [];
  const heat = baseHeat({
    flags: [
      {
        issue_type: "compliance_violation",
        field_name: "origin_country",
        severity: "blocking",
        human_readable_reason: "China is a covered origin.",
        source: "compliance_engine",
        status: "open",
      },
    ],
  });

  const card = window.renderHeatCard({ id: "doc-1" }, heat, []);

  assert.ok(!card.innerHTML.includes("Issue a credential from this heat"), "should not offer the issuance form");
  assert.ok(card.innerHTML.includes("can't be issued"), "expected the blocked notice");
});

test("a reviewed heat with only a resolved blocking flag still shows the working issue panel", () => {
  const window = loadPageFunctions("index.html");
  window.credentials = [];
  const heat = baseHeat({
    fully_addressed: true,
    flagged_for_review: false,
    flags: [
      {
        issue_type: "compliance_violation",
        field_name: "origin_country",
        severity: "blocking",
        human_readable_reason: "China is a covered origin.",
        source: "compliance_engine",
        status: "resolved",
        resolved_by: "u@example.com",
        resolved_at: "2026-01-01T01:00:00Z",
      },
    ],
  });

  const card = window.renderHeatCard({ id: "doc-1" }, heat, []);

  assert.ok(card.innerHTML.includes("Issue a credential from this heat"), "resolved flag should no longer block issuance");
  assert.ok(!card.innerHTML.includes("can't be issued"));
});

test("a reviewed heat with only a needs_review (non-blocking) flag still shows the working issue panel", () => {
  const window = loadPageFunctions("index.html");
  window.credentials = [];
  const heat = baseHeat({
    flags: [
      {
        issue_type: "low_confidence_extraction",
        field_name: "origin_country",
        severity: "needs_review",
        human_readable_reason: "Origin confidence marked low.",
        source: "compliance_engine",
        status: "open",
      },
    ],
  });

  const card = window.renderHeatCard({ id: "doc-1" }, heat, []);

  assert.ok(card.innerHTML.includes("Issue a credential from this heat"));
  assert.ok(!card.innerHTML.includes("can't be issued"));
});
