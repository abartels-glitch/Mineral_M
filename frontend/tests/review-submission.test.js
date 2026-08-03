// Regression coverage for the Found zone's "Submit review" body
// (renderHeatCard, index.html): test_results had no editor anywhere in
// the UI, so it was never included in the /review request body at all
// -- meaning HeatReviewRequest.test_results defaulted to null and every
// single review submission silently wiped out any existing test_results
// on that heat, regardless of what a reviewer intended. Same silent-
// data-loss shape as this session's earlier flag-drop and concurrency
// fixes, just on a field with no UI to make the loss visible.
//
// Loads app.js's shared helpers plus index.html's own inline script into
// a real jsdom window, same technique as correction-panel.test.js.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const FRONTEND_DIR = path.resolve(__dirname, "..");

function loadPageFunctions(htmlFilename) {
  // #doc-list is needed too: onSaved's refreshAll() -> renderDocList()
  // reaches into it unconditionally -- without it, refreshAll() throws,
  // which (caught by the correction save handler's try/catch) silently
  // aborts before renderDocumentPanel(updatedDoc) ever runs, which would
  // make the next test below look like it caught a real staleness bug
  // when it was actually just an incomplete fixture.
  const dom = new JSDOM(
    '<!DOCTYPE html><html><body><form id="upload-form"></form><ul id="doc-list"></ul>' +
      '<section id="review-panel"><div id="review-content"></div></section></body></html>',
    { runScripts: "dangerously", url: "http://localhost/index.html" }
  );
  const window = dom.window;

  const appJs = fs.readFileSync(path.join(FRONTEND_DIR, "app.js"), "utf8");
  window.eval(appJs);

  const html = fs.readFileSync(path.join(FRONTEND_DIR, htmlFilename), "utf8");
  const inlineScripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const pageScript = inlineScripts[inlineScripts.length - 1];
  window.eval(pageScript);

  return window;
}

async function flushMicrotasks() {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
}

test("Submit review carries test_results forward unedited instead of silently nulling it", async () => {
  const window = loadPageFunctions("index.html");
  const calls = [];
  window.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, json: async () => ({}) };
  };
  window.credentials = [];
  window.documents = [];

  const heat = {
    id: "heat-1",
    heat_id: "H1",
    mass_kg: 50,
    alloy_composition: { Nd: 29.5 },
    test_results: { Br_kG: { value: 13.2, result: "pass" } },
    reviewed: false,
    flagged_for_review: false,
    flags: [],
    sublots: [],
    nonconformance_refs: [],
  };
  const card = window.renderHeatCard({ id: "doc-1" }, heat, []);
  const submitBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Submit review");
  assert.ok(submitBtn, "expected a Submit review button for an unreviewed heat");

  submitBtn.click();
  await flushMicrotasks();

  const reviewCall = calls.find((c) => c.url.includes("/review"));
  assert.ok(reviewCall, "expected a POST to /review");
  const body = JSON.parse(reviewCall.options.body);
  assert.deepEqual(
    body.test_results,
    { Br_kG: { value: 13.2, result: "pass" } },
    "test_results should round-trip unedited, not silently null out"
  );
});

test("Submit review sends null test_results when the heat genuinely has none", () => {
  const window = loadPageFunctions("index.html");
  const calls = [];
  window.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, json: async () => ({}) };
  };
  window.credentials = [];
  window.documents = [];

  const heat = {
    id: "heat-1",
    heat_id: "H1",
    mass_kg: 50,
    alloy_composition: {},
    test_results: null,
    reviewed: false,
    flagged_for_review: false,
    flags: [],
    sublots: [],
    nonconformance_refs: [],
  };
  const card = window.renderHeatCard({ id: "doc-1" }, heat, []);
  const submitBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Submit review");

  submitBtn.click();

  return flushMicrotasks().then(() => {
    const reviewCall = calls.find((c) => c.url.includes("/review"));
    assert.ok(reviewCall);
    const body = JSON.parse(reviewCall.options.body);
    assert.equal(body.test_results, null);
  });
});

test("Submit review after a same-session test_results correction sends the corrected value, not a stale pre-correction one", async () => {
  // Traces the exact path a reviewer would hit: correct test_results via
  // the correction panel (no page reload), then click Submit review.
  // renderCorrectionPanel's onSaved callback re-fetches the document and
  // fully re-renders the heat card -- this confirms that re-render is
  // what the next "Submit review" click actually binds to, not a stale
  // `heat` object captured before the correction landed. Exactly the
  // kind of stale-read bug the concurrency work this session was
  // hunting, just at the frontend/single-session level rather than
  // across concurrent requests.
  const window = loadPageFunctions("index.html");

  const originalHeat = {
    id: "heat-1",
    heat_id: "H1",
    mass_kg: 50,
    alloy_composition: { Nd: 29.5 },
    test_results: { Br_kG: { value: 13.2, result: "pass" } },
    reviewed: false,
    flagged_for_review: true,
    fully_addressed: false,
    flags: [
      {
        issue_type: "missing_field",
        field_name: "test_results",
        severity: "needs_review",
        human_readable_reason: "Only one test result reported.",
        source: "extraction",
        status: "open",
      },
    ],
    sublots: [],
    nonconformance_refs: [],
  };
  // What the server would actually hold after the correction lands --
  // the flag resolved, and a second test result added by the reviewer.
  const correctedTestResults = {
    Br_kG: { value: 13.2, result: "pass" },
    Hci_kOe: { value: 11.5, result: "pass" },
  };
  const updatedHeat = {
    ...originalHeat,
    test_results: correctedTestResults,
    flagged_for_review: false,
    fully_addressed: true,
    flags: [{ ...originalHeat.flags[0], status: "resolved", resolved_by: "u@example.com", resolved_at: "2026-01-01T00:00:00Z" }],
  };
  const doc = { id: "doc-1", raw_text: "", certificate_id: null, supplier_id: null, heats: [originalHeat] };
  const updatedDoc = { ...doc, heats: [updatedHeat] };

  const calls = [];
  window.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.includes("/correct")) return { ok: true, status: 200, json: async () => updatedHeat };
    if (url.endsWith("/documents/doc-1")) return { ok: true, status: 200, json: async () => updatedDoc };
    if (url.includes("/audit-trail")) return { ok: true, status: 200, json: async () => [] };
    if (url.endsWith("/documents")) return { ok: true, status: 200, json: async () => [] };
    if (url.endsWith("/credentials")) return { ok: true, status: 200, json: async () => [] };
    return { ok: true, status: 200, json: async () => ({}) };
  };

  await window.renderDocumentPanel(doc);
  const content = window.document.getElementById("review-content");

  // Save the test_results correction via the panel's real save button.
  const saveBtn = [...content.querySelectorAll("button")].find((b) => b.textContent === "Save correction");
  assert.ok(saveBtn, "expected a working save button for the test_results flag");
  saveBtn.click();
  await flushMicrotasks();
  await flushMicrotasks();

  const correctCall = calls.find((c) => c.url.includes("/correct"));
  assert.ok(correctCall, "expected the correction to have been submitted");

  // The panel's onSaved callback re-fetches and fully re-renders --
  // find the *new* Submit review button now in the DOM and click it.
  const submitBtn = [...content.querySelectorAll("button")].find((b) => b.textContent === "Submit review");
  assert.ok(submitBtn, "expected a freshly re-rendered Submit review button");
  submitBtn.click();
  await flushMicrotasks();

  const reviewCall = [...calls].reverse().find((c) => c.url.includes("/review"));
  assert.ok(reviewCall, "expected a POST to /review");
  const body = JSON.parse(reviewCall.options.body);
  assert.deepEqual(
    body.test_results,
    correctedTestResults,
    "Submit review used a stale, pre-correction test_results value instead of the freshly corrected one"
  );
});
