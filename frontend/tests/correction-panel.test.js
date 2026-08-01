// Regression coverage for renderCorrectionPanel (index.html): a flagged
// field whose current value is an object (e.g. alloy_composition) must
// render as a real structured representation, never a stringified
// "[object Object]" blob — and since the backend's /correct endpoint only
// accepts scalar corrections for heat-level fields today (see main.py's
// _HEAT_CORRECTABLE_FIELDS), an object-shaped field must not offer a
// "Save correction" button that would just 400 against the real API.
//
// Loads app.js's shared helpers plus index.html's own inline script into a
// real jsdom window and calls renderCorrectionPanel directly — no server,
// no network. index.html's own script ends with a trailing auto-run IIFE
// (requireAuth() -> fetch("/auth/me")); with no real backend to answer,
// that fetch rejects, but requireAuth() already catches its own failure
// (see app.js), so this is a harmless, self-contained no-op here — and it
// runs asynchronously, well after this file's synchronous assertions
// against the page's function declarations have already completed.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const FRONTEND_DIR = path.resolve(__dirname, "..");

function loadPageFunctions(htmlFilename) {
  // A minimal stand-in for the one element index.html's script wires up
  // at the top level (outside any function) as soon as it loads —
  // without it, that addEventListener call throws on a null element and
  // aborts the whole eval before it finishes, function hoisting or not.
  //
  // A `url` is required too: with no real backend to answer
  // fetch("/auth/me"), the page's own trailing auto-run IIFE hits
  // requireAuth()'s catch block, which does `location.href =
  // "/login.html"` — a relative URL that jsdom can't resolve (and
  // throws for) without a base URL configured, producing an unhandled
  // rejection that outlives this function's synchronous return.
  const dom = new JSDOM('<!DOCTYPE html><html><body><form id="upload-form"></form></body></html>', {
    runScripts: "dangerously",
    url: "http://localhost/index.html",
  });
  const window = dom.window;

  const appJs = fs.readFileSync(path.join(FRONTEND_DIR, "app.js"), "utf8");
  window.eval(appJs);

  const html = fs.readFileSync(path.join(FRONTEND_DIR, htmlFilename), "utf8");
  const inlineScripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const pageScript = inlineScripts[inlineScripts.length - 1]; // the page's own script, not a <script src="..."> tag
  window.eval(pageScript);

  return window;
}

test("object-shaped flagged field (alloy_composition) renders structured, not '[object Object]', and offers no broken save button", () => {
  const window = loadPageFunctions("index.html");
  const heat = {
    id: "heat-1",
    alloy_composition: { Nd: 29.5, Fe: 68.2, B: 1.0, Dy: 1.3 },
    sublots: [],
    flags: [
      {
        issue_type: "ambiguous_field",
        field_name: "alloy_composition",
        severity: "needs_review",
        human_readable_reason: "Dysprosium composition is ambiguous.",
        source: "extraction",
        status: "open",
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  assert.ok(container, "expected a correction panel to be rendered");
  const html = container.innerHTML;
  assert.ok(!html.includes("[object Object]"), `correction panel rendered a stringified object:\n${html}`);

  const inputValues = [...container.querySelectorAll("input")].map((i) => i.value);
  assert.ok(inputValues.includes("29.5"), "expected Nd's value 29.5 to render in a real input");
  assert.ok(inputValues.includes("Fe"), "expected the composition's element keys to render");

  assert.ok(
    !html.includes("Save correction"),
    "object-shaped field must not offer a save button — /correct can't actually save it today"
  );
  assert.ok(html.includes("isn't available yet"), "expected the redirect-to-full-review note");
});

test("scalar flagged field (heat_id) still renders a normal editable input and a working save button", () => {
  const window = loadPageFunctions("index.html");
  const heat = {
    id: "heat-1",
    heat_id: null,
    sublots: [],
    flags: [
      {
        issue_type: "missing_field",
        field_name: "heat_id",
        severity: "needs_review",
        human_readable_reason: "No heat number stated.",
        source: "extraction",
        status: "open",
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  assert.ok(container);
  assert.ok(
    container.innerHTML.includes("Save correction"),
    "scalar field should still offer a working quick-correction save button"
  );
  assert.equal(container.querySelectorAll("input[type=text]").length, 1);
});

test("resolved flags are excluded from the correction panel regardless of value shape", () => {
  const window = loadPageFunctions("index.html");
  const heat = {
    id: "heat-1",
    alloy_composition: { Nd: 29.5 },
    sublots: [],
    flags: [
      {
        issue_type: "ambiguous_field",
        field_name: "alloy_composition",
        severity: "needs_review",
        human_readable_reason: "Already resolved.",
        source: "extraction",
        status: "resolved",
        resolved_by: "someone@example.com",
        resolved_at: "2026-01-01T00:00:00Z",
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  assert.equal(container, null, "a heat with only resolved flags should render no correction panel at all");
});
