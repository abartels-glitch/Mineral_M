// Regression coverage for renderCorrectionPanel (index.html): a flagged
// field whose current value is an object must render as a real
// structured representation, never a stringified "[object Object]"
// blob. alloy_composition/test_results are now genuinely correctable in
// place (main.py's _HEAT_CORRECTABLE_FIELDS) and get a real editable
// sub-form with a working "Save correction" button; any other
// object/array-shaped field (nothing allowlisted for it on the backend)
// still gets the original locked read-only view + redirect note instead
// of a save button that would just 400.
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

async function flushMicrotasks() {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
}

test("alloy_composition flag renders structured, not '[object Object]', with a real editable sub-form", () => {
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
  assert.ok(inputValues.includes("29.5"), "expected Nd's value 29.5 to render in a real, editable input");
  assert.ok(inputValues.includes("Fe"), "expected the composition's element keys to render");

  assert.ok(html.includes("Save correction"), "alloy_composition is correctable now -- expected a working save button");
  assert.ok(!html.includes("isn't available yet"), "should no longer show the redirect-to-full-review note");
});

test("saving an alloy_composition correction POSTs the edited object, not a stringified value", async () => {
  const window = loadPageFunctions("index.html");
  const calls = [];
  window.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, json: async () => ({}) };
  };

  const heat = {
    id: "heat-1",
    alloy_composition: { Nd: 29.5, Fe: 68.2 },
    sublots: [],
    flags: [
      {
        issue_type: "ambiguous_field",
        field_name: "alloy_composition",
        severity: "needs_review",
        human_readable_reason: "Ambiguous.",
        source: "extraction",
        status: "open",
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  // Edit Fe's value in place via the real input, then click "Save correction".
  const feInput = [...container.querySelectorAll("input")].find((i) => i.value === "68.2");
  feInput.value = "68.5";
  const saveBtn = [...container.querySelectorAll("button")].find((b) => b.textContent === "Save correction");
  saveBtn.click();
  await flushMicrotasks();

  assert.equal(calls.length, 1, "expected exactly one /correct request");
  const body = JSON.parse(calls[0].options.body);
  assert.equal(body.target, "heat");
  assert.equal(body.field_name, "alloy_composition");
  assert.deepEqual(body.corrected_value, { Nd: 29.5, Fe: 68.5 }, "expected a real object, not a stringified one");
});

test("test_results flag renders a real editable sub-form and saves a well-shaped object", async () => {
  const window = loadPageFunctions("index.html");
  const calls = [];
  window.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, json: async () => ({}) };
  };

  const heat = {
    id: "heat-1",
    test_results: { Br_kG: { value: 13.2, result: "pass" } },
    sublots: [],
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
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  const html = container.innerHTML;
  assert.ok(!html.includes("[object Object]"));
  assert.ok(html.includes("Save correction"));
  const inputValues = [...container.querySelectorAll("input")].map((i) => i.value);
  assert.ok(inputValues.includes("Br_kG"));
  assert.ok(inputValues.includes("13.2"));
  const select = container.querySelector("select");
  assert.equal(select.value, "pass");

  const saveBtn = [...container.querySelectorAll("button")].find((b) => b.textContent === "Save correction");
  saveBtn.click();
  await flushMicrotasks();

  assert.equal(calls.length, 1);
  const body = JSON.parse(calls[0].options.body);
  assert.equal(body.field_name, "test_results");
  assert.deepEqual(body.corrected_value, { Br_kG: { value: 13.2, result: "pass" } });
});

test("test_results row with an unexpected shape renders read-only instead of guessing or crashing", () => {
  const window = loadPageFunctions("index.html");
  const heat = {
    id: "heat-1",
    test_results: { Br_kG: 13.2 }, // malformed: not {value, result}
    sublots: [],
    flags: [
      {
        issue_type: "missing_field",
        field_name: "test_results",
        severity: "needs_review",
        human_readable_reason: "Malformed legacy row.",
        source: "extraction",
        status: "open",
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  assert.ok(!container.innerHTML.includes("[object Object]"));
  assert.ok(container.innerHTML.includes("13.2"), "expected the malformed row's raw value to still be visible");
  const keyInput = [...container.querySelectorAll("input")].find((i) => i.value === "Br_kG");
  assert.ok(keyInput.disabled, "malformed row should render read-only, not an editable guess");
});

test("a still-unsupported list field (nonconformance_refs) keeps the read-only redirect fallback", () => {
  // nonconformance_refs is a list of strings (llm_extractor.HEAT_SCHEMA),
  // not a dict, and isn't in HEAT_CORRECTABLE_FIELDS -- the field_name
  // allowlist check (not object-shape detection) routes it to a
  // read-only explanation before a save button that would just 400
  // ever gets a chance to render.
  const window = loadPageFunctions("index.html");
  const heat = {
    id: "heat-1",
    nonconformance_refs: ["NCR-1"],
    sublots: [],
    flags: [
      {
        issue_type: "ambiguous_field",
        field_name: "nonconformance_refs",
        severity: "needs_review",
        human_readable_reason: "Ambiguous nonconformance reference.",
        source: "extraction",
        status: "open",
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  assert.ok(container);
  assert.ok(!container.innerHTML.includes("[object Object]"));
  assert.ok(!container.innerHTML.includes("Save correction"), "no allowlisted column for this field -- must not offer a save button");
  assert.ok(container.innerHTML.includes("doesn't have a direct correction here"));
});

test("a flattened duplicate of a sub-lot's compliance flag renders read-only, pointing at the sub-lot", () => {
  // heat.flags (main.py's HeatOut.flags) includes a flattened copy of
  // every sub-lot's own compliance_engine flag, alongside the heat's
  // own extraction-level ones -- this copy carries a real sublot_id
  // even though it appears in heat.flags, which used to make the panel
  // offer a heat-level save button for it that always 400'd (the real
  // fix lives on the sub-lot's own flag, rendered separately below).
  const window = loadPageFunctions("index.html");
  const heat = {
    id: "heat-1",
    sublots: [],
    flags: [
      {
        issue_type: "compliance_violation",
        field_name: "origin_country",
        severity: "blocking",
        human_readable_reason: "origin country 'China' is FEOC-covered",
        source: "compliance_engine",
        status: "open",
        sublot_id: "sublot-1",
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  assert.ok(container);
  assert.ok(!container.innerHTML.includes("Save correction"), "the flattened duplicate must not offer its own save button");
  assert.ok(container.innerHTML.includes("Resolved automatically when you correct the matching sub-lot below"));
});

test("an unresolved heat-level origin flag (sublot_id null) points at the sub-lot table, not a dead-end save button", () => {
  // The LLM's own heat-level flag about origin data (sublot_id=null,
  // source="extraction") -- distinct from the previous test's flattened
  // compliance_engine duplicate. No direct heat-level correction exists
  // for it (origin is inherently per-sub-lot), but unlike a genuinely
  // unmappable field, this one gets its own, more specific explanation
  // pointing at where the real fix happens, since it resolves
  // automatically (main.py's _resolve_heat_level_origin_flags_if_all_
  // sublots_clear) once every sub-lot is compliant.
  const window = loadPageFunctions("index.html");
  const heat = {
    id: "heat-1",
    sublots: [],
    flags: [
      {
        issue_type: "compliance_violation",
        field_name: "feedstock_sublots[0].origin_country", // LLM phrasing variant, not the plain name
        severity: "blocking",
        human_readable_reason: "Covered country China appears as origin of feedstock material.",
        source: "extraction",
        status: "open",
        sublot_id: null,
      },
    ],
  };
  const statusEl = window.document.createElement("p");
  const container = window.renderCorrectionPanel({ id: "doc-1" }, heat, statusEl, async () => {});

  assert.ok(container);
  assert.ok(!container.innerHTML.includes("Save correction"));
  assert.ok(container.innerHTML.includes("concerns a sub-lot's origin"));
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
