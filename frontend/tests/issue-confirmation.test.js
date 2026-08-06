// Regression coverage for Stage 5's confirm-then-sign-then-submit
// issuance flow (renderIssuePanel, index.html): clicking "Issue
// credential" must show the org user a human-readable confirmation of
// what they typed -- not the opaque signable bytes -- before anything
// gets signed, and the two-phase prepare/sign/submit sequence must run
// only after that confirmation, using this browser's own local key
// (never sending a private key or reconstructing the payload client-
// side). Mocks signing.js's exports directly (isEd25519Supported,
// getStoredKeyRecord, signBytesB64) rather than loading real Web Crypto/
// IndexedDB, which jsdom doesn't implement -- same "mock the boundary,
// not the DOM" approach as review-submission.test.js mocking fetch.
//
// window.fetch must be assigned BEFORE the page's inline script is
// eval'd, not after: index.html's bottom IIFE calls requireAuth()
// (-> apiFetch("/auth/me")) synchronously as the script loads, and its
// result is assigned to the module-scoped `currentUser` the issuance
// flow reads via plain closure, not via `window.currentUser` (a `let`
// at a vm-evaluated script's top level is a lexical binding, not a
// global-object property, so poking window.currentUder after the fact
// -- as other test files in this dir do for `credentials`/`documents`,
// harmlessly, since those already default to `[]` -- would silently
// not work here).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const FRONTEND_DIR = path.resolve(__dirname, "..");

function loadPageFunctions(htmlFilename, { fetchImpl, signingMocks }) {
  const dom = new JSDOM(
    '<!DOCTYPE html><html><body><form id="upload-form"></form><ul id="doc-list"></ul>' +
      '<section id="review-panel"><div id="review-content"></div></section></body></html>',
    { runScripts: "dangerously", url: "http://localhost/index.html" }
  );
  const window = dom.window;

  const appJs = fs.readFileSync(path.join(FRONTEND_DIR, "app.js"), "utf8");
  window.eval(appJs);

  window.isEd25519Supported = signingMocks.isEd25519Supported;
  window.getStoredKeyRecord = signingMocks.getStoredKeyRecord;
  window.signBytesB64 = signingMocks.signBytesB64;
  window.fetch = fetchImpl;

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

function baseFetchImpl(calls, extra = {}) {
  return async (url, options) => {
    calls.push({ url, options });
    if (url === "/auth/me") {
      return { ok: true, status: 200, json: async () => ({ id: "u1", org_id: "org-1", role: "org_user", email: "a@b.com", org_name: "Acme" }) };
    }
    if (url === "/documents") return { ok: true, status: 200, json: async () => [] };
    if (url === "/credentials") return { ok: true, status: 200, json: async () => [] };
    if (extra[url]) return extra[url];
    return { ok: true, status: 200, json: async () => ({}) };
  };
}

function reviewedHeatWithoutCredential() {
  return {
    id: "heat-1",
    heat_id: "H1",
    mass_kg: 50,
    alloy_composition: { Nd: 29.5, Fe: 65, B: 1 },
    test_results: null,
    reviewed: true,
    reviewed_by: "u@example.com",
    reviewed_at: "2026-01-01T00:00:00Z",
    fully_addressed: true,
    flagged_for_review: false,
    credential_id: null,
    flags: [],
    sublots: [],
    nonconformance_refs: [],
  };
}

function fillIssueForm(card, { materialType = "Sintered NdFeB Magnet Alloy", originCountry = "United States" } = {}) {
  const inputs = [...card.querySelectorAll(".rq-issue-panel input[type=text]")];
  // Order matches renderIssuePanel's construction: credentialType,
  // materialType, originCountry, massKg, heatNumber, supplierName.
  inputs[1].value = materialType;
  inputs[2].value = originCountry;
}

test("Issue credential shows a human-readable confirmation before signing anything", async () => {
  const calls = [];
  const window = loadPageFunctions("index.html", {
    fetchImpl: baseFetchImpl(calls),
    signingMocks: {
      isEd25519Supported: async () => true,
      getStoredKeyRecord: async () => ({ keyId: "key-1", privateKey: {} }),
      signBytesB64: async () => "sig",
    },
  });
  await flushMicrotasks();
  calls.length = 0;

  const card = window.renderHeatCard({ id: "doc-1", supplier_id: "Acme" }, reviewedHeatWithoutCredential(), []);
  fillIssueForm(card);
  const issueBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Issue credential");
  assert.ok(issueBtn, "expected an Issue credential button");

  issueBtn.click();
  await flushMicrotasks();

  assert.equal(calls.length, 0, "confirmation screen must appear before any network call, not after");
  assert.ok(card.innerHTML.includes("Confirm before signing"));
  assert.ok(card.innerHTML.includes("Sintered NdFeB Magnet Alloy"), "should show the actual typed material type");
  assert.ok(card.innerHTML.includes("United States"), "should show the actual typed origin country");
  assert.ok(!card.innerHTML.includes("signable_bytes"), "must never show the opaque signable bytes to the user");
});

test("Confirm & sign runs prepare, signs locally, then submits with the signature", async () => {
  const calls = [];
  const window = loadPageFunctions("index.html", {
    fetchImpl: baseFetchImpl(calls, {
      "/credentials/issue/prepare": {
        ok: true,
        status: 200,
        json: async () => ({
          credential_id: "cred-123",
          issued_at: "2026-01-02T00:00:00Z",
          document_id: null,
          document_content_hash: null,
          signable_bytes_b64: "opaque-bytes-from-server",
        }),
      },
      "/credentials/issue": { ok: true, status: 200, json: async () => ({ id: "cred-123" }) },
    }),
    signingMocks: {
      isEd25519Supported: async () => true,
      getStoredKeyRecord: async () => ({ keyId: "key-1", privateKey: { marker: "the-local-private-key" } }),
      signBytesB64: async (privateKey, bytesB64) => {
        assert.equal(privateKey.marker, "the-local-private-key", "must sign with this browser's own local key");
        assert.equal(bytesB64, "opaque-bytes-from-server");
        return "signature-abc";
      },
    },
  });
  await flushMicrotasks();
  calls.length = 0;

  const card = window.renderHeatCard({ id: "doc-1", supplier_id: "Acme" }, reviewedHeatWithoutCredential(), []);
  fillIssueForm(card);
  const issueBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Issue credential");
  issueBtn.click();
  await flushMicrotasks();

  const confirmBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Confirm & sign");
  assert.ok(confirmBtn, "expected a Confirm & sign button after reviewing the confirmation screen");
  confirmBtn.click();
  await flushMicrotasks();

  const prepareCall = calls.find((c) => c.url === "/credentials/issue/prepare");
  assert.ok(prepareCall, "expected a POST to /credentials/issue/prepare");
  const submitCall = calls.find((c) => c.url === "/credentials/issue");
  assert.ok(submitCall, "expected a POST to /credentials/issue (submit)");
  const submitBody = JSON.parse(submitCall.options.body);
  assert.equal(submitBody.credential_id, "cred-123", "must submit the server-issued credential_id from prepare, not invent one");
  assert.equal(submitBody.issued_at, "2026-01-02T00:00:00Z");
  assert.equal(submitBody.key_id, "key-1");
  assert.equal(submitBody.signature_b64, "signature-abc");
  assert.equal(submitBody.material_type, undefined, "submit body must not flatten subject fields at top level");
});

test("Issue credential with no registered local key shows an actionable error instead of calling prepare", async () => {
  const calls = [];
  const window = loadPageFunctions("index.html", {
    fetchImpl: baseFetchImpl(calls),
    signingMocks: {
      isEd25519Supported: async () => true,
      getStoredKeyRecord: async () => null,
      signBytesB64: async () => {
        throw new Error("should never be called");
      },
    },
  });
  await flushMicrotasks();
  calls.length = 0;

  const card = window.renderHeatCard({ id: "doc-1", supplier_id: "Acme" }, reviewedHeatWithoutCredential(), []);
  fillIssueForm(card);
  const issueBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Issue credential");
  issueBtn.click();
  await flushMicrotasks();

  const confirmBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Confirm & sign");
  confirmBtn.click();
  await flushMicrotasks();

  assert.equal(calls.length, 0, "must not call prepare/issue when this browser has no registered key");
  assert.ok(card.innerHTML.toLowerCase().includes("register"), "error should point the user at registering a key");
});

test("Issue credential on an unsupported browser shows a clear message instead of failing silently", async () => {
  const calls = [];
  const window = loadPageFunctions("index.html", {
    fetchImpl: baseFetchImpl(calls),
    signingMocks: {
      isEd25519Supported: async () => false,
      getStoredKeyRecord: async () => {
        throw new Error("should never be called");
      },
      signBytesB64: async () => {
        throw new Error("should never be called");
      },
    },
  });
  await flushMicrotasks();
  calls.length = 0;

  const card = window.renderHeatCard({ id: "doc-1", supplier_id: "Acme" }, reviewedHeatWithoutCredential(), []);
  fillIssueForm(card);
  const issueBtn = [...card.querySelectorAll("button")].find((b) => b.textContent === "Issue credential");
  issueBtn.click();
  await flushMicrotasks();

  assert.equal(calls.length, 0);
  assert.ok(!card.innerHTML.includes("Confirm before signing"), "should not offer to sign on an unsupported browser");
  assert.ok(card.innerHTML.toLowerCase().includes("update") || card.innerHTML.toLowerCase().includes("support"));
});
