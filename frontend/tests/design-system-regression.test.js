// CSS/visual regression coverage for the token-driven design system
// (tokens.css/components.css/layout.css, replacing the old "Attestation
// Record" passport.css/style.css/review.css trio). Rewritten alongside
// that rebuild — same intent as before (catch a broken stylesheet link, a
// color token drifting off-palette, a contrast regression), pointed at the
// new files/token names.
//
// Deliberately NOT a Playwright screenshot-diff suite: this app has exactly
// one dependency on purpose (jsdom -- see package.json's own description),
// and adding a real browser runtime is a bigger call than this pass
// warrants. jsdom's getComputedStyle does NOT resolve CSS custom
// properties or reliably expand shorthand (verified empirically), so this
// file does real, non-fake verification a different way: parsing the
// actual token values out of the real CSS source (so a future edit to the
// palette is what's tested, not a frozen copy) and computing genuine WCAG
// contrast ratios against them.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const FRONTEND_DIR = path.resolve(__dirname, "..");
const PAGES = ["login.html", "scan.html", "index.html", "keys.html", "passport.html", "admin.html", "accept-invite.html"];
const tokensCss = fs.readFileSync(path.join(FRONTEND_DIR, "tokens.css"), "utf8");
const componentsCss = fs.readFileSync(path.join(FRONTEND_DIR, "components.css"), "utf8");

function readHtmlWithoutComments(page) {
  const raw = fs.readFileSync(path.join(FRONTEND_DIR, page), "utf8");
  return raw.replace(/<!--[\s\S]*?-->/g, "");
}

// ---- WCAG 2.x contrast ratio (relative luminance formula, sRGB) ----
function srgbToLinear(c) {
  const cs = c / 255;
  return cs <= 0.03928 ? cs / 12.92 : Math.pow((cs + 0.055) / 1.055, 2.4);
}
function relativeLuminance(hex) {
  const h = hex.replace("#", "");
  const r = parseInt(h.substring(0, 2), 16);
  const g = parseInt(h.substring(2, 4), 16);
  const b = parseInt(h.substring(4, 6), 16);
  return 0.2126 * srgbToLinear(r) + 0.7152 * srgbToLinear(g) + 0.0722 * srgbToLinear(b);
}
function contrastRatio(hexA, hexB) {
  const lA = relativeLuminance(hexA);
  const lB = relativeLuminance(hexB);
  const lighter = Math.max(lA, lB);
  const darker = Math.min(lA, lB);
  return (lighter + 0.05) / (darker + 0.05);
}

function extractToken(varName) {
  const match = tokensCss.match(new RegExp(`--${varName}:\\s*(#[0-9a-fA-F]{3,8})`));
  assert.ok(match, `expected to find --${varName} declared in tokens.css`);
  return match[1];
}

const STATUS_STATES = ["verified", "pending", "flagged", "rejected"];
const TOKENS = {
  surface: extractToken("color-surface"),
  bg: extractToken("color-bg"),
  status: Object.fromEntries(STATUS_STATES.map((s) => [s, extractToken(`status-${s}-fg`)])),
};

// ---- The 4-state budget: never a 5th ad hoc status color ----
test("tokens.css declares exactly the 4 status states, no more", () => {
  const declared = [...tokensCss.matchAll(/--status-([a-z]+)-fg:/g)].map((m) => m[1]);
  assert.deepEqual(new Set(declared), new Set(STATUS_STATES));
});

test("components.css's .status-chip only ever defines the 4 approved modifiers (plus the --lg size variant)", () => {
  const modifiers = [...componentsCss.matchAll(/\.status-chip--([a-z]+)\s*\{/g)].map((m) => m[1]);
  const allowed = new Set([...STATUS_STATES, "lg"]);
  for (const m of modifiers) {
    assert.ok(allowed.has(m), `unexpected .status-chip--${m} — only ${[...allowed].join("/")} are approved`);
  }
});

// Every status-chip--<x> usage anywhere in the app (HTML markup or inline
// JS building class strings) must be one of the 4 states (or the --lg size
// modifier) — guards against a future page/edit introducing a 5th color.
test("every status-chip--<modifier> usage across all pages is an approved state", () => {
  const allowed = new Set([...STATUS_STATES, "lg"]);
  const found = new Set();
  for (const page of PAGES) {
    const html = readHtmlWithoutComments(page);
    for (const m of html.matchAll(/status-chip--([a-z]+)/g)) found.add(m[1]);
  }
  const appJs = fs.readFileSync(path.join(FRONTEND_DIR, "app.js"), "utf8");
  for (const m of appJs.matchAll(/status-chip--([a-z]+)/g)) found.add(m[1]);
  for (const f of found) {
    assert.ok(allowed.has(f), `found status-chip--${f} in use, which is not one of the approved states`);
  }
  assert.ok(found.size > 0, "expected to find at least one status-chip usage across the app");
});

// ---- Contrast: each status color against the real backgrounds it
// actually renders on (a panel/table surface, and the page background). ----
for (const state of STATUS_STATES) {
  for (const [bgName, bgHex] of [["--color-surface", TOKENS.surface], ["--color-bg", TOKENS.bg]]) {
    test(`--status-${state}-fg (${TOKENS.status[state]}) vs ${bgName} clears WCAG AA`, () => {
      const ratio = contrastRatio(TOKENS.status[state], bgHex);
      assert.ok(
        ratio >= 4.5,
        `--status-${state}-fg ${TOKENS.status[state]} on ${bgName} ${bgHex} is ${ratio.toFixed(2)}:1, below the 4.5:1 AA floor for normal text`
      );
    });
  }
}

test("components.css's .success rule points at --status-verified-fg, not a different/stale token", () => {
  const match = componentsCss.match(/\.success\s*\{[^}]*color:\s*var\((--[\w-]+)\)/);
  assert.ok(match, "expected .success { color: var(--...) } in components.css");
  assert.equal(match[1], "--status-verified-fg");
});

test("login.html has no .success-classed element today — flagged, not assumed", () => {
  // A failed login has no success state to render inline -- the successful
  // path just navigates to index.html. Asserting that explicitly here,
  // rather than silently fabricating a login.html .success check, so this
  // discrepancy stays visible instead of getting silently "fixed" by
  // testing something that isn't there.
  const html = readHtmlWithoutComments("login.html");
  assert.equal(/class="success"/.test(html), false);
});

// ---- favicon presence + resolvable path on every page ----
for (const page of PAGES) {
  test(`${page} declares a favicon that resolves given its directory depth`, () => {
    const html = readHtmlWithoutComments(page);
    const match = html.match(/<link\s+rel="icon"[^>]*href="([^"]+)"/);
    assert.ok(match, `expected a <link rel="icon"> in ${page}`);
    const href = match[1];
    // All five pages live flat in frontend/ (no subdirectories), and
    // StaticFiles mounts that directory at "/" (see backend/main.py) --
    // an absolute "/favicon.svg" resolves correctly from any of them.
    assert.equal(href, "/favicon.svg", `${page}: favicon href should be the absolute "/favicon.svg"`);
    assert.ok(
      fs.existsSync(path.join(FRONTEND_DIR, href.replace(/^\//, ""))),
      `${page} references ${href}, but that file doesn't exist on disk`
    );
  });
}

// ---- exactly one <header>, no unexpected nesting ----
for (const page of PAGES) {
  test(`${page} has exactly one <header>, with no unexpected nesting`, () => {
    const html = readHtmlWithoutComments(page);
    const headerOpenTags = html.match(/<header[\s>]/g) || [];
    assert.equal(headerOpenTags.length, 1, `${page}: expected exactly one <header>, found ${headerOpenTags.length}`);
  });
}

// ---- Stylesheet-link regression: every page must load the shared
// design-system files (tokens -> components -> layout). ----
for (const page of PAGES) {
  test(`${page} loads tokens.css, components.css, and layout.css`, () => {
    const html = readHtmlWithoutComments(page);
    assert.ok(/href="\/tokens\.css"/.test(html), `${page}: missing tokens.css link`);
    assert.ok(/href="\/components\.css"/.test(html), `${page}: missing components.css link`);
    assert.ok(/href="\/layout\.css"/.test(html), `${page}: missing layout.css link`);
  });
}

// ---- No page should still reference the retired stylesheets. ----
for (const page of PAGES) {
  test(`${page} does not reference the retired style.css/passport.css/review.css`, () => {
    const html = readHtmlWithoutComments(page);
    assert.ok(!/href="\/(style|passport|review)\.css"/.test(html), `${page}: still references a retired stylesheet`);
  });
}
