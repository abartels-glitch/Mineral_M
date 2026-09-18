// Regression coverage for the button system introduced by the token-driven
// design rebuild (tokens.css/components.css/layout.css). The previous
// version of this file guarded against passport.css's bare `button { ... }`
// base rule outranking a dozen one-off per-page button classes
// (.rq-submit-btn, .icon-btn, .rq-save-btn, .dash-link-btn, etc.) — that
// specific fragility no longer exists by construction: every button in the
// app now gets an explicit `.btn` class plus exactly one of
// `.btn--primary`/`.btn--secondary`/`.btn--tertiary`/`.btn--icon`, and
// there is no bare `<button>` fallback style anywhere for a stray class to
// accidentally outrank.
//
// What *can* still regress: `.btn` and its variant modifiers are equal-
// specificity single-class selectors (0,1,0) — a variant only wins the
// properties it shares with `.btn` (border, height, padding, background)
// because it's declared *later* in components.css. A future edit that
// reordered these rules would silently break every button's chrome. This
// file checks that invariant directly (source order) and proves it
// behaviorally for the one variant that actually overrides shared
// properties (.btn--tertiary, which zeroes out .btn's height/padding).
//
// Same jsdom caveat as before, verified empirically for this version too:
// getComputedStyle resolves simple longhand values (padding, height)
// reliably but not the `background` shorthand or var() custom properties —
// so padding/height are what's used to prove the cascade winner, and the
// color-bearing variants (primary/secondary's border-color) are checked
// structurally against the real CSS source instead of through jsdom.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const FRONTEND_DIR = path.resolve(__dirname, "..");
const componentsCss = fs.readFileSync(path.join(FRONTEND_DIR, "components.css"), "utf8");

test("components.css declares .btn before its variant modifiers (source-order invariant the cascade depends on)", () => {
  const baseIndex = componentsCss.indexOf(".btn {");
  assert.ok(baseIndex >= 0, "expected a bare .btn { ... } base rule in components.css");
  for (const variant of ["--primary", "--secondary", "--tertiary", "--icon", "--sm", "--lg", "--block"]) {
    const variantIndex = componentsCss.indexOf(`.btn${variant} {`);
    assert.ok(variantIndex >= 0, `expected a .btn${variant} rule in components.css`);
    assert.ok(variantIndex > baseIndex, `.btn${variant} must be declared after the base .btn rule to win the cascade`);
  }
});

test(".btn--primary and .btn--secondary each declare their own border-color, distinct from the base's transparent border", () => {
  const primary = componentsCss.match(/\.btn--primary\s*\{([^}]*)\}/);
  const secondary = componentsCss.match(/\.btn--secondary\s*\{([^}]*)\}/);
  assert.ok(primary && /border-color:\s*var\(--color-accent\)/.test(primary[1]), ".btn--primary should set border-color to the accent token");
  assert.ok(secondary && /border-color:\s*var\(--color-border-strong\)/.test(secondary[1]), ".btn--secondary should set border-color to the border-strong token");
});

test(".btn--tertiary's cascade win over the base .btn rule is real, not just declared", () => {
  const dom = new JSDOM(
    `<!DOCTYPE html><html><head><style>${componentsCss}</style></head><body>
      <button id="base" class="btn">x</button>
      <button id="tertiary" class="btn btn--tertiary">x</button>
    </body></html>`,
    { pretendToBeVisual: true }
  );
  const { document, getComputedStyle } = dom.window;
  const base = getComputedStyle(document.getElementById("base"));
  const tertiary = getComputedStyle(document.getElementById("tertiary"));
  assert.notEqual(tertiary.padding, base.padding, "expected .btn--tertiary's own padding (0), not the base rule's");
  assert.notEqual(tertiary.height, base.height, "expected .btn--tertiary's own height (auto), not the base rule's fixed height");
});

test("every .btn variant used across the app pages is one of the approved modifiers", () => {
  const PAGES = ["login.html", "scan.html", "index.html", "keys.html", "passport.html", "admin.html", "accept-invite.html"];
  const allowed = new Set(["primary", "secondary", "tertiary", "icon", "sm", "lg", "block"]);
  const found = new Set();
  for (const page of PAGES) {
    const html = fs.readFileSync(path.join(FRONTEND_DIR, page), "utf8").replace(/<!--[\s\S]*?-->/g, "");
    for (const m of html.matchAll(/btn--([a-z]+)/g)) found.add(m[1]);
  }
  for (const f of found) {
    assert.ok(allowed.has(f), `found .btn--${f} in use, which is not one of the approved modifiers`);
  }
  assert.ok(found.size > 0, "expected to find at least one .btn variant in use across the app");
});
