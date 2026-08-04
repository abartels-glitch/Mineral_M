const API_BASE = "";

async function apiFetch(path, options = {}) {
  const res = await fetch(API_BASE + path, options);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (e) {
      // ignore
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.status === 204 ? null : res.json();
}

async function requireAuth(allowedRoles) {
  let user;
  try {
    user = await apiFetch("/auth/me");
  } catch (e) {
    location.href = "/login.html";
    return null;
  }
  if (allowedRoles && !allowedRoles.includes(user.role)) {
    location.href = "/login.html";
    return null;
  }
  renderUserHeader(user);
  return user;
}

async function getCurrentUserOrNull() {
  // Unlike requireAuth(), never redirects — for pages like passport.html
  // that must stay fully usable when logged out, but show extra depth
  // when a session happens to exist.
  try {
    const user = await apiFetch("/auth/me");
    renderUserHeader(user);
    return user;
  } catch (e) {
    return null;
  }
}

// Renders the shared title+nav into <header id="header-root"></header> —
// index.html/passport.html/scan.html each have that empty placeholder
// instead of duplicating the markup. login.html has its own static
// <header> with no #header-root, so this is a deliberate no-op there:
// it's a pre-auth entry point that intentionally has no nav (see its
// own markup) and shouldn't grow one just because app.js is loaded
// everywhere.
//
// Composes with renderUserHeader() below via ordinary DOM ordering, not
// any shared state: this runs synchronously as soon as app.js loads
// (before any page's own inline <script> calls requireAuth()/
// getCurrentUserOrNull()), so by the time renderUserHeader() later does
// document.querySelector("header nav") and appends into it, that <nav>
// already exists with this function's links inside it. Neither
// function touches what the other wrote.
function renderHeader() {
  const root = document.getElementById("header-root");
  if (!root) return;
  // location.pathname is "/" (not "/index.html") when the app is loaded
  // from the bare root — StaticFiles(html=True) serves index.html there
  // without a redirect, so the URL bar never shows the .html path.
  const currentPath = location.pathname === "/" ? "/index.html" : location.pathname;
  const links = [
    { href: "/index.html", text: "Review queue" },
    { href: "/passport.html", text: "Passport lookup" },
    { href: "/scan.html", text: "Scan" },
  ];
  root.appendChild(el("h1", { text: "FEOC Compliance Passport (MVP)" }));
  root.appendChild(
    el(
      "nav",
      {},
      links.map((link) =>
        el("a", { href: link.href, text: link.text, class: link.href === currentPath ? "active" : null })
      )
    )
  );
}

renderHeader();

function renderUserHeader(user) {
  const nav = document.querySelector("header nav");
  if (!nav) return;
  const info = el("span", {
    class: "muted",
    style: "margin-left: 1rem",
    text: `${user.email}${user.org_name ? " · " + user.org_name : ""} (${user.role})`,
  });
  const logout = el("a", { href: "#", style: "margin-left: 1rem", text: "Log out" });
  logout.addEventListener("click", async (e) => {
    e.preventDefault();
    await apiFetch("/auth/logout", { method: "POST" });
    location.href = "/login.html";
  });
  nav.appendChild(info);
  nav.appendChild(logout);
}

// Light formatting for an audit_log entry's detail object, used by both
// index.html's correction history and passport.html's Timeline --
// avoids dumping raw JSON syntax (braces, quoted keys) in front of a
// logged-in reviewer/auditor. Not a full renderer: detail shapes vary
// per action, so a nested object/array value still falls back to
// JSON.stringify for itself rather than trying to format every
// possible shape specifically.
function formatAuditDetail(detail) {
  const keys = Object.keys(detail || {});
  if (!keys.length) return "—";
  return keys
    .map((k) => {
      const value = detail[k];
      const formatted =
        value === null || value === undefined ? "—" : typeof value === "object" ? JSON.stringify(value) : String(value);
      return `${k.replace(/_/g, " ")}: ${formatted}`;
    })
    .join("; ");
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined) continue;
    if (key === "text") node.textContent = value;
    else if (key === "html") node.innerHTML = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    if (child) node.appendChild(child);
  }
  return node;
}
