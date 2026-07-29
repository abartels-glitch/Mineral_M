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
