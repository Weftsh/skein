// Skein's UI: one small page, no build step, served from the binary.
//
// Two rules hold everywhere below:
//
// * Every string that came from the server — a package name, a licence,
//   a username, a refusal — reaches the page through `textContent`,
//   never `innerHTML`. Package names are chosen by whoever publishes, and
//   a registry UI that rendered one as markup would run it.
// * Every request carries `x-skein-csrf`. The server refuses a
//   state-changing request from a browser without it, which is what
//   stops a page elsewhere from acting with this session's cookie.

"use strict";

// ------------------------------------------------------------------ dom

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "html") throw new Error("no markup from data");
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const ICONS = {
  box: "M21 8l-9-5-9 5v8l9 5 9-5V8zM3 8l9 5 9-5M12 13v8",
  plug: "M9 2v6M15 2v6M6 8h12v3a6 6 0 01-12 0V8zM12 17v5",
  key: "M15 7a4 4 0 11-3.9 5H4v3H2v-5h9.1A4 4 0 0115 7z",
  users: "M16 19v-1a4 4 0 00-4-4H6a4 4 0 00-4 4v1M9 10a3 3 0 100-6 3 3 0 000 6zM22 19v-1a4 4 0 00-3-3.9M16 4.1a3 3 0 010 5.8",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  flag: "M4 22V4m0 0h13l-2 4 2 4H4",
  clock: "M12 22a10 10 0 100-20 10 10 0 000 20zM12 6v6l4 2",
  gear: "M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z",
  copy: "M8 8h12v12H8zM4 16V4h12",
};

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
  p.setAttribute("d", ICONS[name]);
  svg.append(p);
  return svg;
}

function logo(size) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("aria-hidden", "true");
  const r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  r.setAttribute("width", "32"); r.setAttribute("height", "32"); r.setAttribute("rx", "8");
  r.setAttribute("fill", "var(--surface-2)");
  svg.append(r);
  for (const y of [11, 16, 21]) {
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", `M8 ${y}c5-4 11 4 16 0`);
    p.setAttribute("stroke", "var(--brand)");
    p.setAttribute("stroke-width", "2.4");
    p.setAttribute("fill", "none");
    p.setAttribute("stroke-linecap", "round");
    svg.append(p);
  }
  return svg;
}

function toast(msg, kind) {
  const el = h("div", { class: kind || "" }, msg);
  document.getElementById("toast").append(el);
  setTimeout(() => el.remove(), kind === "bad" ? 7000 : 3500);
}

function copyButton(text) {
  return h("button", {
    class: "btn small copy", type: "button", title: "Copy", "aria-label": "Copy",
    onclick: async (e) => {
      e.stopPropagation();
      try { await navigator.clipboard.writeText(typeof text === "function" ? text() : text); toast("Copied", "good"); }
      catch { toast("Copy failed — select the text instead", "bad"); }
    },
  }, icon("copy"));
}

function codeblock(text) {
  return h("div", { class: "codeblock" }, h("pre", { class: "code" }, text), copyButton(text));
}

// --------------------------------------------------------------- format

const bytes = (n) => {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${i ? v.toFixed(v < 10 ? 1 : 0) : v} ${u[i]}`;
};

function ago(ms) {
  if (!ms) return "never";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 45) return "just now";
  const m = Math.round(s / 60); if (m < 60) return `${m} min ago`;
  const hr = Math.round(m / 60); if (hr < 36) return `${hr} h ago`;
  const d = Math.round(hr / 24); if (d < 60) return `${d} days ago`;
  return new Date(ms).toISOString().slice(0, 10);
}

function when(ms) {
  return h("span", { class: "nowrap", title: ms ? new Date(ms).toLocaleString() : "" }, ago(ms));
}

const ECO_LABEL = { npm: "npm", maven: "Maven", pypi: "PyPI", cargo: "Cargo", oci: "OCI" };
const ecoBadge = (e) => h("span", { class: "badge eco" }, ECO_LABEL[e] || e);

// ------------------------------------------------------------------ api

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const init = {
    method,
    credentials: "same-origin",
    headers: { "x-skein-csrf": "1", "accept": "application/json" },
  };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const r = await fetch(`/api/v1${path}`, init);
  if (r.status === 204) return null;
  let data = null;
  try { data = await r.json(); } catch { /* a body that is not JSON */ }
  if (!r.ok) {
    // Signed out underneath us — the session expired, or an admin
    // disabled this account. Only when we believed we were signed in:
    // `render` asks `/me` with `state.me` unset, and a 401 there is its
    // own answer, not a reason to render again.
    if (r.status === 401 && state.me && path !== "/session") {
      state.me = null;
      setTimeout(render);
    }
    throw new ApiError(r.status, (data && data.error) || `${r.status} ${r.statusText}`);
  }
  return data;
}

// Run an action, reporting a failure as a toast rather than an
// unhandled rejection nobody sees. It still throws, so the handler that
// awaited it stops there — a refused key does not go on to render as if
// it had been installed — and the throw is marked as already reported,
// so it does not then surface as an uncaught error in the console.
async function act(fn, done) {
  try { const out = await fn(); if (done) toast(done, "good"); return out; }
  catch (e) { toast(e.message, "bad"); e.reported = true; throw e; }
}
window.addEventListener("unhandledrejection", (ev) => {
  if (ev.reason && ev.reason.reported) ev.preventDefault();
});

// ---------------------------------------------------------------- state

const state = { me: null, overview: null, license: null };
const isAdmin = () => !!state.me && state.me.scopes.includes("org:admin");
const canWrite = () => !!state.me && (isAdmin() || state.me.scopes.includes("package:write"));
const base = () => (state.me && state.me.public_url) || location.origin;
const served = () => ((state.overview && state.overview.ecosystems) || []).filter((e) => e.served);

// --------------------------------------------------------------- router

function go(hash) { if (location.hash !== hash) location.hash = hash; else render(); }
window.addEventListener("hashchange", () => render());

const ROUTES = [
  [/^#\/?$/, () => packagesPage()],
  [/^#\/packages\/([0-9a-z]{26})$/, (m) => packagePage(m[1])],
  [/^#\/connect$/, () => connectPage()],
  [/^#\/tokens$/, () => tokensPage()],
  [/^#\/people$/, () => peoplePage()],
  [/^#\/policy$/, () => policyPage()],
  [/^#\/findings$/, () => findingsPage()],
  [/^#\/activity$/, () => activityPage()],
  [/^#\/settings$/, () => settingsPage()],
];

async function render() {
  const app = document.getElementById("app");
  if (location.hash === "#/login" || !state.me) {
    if (!state.me) {
      // `/session` answers 200 either way, so a first visit does not
      // begin with a refusal in the console.
      let s;
      try { s = await api("GET", "/session"); }
      catch (e) {
        app.replaceChildren(e.status === 503 ? setupScreen(e.message) : loginScreen());
        return;
      }
      if (!s.signed_in) { app.replaceChildren(loginScreen()); return; }
      state.me = s;
    }
    if (location.hash === "#/login") { location.hash = "#/"; return; }
  }
  if (!state.overview) {
    try { state.overview = await api("GET", "/overview"); } catch { state.overview = null; }
  }
  // Admins see what the licence says on every page. It never stops
  // anything, which is exactly why it has to be visible somewhere.
  if (isAdmin() && !state.license) {
    try { state.license = await api("GET", "/license"); } catch { state.license = null; }
  }
  const route = ROUTES.find(([re]) => re.test(location.hash || "#/"));
  const content = h("div", { class: "content" }, h("p", { class: "muted" }, "Loading…"));
  app.replaceChildren(h("div", { class: "shell" }, sidebar(), h("main", { class: "main" }, content)));
  try {
    const page = route ? await route[1](location.hash.match(route[0])) : notFound();
    content.replaceChildren(...[licenseBanner(), page].flat().filter(Boolean));
  } catch (e) {
    content.replaceChildren(h("div", { class: "notice bad" }, e.message));
  }
  document.title = `Skein · ${(state.overview && state.overview.org.name) || ""}`;
}

function notFound() {
  return h("div", { class: "empty" }, h("strong", {}, "Nothing here"), h("a", { href: "#/" }, "Back to packages"));
}

// ---------------------------------------------------------------- chrome

function sidebar() {
  const here = location.hash || "#/";
  const link = (href, ic, label) =>
    h("a", { href, class: (href === "#/" ? here === "#/" || here.startsWith("#/packages") : here === href) ? "active" : "" }, icon(ic), label);
  const orgName = (state.overview && state.overview.org.name) || state.me.org.name;
  return h("aside", { class: "sidebar" },
    h("div", { class: "brand" }, logo(28), h("div", {}, "Skein", h("span", { class: "org" }, orgName))),
    h("nav", { class: "nav", "aria-label": "Main" },
      link("#/", "box", "Packages"),
      link("#/connect", "plug", "Connect a client"),
      h("div", { class: "group" }, "Policy"),
      link("#/policy", "shield", "Admission policy"),
      link("#/findings", "flag", "What it caught"),
      h("div", { class: "group" }, "Organization"),
      link("#/people", "users", "People"),
      isAdmin() && link("#/activity", "clock", "Activity"),
      isAdmin() && link("#/settings", "gear", "Settings"),
      h("div", { class: "group" }, "You"),
      link("#/tokens", "key", "Your tokens"),
    ),
    h("div", { class: "me" },
      h("div", { class: "who" },
        h("div", {}, h("strong", {}, state.me.username)),
        h("div", { class: "muted small" }, state.me.role)),
      h("button", { class: "btn small", onclick: logout }, "Sign out")),
  );
}

async function logout() {
  await api("DELETE", "/session").catch(() => {});
  state.me = null; state.overview = null;
  go("#/login");
}

function loginScreen() {
  const user = h("input", { name: "username", autocomplete: "username", required: true, autofocus: true });
  const pass = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true });
  const err = h("div", { class: "notice bad", hidden: true });
  const submit = h("button", { class: "btn primary", type: "submit" }, "Sign in");
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true; err.hidden = true;
      try {
        state.me = await api("POST", "/session", { username: user.value, password: pass.value });
        state.overview = null;
        location.hash = "#/"; render();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
      finally { submit.disabled = false; }
    },
  },
    h("label", { class: "field" }, "Username", user),
    h("label", { class: "field" }, "Password", pass),
    err, submit);
  return h("div", { class: "login" }, h("div", { class: "card" },
    logo(36), h("h1", {}, "Sign in to Skein"),
    h("p", { class: "secondary" }, "Your organization's private package registry."),
    form,
    h("p", { class: "muted small" }, "Lost access? An operator can run ", h("code", {}, "skein admin reset-password <you>"), " on the server.")));
}

function setupScreen(msg) {
  return h("div", { class: "login" }, h("div", { class: "card" },
    logo(36), h("h1", {}, "Skein is not set up yet"),
    h("p", { class: "secondary" }, msg),
    codeblock("skein admin bootstrap --org <your-org>"),
    h("p", { class: "muted small" }, "It prints the first admin's password and an API token, once. Reload this page afterwards.")));
}

function pageHead(title, sub, ...actions) {
  return h("div", { class: "page-head" },
    h("div", { style: "min-width:0" }, h("h1", {}, title), sub && h("p", {}, sub)),
    actions.length ? h("div", { class: "row" }, ...actions) : null);
}

// -------------------------------------------------------------- packages

async function packagesPage() {
  const params = new URLSearchParams(sessionStorage.getItem("skein.filter") || "");
  const q = h("input", { type: "search", placeholder: "Search packages", value: params.get("q") || "", "aria-label": "Search packages", style: "flex:1 1 220px" });
  const eco = h("select", { "aria-label": "Ecosystem" },
    h("option", { value: "" }, "All ecosystems"),
    Object.entries(ECO_LABEL).map(([k, v]) => h("option", { value: k, selected: params.get("ecosystem") === k }, v)));
  const body = h("div", {});
  const ov = state.overview;

  async function load() {
    const p = new URLSearchParams();
    if (q.value.trim()) p.set("q", q.value.trim());
    if (eco.value) p.set("ecosystem", eco.value);
    p.set("limit", "200");
    sessionStorage.setItem("skein.filter", p.toString());
    const { packages } = await api("GET", `/packages?${p}`);
    if (!packages.length) {
      body.replaceChildren(q.value || eco.value
        ? h("div", { class: "empty" }, h("strong", {}, "No packages match"), "Try a shorter search.")
        : h("div", { class: "empty" }, h("strong", {}, "Nothing published yet"),
            "Point a client at this registry and publish — ", h("a", { href: "#/connect" }, "here is how"), "."));
      return;
    }
    body.replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Package"), h("th", {}, "Ecosystem"), h("th", { class: "hide-sm" }, "Origin"), h("th", { class: "num hide-sm" }, "Updated"))),
      h("tbody", {}, packages.map((p) => h("tr", { class: "link-row", onclick: () => go(`#/packages/${p.id}`) },
        h("td", { class: "wrap" }, h("a", { href: `#/packages/${p.id}`, onclick: (e) => e.stopPropagation() }, h("strong", {}, p.name))),
        h("td", {}, ecoBadge(p.ecosystem)),
        h("td", { class: "hide-sm" }, p.origin === "proxied" ? h("span", { class: "badge", title: "Cached from an upstream registry" }, "cached") : h("span", { class: "badge good" }, "published")),
        h("td", { class: "num hide-sm" }, when(p.updated_at))))))));
  }
  let t;
  q.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => load().catch((e) => toast(e.message, "bad")), 180); });
  eco.addEventListener("change", () => load().catch((e) => toast(e.message, "bad")));
  await load();

  const stats = ov && h("div", { class: "grid stats" },
    h("div", { class: "card stat" }, h("div", { class: "v" }, String(ov.ecosystems.reduce((a, e) => a + e.packages, 0))), h("div", { class: "k" }, "packages")),
    h("div", { class: "card stat" }, h("div", { class: "v" }, bytes(ov.stored_bytes)), h("div", { class: "k" }, "stored in the bucket")),
    h("div", { class: "card stat" }, h("div", { class: "v" }, String(ov.findings)), h("div", { class: "k" }, h("a", { href: "#/findings" }, "policy findings"))));
  return [
    pageHead("Packages", "Everything your organization has published or cached. Private to its members."),
    stats,
    h("div", { class: "card" }, h("div", { class: "row", style: "margin-bottom:12px" }, q, eco), body),
  ];
}

const INSTALL = {
  npm: (n, v) => `npm install ${n}@${v}`,
  maven: (n, v) => { const [g, a] = n.split(":"); return `<dependency>\n  <groupId>${g}</groupId>\n  <artifactId>${a}</artifactId>\n  <version>${v}</version>\n</dependency>`; },
  pypi: (n, v) => `pip install ${n}==${v}`,
  cargo: (n, v) => `cargo add ${n}@${v} --registry ${(state.overview && state.overview.org.name) || "skein"}`,
  oci: (n, v) => `docker pull ${new URL(base()).host}/${n}:${v}`,
};

async function packagePage(id) {
  const p = await api("GET", `/packages/${id}`);
  const latest = (p.tags.find((t) => t.tag === "latest") || {}).version || (p.versions[0] || {}).version;
  const versionRows = p.versions.map((v) => h("tr", {},
    h("td", { class: "wrap" }, h("strong", { class: "mono" }, v.version),
      v.yanked && h("span", { class: "badge warn", style: "margin-left:8px", title: v.yank_reason || "" }, "yanked")),
    h("td", {}, v.license ? h("span", { class: "mono" }, v.license) : h("span", { class: "badge warn", title: "The package declared no licence we could read" }, "unknown")),
    h("td", {}, v.published_by_username || h("span", { class: "muted" }, p.origin === "proxied" ? "upstream" : "—")),
    h("td", { class: "num" }, when(v.published_at)),
    h("td", { class: "num mono" }, bytes(v.size_bytes)),
    h("td", { class: "num" }, canWrite() && p.origin !== "proxied" && h("button", {
      class: "btn small",
      onclick: async () => {
        const reason = v.yanked ? null : prompt(`Yank ${p.name} ${v.version}? It stays installable by exact version, so lockfiles keep building. Reason (optional):`, "");
        if (!v.yanked && reason === null) return;
        await act(() => api("POST", `/packages/${p.id}/versions/${encodeURIComponent(v.version)}/yank`, { yanked: !v.yanked, reason: reason || null }), v.yanked ? "Restored" : "Yanked");
        render();
      },
    }, v.yanked ? "Un-yank" : "Yank"))));

  const files = p.versions.length ? p.versions[0].files : [];
  return [
    h("div", { class: "crumbs" }, h("a", { href: "#/" }, "Packages"), " / ", p.name),
    pageHead(p.name, null, ecoBadge(p.ecosystem),
      p.origin === "proxied" ? h("span", { class: "badge" }, "cached from upstream") : h("span", { class: "badge good" }, "published here")),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h2", {}, "Install"),
        h("p", { class: "lede" }, "With a client already ", h("a", { href: "#/connect" }, "pointed at this registry"), "."),
        latest && INSTALL[p.ecosystem] ? codeblock(INSTALL[p.ecosystem](p.name, latest)) : h("p", { class: "muted" }, "No versions.")),
      h("div", { class: "card" }, h("h2", {}, "Tags"),
        p.tags.length
          ? h("table", {}, h("tbody", {}, p.tags.map((t) => h("tr", {}, h("td", { class: "mono" }, t.tag), h("td", { class: "mono" }, t.version)))))
          : h("p", { class: "muted" }, "No tags."))),
    h("div", { class: "card" }, h("h2", {}, `Versions (${p.versions.length})`),
      h("p", { class: "lede" }, "A published version never changes. Yanking hides it from resolution without breaking a lockfile that names it."),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Version"), h("th", {}, "Licence"), h("th", {}, "Published by"), h("th", { class: "num" }, "When"), h("th", { class: "num" }, "Size"), h("th", {}))),
        h("tbody", {}, versionRows)))),
    files.length ? h("div", { class: "card" }, h("h2", {}, `Files in ${p.versions[0].version}`),
      h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, files.map((f) => h("tr", {},
        h("td", { class: "wrap mono" }, f.filename),
        h("td", { class: "mono muted", title: f.digest }, f.digest.slice(0, 19) + "…"),
        h("td", { class: "num mono" }, bytes(f.size_bytes)))))))) : null,
    isAdmin() && h("div", { class: "card" }, h("h2", {}, "Delete this package"),
      h("p", { class: "lede" }, "Removes every version. Anything that installs it will break, and this cannot be undone."),
      h("button", {
        class: "btn danger",
        onclick: async () => {
          if (prompt(`Type the package name to delete it: ${p.name}`) !== p.name) return;
          await act(() => api("DELETE", `/packages/${p.id}`), "Deleted");
          state.overview = null; go("#/");
        },
      }, "Delete package")),
  ];
}

// ------------------------------------------------------------- connect

function snippets(eco, token) {
  const b = base();
  const host = new URL(b).host;
  const org = (state.overview && state.overview.org.name) || "acme";
  const tok = token || "skein_…";
  switch (eco) {
    case "npm": return [
      ["~/.npmrc — your scope from here, everything else from npmjs", `@${org}:registry=${b}/npm/\n${b.replace(/^https?:/, "")}/npm/:_authToken=${tok}`],
      ["Or everything through Skein (when npm is in proxy mode)", `registry=${b}/npm/\n${b.replace(/^https?:/, "")}/npm/:_authToken=${tok}`],
      ["Then", "npm publish\nnpm install @" + org + "/<package>"],
    ];
    case "maven": return [
      ["~/.m2/settings.xml", `<settings>\n  <servers>\n    <server>\n      <id>skein</id>\n      <username>skein</username>\n      <password>${tok}</password>\n    </server>\n  </servers>\n  <profiles>\n    <profile>\n      <id>skein</id>\n      <repositories>\n        <repository>\n          <id>skein</id>\n          <url>${b}/maven/</url>\n          <releases><enabled>true</enabled></releases>\n          <snapshots><enabled>false</enabled></snapshots>\n        </repository>\n      </repositories>\n    </profile>\n  </profiles>\n  <activeProfiles><activeProfile>skein</activeProfile></activeProfiles>\n</settings>`],
      ["Deploy", `mvn deploy -DaltDeploymentRepository=skein::${b}/maven/`],
    ];
    case "pypi": return [
      ["~/.config/pip/pip.conf", `[global]\nindex-url = ${b.replace("://", `://skein:${tok}@`)}/pypi/simple/`],
      ["~/.pypirc, for twine", `[distutils]\nindex-servers = skein\n\n[skein]\nrepository = ${b}/pypi/\nusername = __token__\npassword = ${tok}`],
      ["Then", "twine upload -r skein dist/*"],
    ];
    case "cargo": return [
      ["~/.cargo/config.toml", `[registries.${org}]\nindex = "sparse+${b}/cargo/index/"\ncredential-provider = ["cargo:token"]`],
      ["~/.cargo/credentials.toml", `[registries.${org}]\ntoken = "${tok}"`],
      ["Then", `cargo publish --registry ${org}`],
    ];
    case "oci": return [
      ["Log in", `echo "${tok}" | docker login ${host} --username skein --password-stdin`],
      ["Push and pull", `docker tag app:latest ${host}/team/app:1.0\ndocker push ${host}/team/app:1.0\ndocker pull ${host}/team/app:1.0`],
    ];
    default: return [];
  }
}

async function connectPage() {
  const ecos = served();
  let token = null;
  let current = ecos.find((e) => e.mode !== "off") || ecos[0];
  const panel = h("div", {});
  const tabs = h("div", { class: "tabs", role: "tablist" });
  const tokenBox = h("div", {});

  function draw() {
    tabs.replaceChildren(...ecos.map((e) => h("button", {
      class: e === current ? "on" : "", role: "tab",
      onclick: () => { current = e; draw(); },
    }, e.label)));
    const off = current && current.mode === "off";
    panel.replaceChildren(...[
      off && h("div", { class: "notice warn" }, `${current.label} is switched off for this registry. `,
        isAdmin() ? h("a", { href: "#/policy" }, "Switch it on") : "Ask an admin to switch it on."),
      ...(current ? snippets(current.ecosystem, token) : []).map(([t, code]) =>
        h("div", {}, h("p", { class: "secondary", style: "margin:14px 0 6px" }, t), codeblock(code))),
    ].filter(Boolean));
  }
  const readBtn = h("button", { class: "btn", onclick: () => mint(["package:read"]) }, "Mint an install token");
  const writeBtn = canWrite() && h("button", { class: "btn primary", onclick: () => mint(["package:write"]) }, "Mint a publish token");
  async function mint(scopes) {
    const label = `${current ? current.ecosystem : "client"} from the UI`;
    const t = await act(() => api("POST", "/me/tokens", { label, scopes }));
    token = t.token;
    tokenBox.replaceChildren(h("div", { class: "notice" },
      h("p", { style: "margin:0 0 8px" }, h("strong", {}, "Your new token, shown once. "), "It is in the snippets below now; copy what you need before you leave this page."),
      h("div", { class: "row" }, h("div", { class: "secret", style: "flex:1" }, token), copyButton(token))));
    draw();
  }
  draw();
  return [
    pageHead("Connect a client", "The configuration each tool reads, filled in for this registry."),
    h("div", { class: "card" },
      h("h2", {}, "A token first"),
      h("p", { class: "lede" }, "Every install and publish is you, through a token. It carries your role's authority as it is now — if your role changes, the token follows."),
      h("div", { class: "row" }, readBtn, writeBtn, h("a", { href: "#/tokens", class: "btn link" }, "Manage your tokens")),
      tokenBox),
    ecos.length ? h("div", { class: "card" }, tabs, panel) : h("div", { class: "notice warn" }, "No ecosystems are served by this build."),
  ];
}

// --------------------------------------------------------------- tokens

function scopeBadges(scopes) {
  return scopes.map((s) => h("span", { class: `badge ${s === "org:admin" ? "warn" : s === "package:write" ? "good" : ""}`, style: "margin-right:4px" }, s));
}

function tokenTable(tokens, showOwner, onRevoke) {
  if (!tokens.length) return h("div", { class: "empty" }, h("strong", {}, "No tokens"), "Mint one to point a client at this registry.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Label"), showOwner && h("th", {}, "Owner"), h("th", {}, "Scopes"), h("th", { class: "num" }, "Created"), h("th", { class: "num" }, "Last used"), h("th", { class: "num" }, "Expires"), h("th", {}))),
    h("tbody", {}, tokens.map((t) => h("tr", {},
      h("td", { class: "wrap" }, t.label),
      showOwner && h("td", {}, t.username),
      h("td", { class: "wrap" }, scopeBadges(t.scopes)),
      h("td", { class: "num" }, when(t.created_at)),
      h("td", { class: "num" }, when(t.last_used_at)),
      h("td", { class: "num" }, t.expires_at ? new Date(t.expires_at).toISOString().slice(0, 10) : h("span", { class: "muted" }, "never")),
      h("td", { class: "num" }, h("button", {
        class: "btn small danger",
        onclick: async () => {
          if (!confirm(`Revoke "${t.label}"? Anything using it stops working at once.`)) return;
          await act(() => api("DELETE", `/tokens/${t.id}`), "Revoked");
          onRevoke();
        },
      }, "Revoke")))))));
}

async function tokensPage() {
  const list = h("div", {});
  const fresh = h("div", {});
  async function load() {
    const { tokens } = await api("GET", "/me/tokens");
    list.replaceChildren(tokenTable(tokens, false, load));
  }
  const label = h("input", { placeholder: "laptop, release job…", required: true, maxlength: 100 });
  const scope = h("select", {},
    h("option", { value: "package:read" }, "package:read — install"),
    canWrite() && h("option", { value: "package:write" }, "package:write — install and publish"),
    h("option", { value: "org:read" }, "org:read — install, and read settings"),
    isAdmin() && h("option", { value: "org:admin" }, "org:admin — everything"));
  const days = h("select", {},
    h("option", { value: "" }, "Never"), h("option", { value: "30" }, "30 days"), h("option", { value: "90" }, "90 days"), h("option", { value: "365" }, "1 year"));
  const form = h("form", {
    class: "inline",
    onsubmit: async (e) => {
      e.preventDefault();
      const t = await act(() => api("POST", "/me/tokens", { label: label.value, scopes: [scope.value], expires_in_days: days.value ? Number(days.value) : null }));
      fresh.replaceChildren(h("div", { class: "notice", style: "margin-top:14px" },
        h("p", { style: "margin:0 0 8px" }, h("strong", {}, "Shown once. "), "Only its hash is stored, so there is no second chance to read it."),
        h("div", { class: "row" }, h("div", { class: "secret", style: "flex:1" }, t.token), copyButton(t.token))));
      label.value = "";
      load();
    },
  },
    h("label", { class: "field" }, "Label", label),
    h("label", { class: "field" }, "Scope", scope),
    h("label", { class: "field", style: "flex:0 1 140px" }, "Expires", days),
    h("button", { class: "btn primary", type: "submit" }, "Mint token"));
  await load();
  return [
    pageHead("Your tokens", "Each one carries your role's authority as it is now, narrowed to its scope."),
    h("div", { class: "card" }, h("h2", {}, "Mint a token"), form, fresh),
    h("div", { class: "card" }, list),
    passwordCard(),
  ];
}

function passwordCard() {
  const cur = h("input", { type: "password", autocomplete: "current-password", required: true });
  const next = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 12 });
  return h("div", { class: "card" }, h("h2", {}, "Change your password"),
    h("p", { class: "lede" }, "Signs out every other browser you are signed in on."),
    h("form", {
      class: "inline",
      onsubmit: async (e) => {
        e.preventDefault();
        await act(() => api("PUT", "/me/password", { current: cur.value, new: next.value }), "Password changed");
        cur.value = ""; next.value = "";
      },
    },
      h("label", { class: "field" }, "Current", cur),
      h("label", { class: "field" }, "New", h("span", { class: "hint" }, "At least 12 characters"), next),
      h("button", { class: "btn", type: "submit" }, "Change")));
}

// --------------------------------------------------------------- people

function shownOnce(where, who, token) {
  where.replaceChildren(h("div", { class: "notice" },
    h("p", { style: "margin:0 0 8px" }, h("strong", {}, `A token for ${who}, shown once. `), "Only its hash is stored, so there is no second chance to read it."),
    h("div", { class: "row" }, h("div", { class: "secret", style: "flex:1" }, token), copyButton(token))));
  where.scrollIntoView({ block: "nearest" });
}

async function peoplePage() {
  const { users } = await api("GET", "/users");
  const fresh = h("div", {});
  const out = [pageHead("People", "Everybody who can reach this registry. There is no anonymous access."), fresh];
  if (isAdmin()) {
    const name = h("input", { required: true, placeholder: "ada", autocomplete: "off" });
    const role = h("select", {}, ["reader", "publisher", "admin"].map((r) => h("option", { value: r }, r)));
    const pw = h("input", { type: "password", placeholder: "leave empty for a service account", autocomplete: "new-password" });
    out.push(h("div", { class: "card" }, h("h2", {}, "Add somebody"),
      h("p", { class: "lede" }, "A reader installs; a publisher also publishes and yanks; an admin changes settings and people. With no password it is a service account for CI: it holds tokens and cannot sign in."),
      h("form", {
        class: "inline",
        onsubmit: async (e) => {
          e.preventDefault();
          await act(() => api("POST", "/users", { username: name.value, role: role.value, password: pw.value || null }), `Added ${name.value}`);
          render();
        },
      },
        h("label", { class: "field" }, "Username", name),
        h("label", { class: "field", style: "flex:0 1 150px" }, "Role", role),
        h("label", { class: "field" }, "Password", pw),
        h("button", { class: "btn primary", type: "submit" }, "Add"))));
  }
  out.push(h("div", { class: "card" }, h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Who"), h("th", {}, "Role"), h("th", {}, "Signs in"), h("th", { class: "num" }, "Since"), isAdmin() && h("th", {}))),
    h("tbody", {}, users.map((u) => h("tr", {},
      h("td", { class: "wrap" }, h("strong", {}, u.username), u.disabled && h("span", { class: "badge bad", style: "margin-left:8px" }, "disabled"), u.id === state.me.id && h("span", { class: "muted" }, " (you)")),
      h("td", {}, isAdmin() ? roleSelect(u) : u.role),
      h("td", {}, u.can_sign_in ? "yes" : h("span", { class: "muted" }, "service account")),
      h("td", { class: "num" }, when(u.created_at)),
      isAdmin() && h("td", { class: "num" }, h("div", { class: "actions" }, personActions(u, fresh))))))))));
  if (isAdmin()) {
    const { tokens } = await api("GET", "/tokens");
    const box = h("div", {});
    const reload = async () => box.replaceChildren(tokenTable((await api("GET", "/tokens")).tokens, true, reload));
    box.replaceChildren(tokenTable(tokens, true, reload));
    out.push(h("div", { class: "card" }, h("h2", {}, "Every live token"), h("p", { class: "lede" }, "Revoke anything you do not recognise."), box));
  }
  return out;
}

function roleSelect(u) {
  const s = h("select", {
    "aria-label": `Role of ${u.username}`,
    onchange: async () => {
      try { await act(() => api("PATCH", `/users/${u.id}`, { role: s.value }), `${u.username} is now a ${s.value}`); }
      catch { s.value = u.role; return; }
      u.role = s.value;
    },
  }, ["reader", "publisher", "admin"].map((r) => h("option", { value: r, selected: r === u.role }, r)));
  return s;
}

function personActions(u, fresh) {
  return [
    !u.can_sign_in && !u.disabled && h("button", {
      class: "btn small",
      onclick: async () => {
        const scope = u.role === "reader" ? "package:read" : "package:write";
        const label = prompt(`Label for a ${scope} token for ${u.username}:`, "ci");
        if (!label) return;
        const t = await act(() => api("POST", `/users/${u.id}/tokens`, { label, scopes: [scope] }));
        shownOnce(fresh, u.username, t.token);
      },
    }, "Mint token"),
    h("button", {
      class: "btn small",
      onclick: async () => {
        const pw = prompt(`New password for ${u.username} (at least 12 characters). Signs them out everywhere:`);
        if (!pw) return;
        await act(() => api("PATCH", `/users/${u.id}`, { password: pw }), "Password set");
        render();
      },
    }, "Set password"),
    h("button", {
      class: "btn small",
      onclick: async () => { await act(() => api("PATCH", `/users/${u.id}`, { disabled: !u.disabled }), u.disabled ? "Enabled" : "Disabled"); render(); },
    }, u.disabled ? "Enable" : "Disable"),
    h("button", {
      class: "btn small danger",
      onclick: async () => {
        if (!confirm(`Remove ${u.username}? Their tokens stop working; what they published stays.`)) return;
        await act(() => api("DELETE", `/users/${u.id}`), "Removed");
        render();
      },
    }, "Remove"),
  ];
}

// --------------------------------------------------------------- policy

async function policyPage() {
  const [{ ecosystems }, policy] = await Promise.all([api("GET", "/ecosystems"), api("GET", "/policy?ecosystem=npm")]);
  const admin = isAdmin();
  const dis = !admin;
  const servedSet = new Set(served().map((e) => e.ecosystem));

  const ecoRows = ecosystems.filter((e) => servedSet.has(e.ecosystem)).map((e) => {
    const mode = h("select", { disabled: dis, "aria-label": `${e.label} mode` },
      h("option", { value: "off", selected: e.mode === "off" }, "Off"),
      h("option", { value: "private", selected: e.mode === "private" }, "Private"),
      e.ecosystem === "npm" && h("option", { value: "proxy", selected: e.mode === "proxy" }, "Private + proxy"));
    const unknown = h("select", { disabled: dis, "aria-label": `${e.label} unknown licence` },
      h("option", { value: "block", selected: e.license_unknown === "block" }, "Refuse"),
      h("option", { value: "allow", selected: e.license_unknown === "allow" }, "Admit"));
    const save = async () => {
      await act(() => api("PUT", "/ecosystems", { ecosystem: e.ecosystem, mode: mode.value, license_unknown: unknown.value }), `${e.label} saved`);
      state.overview = null;
    };
    mode.addEventListener("change", save); unknown.addEventListener("change", save);
    return h("tr", {}, h("td", {}, h("strong", {}, e.label)), h("td", {}, mode), h("td", {}, unknown));
  });

  const pmode = h("select", { disabled: dis },
    h("option", { value: "audit", selected: policy.mode === "audit" }, "Audit — serve everything, record what would be refused"),
    h("option", { value: "block", selected: policy.mode === "block" }, "Block — refuse what the rules refuse"));
  const cooldown = h("input", { type: "number", min: 0, max: 3650, value: policy.cooldown_days, disabled: dis, style: "width:7rem" });
  const lmode = h("select", { disabled: dis },
    h("option", { value: "deny_list", selected: policy.license_mode === "deny_list" }, "Deny list — admit everything except what is denied"),
    h("option", { value: "allow_list", selected: policy.license_mode === "allow_list" }, "Allow list — admit only what is allowed"));
  const savePolicy = async () => {
    await act(() => api("PUT", "/policy", { mode: pmode.value, cooldown_days: Number(cooldown.value), license_mode: lmode.value }), "Policy saved");
    render();
  };

  const rules = policy.license_rules.map((r) => h("tr", {},
    h("td", { class: "mono" }, r.spdx_id),
    h("td", {}, h("span", { class: `badge ${r.disposition === "allow" ? "good" : "bad"}` }, r.disposition)),
    h("td", { class: "num" }, admin && h("button", { class: "btn small", onclick: async () => { await act(() => api("PUT", "/policy/licenses", { spdx_id: r.spdx_id, disposition: null }), "Rule removed"); render(); } }, "Remove"))));
  const spdx = h("input", { placeholder: "AGPL-3.0-only", required: true });
  const disp = h("select", {}, h("option", { value: "deny" }, "deny"), h("option", { value: "allow" }, "allow"));

  const reserved = policy.reserved.map((p) => h("tr", {},
    h("td", { class: "mono" }, p),
    h("td", { class: "num" }, admin && h("button", { class: "btn small", onclick: async () => { await act(() => api("DELETE", `/policy/namespaces?ecosystem=npm&pattern=${encodeURIComponent(p)}`), "Released"); render(); } }, "Release"))));
  const ns = h("input", { placeholder: `@${(state.overview && state.overview.org.name) || "acme"}`, required: true });

  return [
    pageHead("Admission policy", admin ? "What may enter your builds from a public registry." : "What may enter your builds from a public registry. Only an admin can change it."),
    h("div", { class: "card" }, h("h2", {}, "Ecosystems"),
      h("p", { class: "lede" }, "An ecosystem that is off answers 404 for everything. Proxy mode fetches public packages through Skein, caches them in your bucket, and applies the policy below on the way in."),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Ecosystem"), h("th", {}, "Mode"), h("th", {}, "A licence we cannot read"))),
        h("tbody", {}, ecoRows)))),
    h("div", { class: "card" }, h("h2", {}, "Rules"),
      h("p", { class: "lede" }, "Start in audit mode and read what it would have refused before switching to block. Switching to block re-checks what is already cached, too."),
      h("div", { class: "stack" },
        h("label", { class: "field" }, "On a violation", pmode),
        h("label", { class: "field" }, "Hold new upstream releases for this many days", h("span", { class: "hint" }, "0 turns it off. Every compromised-maintainer release worth naming was withdrawn within days."), cooldown),
        h("label", { class: "field" }, "Licences", lmode),
        admin && h("div", {}, h("button", { class: "btn primary", onclick: savePolicy }, "Save rules")))),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h2", {}, "Licence rules"),
        h("p", { class: "lede" }, "SPDX identifiers. Expressions are evaluated: ", h("code", {}, "MIT OR GPL-3.0"), " is admitted if either side is."),
        rules.length ? h("table", {}, h("tbody", {}, rules)) : h("p", { class: "muted" }, policy.license_mode === "allow_list" ? "No rules — an empty allow list admits nothing." : "No rules — everything is admitted."),
        admin && h("form", { class: "inline", style: "margin-top:12px", onsubmit: async (e) => { e.preventDefault(); await act(() => api("PUT", "/policy/licenses", { spdx_id: spdx.value, disposition: disp.value }), "Rule saved"); render(); } },
          h("label", { class: "field" }, "SPDX id", spdx), h("label", { class: "field", style: "flex:0 1 110px" }, "Rule", disp), h("button", { class: "btn", type: "submit" }, "Add"))),
      h("div", { class: "card" }, h("h2", {}, "Names that are yours"),
        h("p", { class: "lede" }, "Never fetched from upstream, published or not — reserve your npm scope so nobody else's package can answer for one you have not published yet."),
        reserved.length ? h("table", {}, h("tbody", {}, reserved)) : h("p", { class: "muted" }, "Nothing reserved."),
        admin && h("form", { class: "inline", style: "margin-top:12px", onsubmit: async (e) => { e.preventDefault(); await act(() => api("POST", "/policy/namespaces", { ecosystem: "npm", pattern: ns.value }), "Reserved"); render(); } },
          h("label", { class: "field" }, "npm prefix", ns), h("button", { class: "btn", type: "submit" }, "Reserve")))),
  ];
}

async function findingsPage() {
  const { findings } = await api("GET", "/findings?limit=500");
  const admin = isAdmin();
  const rows = findings.map((f) => h("tr", {},
    h("td", { class: "wrap" }, h("strong", {}, f.name), " ", h("span", { class: "mono muted" }, f.version)),
    h("td", {}, f.disposition === "blocked" ? h("span", { class: "badge bad" }, "refused") : h("span", { class: "badge warn" }, "would refuse")),
    h("td", {}, f.rule),
    h("td", { class: "wrap secondary" }, f.reason),
    h("td", { class: "num mono" }, String(f.hits)),
    h("td", { class: "num" }, when(f.last_at)),
    h("td", { class: "num" }, admin && h("button", {
      class: "btn small",
      title: "Forgetting a finding does not allow the package: the rule still applies and the next install records it again.",
      onclick: async () => { await act(() => api("DELETE", `/findings?ecosystem=${f.ecosystem}&name=${encodeURIComponent(f.name)}&version=${encodeURIComponent(f.version)}`), "Dismissed"); render(); },
    }, "Dismiss"))));
  return [
    pageHead("What the policy caught", "One row per package version, however many times it came up. To allow something, change the rule that refused it."),
    h("div", { class: "card" }, findings.length
      ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Package"), h("th", {}, "Outcome"), h("th", {}, "Rule"), h("th", {}, "Why"), h("th", { class: "num" }, "Hits"), h("th", { class: "num" }, "Last"), h("th", {}))),
        h("tbody", {}, rows)))
      : h("div", { class: "empty" }, h("strong", {}, "Nothing caught"), "Findings appear here when npm is in proxy mode and something meets a rule.")),
  ];
}

// ------------------------------------------------------------- activity

async function activityPage() {
  const { entries } = await api("GET", "/audit?limit=200");
  return [
    pageHead("Activity", "Every change to what is published, who may reach it, and what the policy admits."),
    h("div", { class: "card" }, entries.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "When"), h("th", {}, "Who"), h("th", {}, "What"), h("th", {}, "Detail"))),
      h("tbody", {}, entries.map((e) => h("tr", {},
        h("td", { class: "nowrap" }, when(e.at)),
        h("td", {}, e.username || h("span", { class: "muted" }, e.principal)),
        h("td", { class: "mono" }, e.action),
        // A field recorded as null is one that was not given; it says
        // nothing, and "null" on the page reads as a value.
        h("td", { class: "wrap mono muted small" }, e.context ? JSON.stringify(e.context, (k, v) => (v === null ? undefined : v)) : "")))))) : h("p", { class: "muted" }, "Nothing yet.")),
  ];
}

// -------------------------------------------------------------- licence

function licenseBanner() {
  const l = state.license;
  if (!isAdmin() || !l || !l.warnings.length || location.hash === "#/settings") return null;
  const more = l.warnings.length > 1 ? ` (and ${l.warnings.length - 1} more)` : "";
  return h("div", { class: "notice warn banner", role: "status" },
    h("strong", {}, "Licence. "), l.warnings[0] + more, " ",
    h("a", { href: "#/settings" }, "Details"));
}

const LICENSE_STATE = {
  unlicensed: ["", "no key"],
  invalid: ["bad", "not valid"],
  active: ["good", "active"],
  expiring: ["warn", "expiring"],
  lapsed: ["warn", "lapsed"],
};

function licenseCard(l) {
  const [cls, label] = LICENSE_STATE[l.state] || ["", l.state];
  const row = (k, ...v) => h("tr", {}, h("td", { class: "muted nowrap" }, k), h("td", { class: "wrap" }, ...v));
  const key = h("textarea", { rows: 3, required: true, placeholder: "weft_lic_v1.…", spellcheck: "false", autocomplete: "off", class: "mono" });
  const refresh = (r) => { state.license = r; render(); };
  const terms = l.license_id ? [
    row("Licence", h("span", { class: "mono" }, l.license_id), ` — ${l.tier} tier${l.trial ? " (trial)" : ""}, issued to `, h("strong", {}, l.entity)),
    row("Expires", l.expires_at.slice(0, 10), !l.release_access && h("span", { class: "badge warn", style: "margin-left:8px" }, "no new releases")),
    row("Reporting", l.mode === "offline"
      ? "Offline: Skein makes no calls to Weft. The monthly peaks below are what the annual true-up reports."
      : "Online: one check a day sends the licence id, this version and the most seats since the last check — nothing else."),
    l.mode === "online" && row("Last check", l.last_check_at ? `${when(Date.parse(l.last_check_at))} — ${l.last_check_status}` : "not yet",
      l.last_check_error && h("div", { class: "muted small" }, l.last_check_error)),
  ] : [];
  return h("div", { class: "card" },
    h("div", { class: "row", style: "justify-content:space-between" },
      h("h2", { style: "margin:0" }, "Licence"), h("span", { class: `badge ${cls}` }, label)),
    h("p", { class: "lede" }, "A licence never stops Skein. Whatever it says, everybody keeps installing, publishing and signing in; what it affects is signed updates from Weft."),
    l.notice && h("div", { class: "notice" }, h("strong", {}, "From Weft. "), l.notice),
    l.warnings.length ? h("div", { class: "notice warn" }, h("ul", { class: "plain" }, l.warnings.map((w) => h("li", {}, w)))) : null,
    h("table", {}, h("tbody", {},
      terms,
      row("Seats", `${l.seats} ${l.seats === 1 ? "person" : "people"} can sign in`,
        l.license_id ? (l.max_seats === null ? "; the licence has no seat cap" : `; the licence covers ${l.max_seats}`) : "",
        h("div", { class: "muted small" }, "Service accounts cannot sign in and are not seats. Most this month: ", String(l.peak_seats_this_month), ".")),
      l.monthly_peaks.length > 1 && row("By month", h("span", { class: "mono small" }, l.monthly_peaks.map((m) => `${m.month}: ${m.peak}`).join(" · "))))),
    h("form", {
      class: "stack",
      style: "margin-top:14px",
      onsubmit: async (e) => {
        e.preventDefault();
        refresh(await act(() => api("PUT", "/license", { key: key.value }), "Licence key installed"));
      },
    },
      h("label", { class: "field" }, l.license_id ? "Replace the key" : "Install a key",
        h("span", { class: "hint" }, l.key_source === "environment" ? "The key in force came from SKEIN_LICENSE_KEY. One installed here stands until that variable changes." : "Paste the key Weft sent you."),
        key),
      h("div", { class: "row" },
        h("button", { class: "btn primary", type: "submit" }, "Install"),
        l.mode === "online" && h("button", { class: "btn", type: "button", onclick: async () => refresh(await act(() => api("POST", "/license/check"), "Checked")) }, "Check now"))));
}

async function settingsPage() {
  const ov = await api("GET", "/overview");
  const lic = await api("GET", "/license");
  state.license = lic;
  const name = h("input", { value: ov.org.name, required: true, pattern: "[a-z0-9-]+" });
  return [
    pageHead("Settings"),
    h("div", { class: "card" }, h("h2", {}, "Organization name"),
      h("p", { class: "lede" }, "Shown in the interface and used in the configuration snippets. Renaming it moves nothing: stored bytes are keyed by an id that never changes."),
      h("form", { class: "inline", onsubmit: async (e) => { e.preventDefault(); await act(() => api("PUT", "/org", { name: name.value }), "Renamed"); state.overview = null; render(); } },
        h("label", { class: "field" }, "Name", h("span", { class: "hint" }, "Lowercase letters, digits and dashes"), name),
        h("button", { class: "btn primary", type: "submit" }, "Save"))),
    h("div", { class: "card" }, h("h2", {}, "This install"),
      h("table", {}, h("tbody", {},
        h("tr", {}, h("td", { class: "muted" }, "Public URL"), h("td", { class: "mono" }, ov.public_url)),
        h("tr", {}, h("td", { class: "muted" }, "Version"), h("td", { class: "mono" }, ov.version)),
        h("tr", {}, h("td", { class: "muted" }, "Stored"), h("td", { class: "mono" }, bytes(ov.stored_bytes)))))),
    licenseCard(lic),
  ];
}

render();
