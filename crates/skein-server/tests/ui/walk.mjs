// A person's-eye walk through Skein's UI, in a real Chromium.
//
// Driven by `tests/ui_e2e.rs`, which starts a server, seeds it — a
// package whose metadata is markup, a yanked version, a person with a
// hostile display name — and hands over:
//
//   BASE          the server
//   PW            the admin's password
//   READER_PW     the password of `rita`, a reader
//   PAT_PW        the password of `pat`, a publisher who published
//                 @acme/pat-lib and whom the walk removes
//   TOM_PW        the password of `tom`, whom the walk locks out
//   ADMIN_TOKEN   the admin's API token, to publish mid-walk as a
//                 client would
//   LICENSE_KEY   a valid licence key that covers fewer seats than the
//                 install has
//   OUT           optional: a directory for screenshots
//
// It prints every problem, then `N problem(s)` or `0 problems`, and exits
// non-zero on any. A problem is: a console error or uncaught error that
// was not provoked on purpose, a 5xx, a page that never finished
// loading, a page that scrolls sideways, an error notice, markup from
// data executing, `null`/`undefined`/`NaN` rendered as text, a table
// wider than its card on a desktop, or a step of a flow not doing what
// it says.
//
// The flows are driven the way a person drives them — clicking, typing,
// answering the browser's prompts — because the first walk only
// *operated* the licence form and visited everything else, and a manual
// pass then found a dozen broken flows on pages this walk had called
// clean: a yanked version recommended, a removed person's packages
// credited to nobody, stale counts, a token that replaced the one shown
// once. Each stage below is one of those, held.

import { chromium } from "playwright";

const { BASE, PW, READER_PW, PAT_PW, TOM_PW, ADMIN_TOKEN, LICENSE_KEY, OUT } = process.env;
const problems = [];
const expect = (cond, msg) => { if (!cond) problems.push(msg); };
// A stage that throws is a problem, and the walk goes on: a throw that
// ended the walk would leave every later stage unrun and the run
// looking shorter, not red.
let threw = 0;
async function stage(name, fn) {
  try { await fn(); }
  catch (e) { threw++; problems.push(`${name}: threw: ${e.message.split("\n")[0]}`); }
}
const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
);

// A page that records its own problems. `expected(n, status)` declares
// that the next `n` console errors about a response with that status are
// refusals the walk provokes on purpose.
async function open(tag, { width, height, scheme }) {
  const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme });
  const page = await ctx.newPage();
  let allowed = { n: 0, statuses: [] };
  page.expected = (n, status) => { allowed = { n, statuses: [status].flat() }; };
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    if (allowed.n > 0 && allowed.statuses.some((st) => m.text().includes(`status of ${st}`))) { allowed.n--; return; }
    problems.push(`${tag} console: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.push(`${tag} uncaught: ${e.message}`));
  page.on("response", (r) => { if (r.status() >= 500) problems.push(`${tag} ${r.status()} ${r.url()}`); });
  return page;
}

async function signIn(page, username, password) {
  await page.goto(BASE + "/");
  await page.fill("input[name=username]", username);
  await page.fill("input[name=password]", password);
  await page.click("button[type=submit]");
  await page.waitForSelector(".sidebar");
}

// The next browser dialog — confirm or prompt — answered with `answer`
// (`false` dismisses it); resolves to the dialog's message.
function answerNext(page, answer) {
  return new Promise((resolve) => page.once("dialog", async (d) => {
    const msg = d.message();
    if (answer === false) await d.dismiss(); else await d.accept(typeof answer === "string" ? answer : undefined);
    resolve(msg);
  }));
}

async function go(page, tag, route) {
  await page.goto(BASE + "/" + route);
  await settled(page, tag, route);
}

// The text of the next toast this walk has not read yet: toasts linger
// for seconds, and reading an earlier one would credit one action with
// another's answer.
async function toastText(page, kind) {
  const t = await page.waitForSelector(`#toast div${kind ? "." + kind : ""}:not([data-read])`, { timeout: 5000 }).catch(() => null);
  const text = t ? (await t.textContent()) || "" : "";
  await page.evaluate(() => document.querySelectorAll("#toast div").forEach((d) => d.setAttribute("data-read", "")));
  return text;
}

async function settled(page, tag, route) {
  await page.waitForFunction(
    () => !document.querySelector(".content p.muted")?.textContent?.startsWith("Loading"),
    null, { timeout: 8000 },
  ).catch(() => problems.push(`${tag} ${route}: never finished loading`));
  await page.waitForTimeout(150);
  const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (over > 1) problems.push(`${tag} ${route}: the page scrolls sideways by ${over}px`);
  const layout = await page.evaluate(() => {
    const out = [];
    const wide = window.innerWidth >= 1000;
    for (const w of document.querySelectorAll(".content .table-wrap")) {
      const by = w.scrollWidth - w.clientWidth;
      // On a desktop a table that scrolls inside its card is a table
      // that does not fit — the Activity table hid its Detail column
      // off the card's edge. On a phone it may scroll, but visibly.
      if (by > 1 && wide) out.push(`a table is ${by}px wider than its card`);
      if (by > 1 && !w.classList.contains("scrolls")) out.push("a table scrolls sideways with no sign that it does");
    }
    for (const el of document.querySelectorAll(".content .nowrap")) {
      if (getComputedStyle(el).whiteSpace !== "nowrap") { out.push(`.nowrap wraps: "${el.textContent}"`); break; }
    }
    for (const t of document.querySelectorAll(".content table")) {
      const sizes = new Set([...t.querySelectorAll("th")].map((th) => getComputedStyle(th).fontSize));
      if (sizes.size > 1) { out.push(`one table's headers come in ${[...sizes].join(" and ")}`); break; }
    }
    return out;
  });
  for (const l of layout) problems.push(`${tag} ${route}: ${l}`);
  // Text node by text node: `textContent` runs neighbours together, and a
  // stray "null" before a heading reads as "nullSettings" — no word
  // boundary, nothing found. That blind spot is how one got through.
  const leak = await page.evaluate(() => {
    const walk = document.createTreeWalker(document.querySelector(".content"), NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) {
      const m = n.data.match(/\b(null|undefined|NaN)\b/);
      if (m) return m[1];
    }
    return null;
  });
  if (leak) problems.push(`${tag} ${route}: "${leak}" rendered as text`);
  const bad = await page.$(".content .notice.bad");
  if (bad) problems.push(`${tag} ${route}: error shown: ${await bad.textContent()}`);
  if ((await page.title()).includes("PWNED")) problems.push(`${tag} ${route}: markup from data ran`);
}

// ------------------------------------------------------ the licence flow

{
  const tag = "licence";
  const page = await open(tag, { width: 1280, height: 900, scheme: "dark" });
  await signIn(page, "admin", PW);
  // Unlicensed: a banner on an ordinary page, leading to Settings.
  const banner = await page.waitForSelector(".notice.banner", { timeout: 5000 }).catch(() => null);
  expect(banner && (await banner.textContent()).includes("No licence key is configured"), `${tag}: no unlicensed banner`);
  await page.click(".notice.banner a");
  await page.waitForSelector("textarea.mono");
  await settled(page, tag, "#/settings");
  expect(!(await page.$(".notice.banner")), `${tag}: the banner repeats on Settings`);

  // A key that is not one: refused, said, and nothing else happens.
  page.expected(1, 400);
  await page.fill("textarea.mono", "weft_lic_v1.not.valid");
  await page.click("form.stack button[type=submit]");
  const refusal = await page.waitForSelector("#toast div.bad", { timeout: 5000 }).catch(() => null);
  const said = refusal ? await refusal.textContent() : "";
  expect(said.includes("not installed") && said.includes("malformed"), `${tag}: the refusal said ${JSON.stringify(said)}`);
  await page.waitForTimeout(300);

  // A real one, through the form.
  await page.fill("textarea.mono", LICENSE_KEY);
  await page.click("form.stack button[type=submit]");
  await page.waitForFunction(() => document.querySelector(".card:last-child .badge")?.textContent === "active", null, { timeout: 5000 })
    .catch(() => problems.push(`${tag}: the badge never read active`));
  await settled(page, tag, "#/settings");
  const card = (await page.textContent(".card:last-child")) || "";
  for (const needle of ["lic_walk", "Walkthrough Ltd", "the licence covers", "Nobody is refused", "2099-01-01", "Online: one check a day"]) {
    expect(card.includes(needle), `${tag}: the card does not say ${JSON.stringify(needle)}`);
  }
  expect(!card.includes(LICENSE_KEY.slice(20, 60)), `${tag}: the key is shown back`);
  if (OUT) await page.screenshot({ path: `${OUT}/licence.png`, fullPage: true });

  // Check now, against an endpoint that is not there: recorded and shown.
  await page.click("text=Check now");
  await page.waitForFunction(() => document.querySelector(".card:last-child")?.textContent.includes("could not be reached"), null, { timeout: 45000 })
    .catch(() => problems.push(`${tag}: a failed check was never shown`));
  await settled(page, tag, "#/settings");

  await page.goto(BASE + "/#/");
  await settled(page, tag, "#/");
  const over = await page.$(".notice.banner");
  expect(over && (await over.textContent()).includes("people can sign in"), `${tag}: no over-cap banner`);
  await page.context().close();
}

// A reader never sees the licence.
{
  const tag = "reader";
  const page = await open(tag, { width: 390, height: 844, scheme: "light" });
  await signIn(page, "rita", READER_PW);
  await settled(page, tag, "#/");
  expect(!(await page.$(".notice.banner")), `${tag}: a reader sees the licence banner`);
  await page.context().close();
}

// ------------------------------------------------------ the flows

async function packageId(page, name) {
  const r = await page.request.get(`${BASE}/api/v1/packages?q=${encodeURIComponent(name)}`, { headers: { "x-skein-csrf": "1" } });
  const p = (await r.json()).packages.find((x) => x.name === name);
  if (!p) throw new Error(`no package ${name}`);
  return p.id;
}

function publishDoc(name, version) {
  const bare = name.split("/").pop();
  const data = Buffer.from(`${name}@${version}`).toString("base64");
  return {
    _id: name, name, "dist-tags": { latest: version },
    versions: { [version]: { name, version, license: "MIT" } },
    _attachments: { [`${bare}-${version}.tgz`]: { content_type: "application/octet-stream", data, length: Buffer.from(data, "base64").length } },
  };
}

{
  const tag = "flows";
  const page = await open(tag, { width: 1280, height: 900, scheme: "light" });
  const gets = [];
  page.on("request", (r) => { if (r.method() === "GET" && r.url().includes("/api/v1/")) gets.push(new URL(r.url()).pathname); });
  await signIn(page, "admin", PW);
  await settled(page, tag, "#/");

  await stage("sign-in fetches once", async () => {
    const twice = [...new Set(gets)].filter((p) => gets.filter((q) => q === p).length > 1);
    expect(!twice.length, `${tag}: signing in fetched ${twice.join(", ")} more than once — the page rendered twice`);
  });

  await stage("install card", async () => {
    await go(page, tag, `#/packages/${await packageId(page, "@acme/gadget")}`);
    const install = (await page.textContent(".card:has(h2:text-is('Install')) pre")) || "";
    expect(install.includes("1.0.0") && !install.includes("1.1.0"),
      `${tag}: the install card recommends ${JSON.stringify(install)}, and 1.1.0 is yanked`);
    expect((await page.textContent(".content")).includes("broke the build"),
      `${tag}: a yank's reason is only in a tooltip, which nobody on a phone can hover`);
  });

  await stage("delete, mistyped", async () => {
    const asked = answerNext(page, "@acme/gadgte");
    await page.click("button:text-is('Delete package')");
    await asked;
    const said = await toastText(page);
    expect(/did not match/i.test(said), `${tag}: a mistyped name at "Delete package" said ${JSON.stringify(said)}`);
  });

  await stage("missing package", async () => {
    page.expected(1, 404);
    await page.goto(`${BASE}/#/packages/${"0".repeat(26)}`);
    // Wait on what the check reads: a hash-only navigation leaves the
    // previous page in place until the new one renders.
    await page.waitForSelector(".content .empty, .content .notice.bad", { timeout: 8000 }).catch(() => {});
    const text = (await page.textContent(".content")) || "";
    expect(/no such package/i.test(text), `${tag}: a package that is not there reads ${JSON.stringify(text.slice(0, 80))}`);
    expect(!(await page.$(".content .notice.bad")), `${tag}: a package that is not there is shown as an error`);
  });

  await stage("counts", async () => {
    await go(page, tag, "#/");
    const before = Number(await page.textContent(".stat .v"));
    const r = await page.request.put(`${BASE}/npm/@acme%2fwalk-new`, {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
      data: publishDoc("@acme/walk-new", "1.0.0"),
    });
    expect(r.status() === 201, `${tag}: publishing @acme/walk-new answered ${r.status()}`);
    await page.click("nav a:has-text('Connect a client')");
    await page.click("nav a:has-text('Packages')");
    await settled(page, tag, "#/");
    const after = Number(await page.textContent(".stat .v"));
    expect(after === before + 1, `${tag}: after a publish the package count still reads ${after} (it was ${before})`);
  });

  await stage("service account token", async () => {
    await go(page, tag, "#/people");
    const rows = async () => (await page.$$(".card:has(h2:text-is('Every live token')) tbody tr")).length;
    const n = await rows();
    const asked = answerNext(page, "walk");
    await page.click("tr:has(strong:text-is('ci')) button:text-is('Mint token')");
    await asked;
    await page.waitForSelector(".notice .secret");
    await page.waitForTimeout(300);
    expect((await rows()) === n + 1, `${tag}: minting ci a token left "Every live token" at ${await rows()} rows, from ${n}`);
  });

  await stage("disabled tokens", async () => {
    await go(page, tag, "#/people");
    await page.click("tr:has(strong:text-is('ci')) button:text-is('Disable')");
    await toastText(page, "good");
    await page.waitForSelector("tr:has(strong:text-is('ci')) button:text-is('Enable')");
    const row = (await page.textContent(".card:has(h2:text-is('Every live token')) tbody tr:has(td:text-is('ci'))")) || "";
    expect(/disabled/i.test(row), `${tag}: a disabled person's token is listed as if it worked: ${JSON.stringify(row)}`);
    await page.click("tr:has(strong:text-is('ci')) button:text-is('Enable')");
    await toastText(page, "good");
  });

  await stage("password change", async () => {
    try { await passwordChange(); }
    finally {
      // Whatever happened above, the admin's password is PW again for
      // the stages after this one; a refusal here means it already is.
      await page.request.put(`${BASE}/api/v1/me/password`, { headers: { "x-skein-csrf": "1" }, data: { current: "a-new-walk-password", new: PW } });
    }
  });
  async function passwordChange() {
    await go(page, tag, "#/tokens");
    const card = ".card:has(h2:text-is('Change your password'))";
    page.expected(1, 403);
    await page.fill(`${card} input[autocomplete=current-password]`, "not-the-password");
    await page.fill(`${card} input[autocomplete=new-password]`, "a-new-walk-password");
    await page.click(`${card} button[type=submit]`);
    await toastText(page, "bad");
    await page.fill(`${card} input[autocomplete=current-password]`, PW);
    await page.fill(`${card} input[autocomplete=new-password]`, "a-new-walk-password");
    await page.click(`${card} button[type=submit]`);
    await toastText(page, "good");
    expect(!(await page.$("#toast div.bad")), `${tag}: "the current password is wrong" is still showing beside "Password changed"`);
    await page.fill(`${card} input[autocomplete=current-password]`, "a-new-walk-password");
    await page.fill(`${card} input[autocomplete=new-password]`, PW);
    await page.click(`${card} button[type=submit]`);
    await toastText(page, "good");
  }

  await stage("cooldown", async () => {
    await go(page, tag, "#/policy");
    const saved = await page.inputValue("input[type=number]");
    await page.fill("input[type=number]", "99999");
    page.expected(1, 400);
    await page.click("button:text-is('Save rules')");
    await toastText(page, "bad");
    await page.waitForTimeout(300);
    const now = await page.inputValue("input[type=number]");
    expect(now === saved, `${tag}: a refused cooldown still reads ${now}; ${saved} is what is in force`);
  });

  await stage("unknown licence", async () => {
    await go(page, tag, "#/policy");
    const offered = await page.$$eval("select[aria-label$='unknown licence']", (s) => s.map((e) => e.getAttribute("aria-label")));
    expect(offered.length === 1 && offered[0].startsWith("npm"),
      `${tag}: "A licence we cannot read" is offered for ${offered.join(", ")} — only npm's proxy reads it`);
  });

  await stage("licence rules", async () => {
    await go(page, tag, "#/policy");
    const card = ".card:has(h2:text-is('Licence rules'))";
    const empty = (await page.textContent(card)) || "";
    expect(/cooldown/i.test(empty), `${tag}: with no rules the page says ${JSON.stringify(empty.slice(0, 160))} — unknown licences and the cooldown still apply`);
    await page.fill(`${card} input`, "GPL-3.0-only");
    await page.click(`${card} button[type=submit]`);
    await toastText(page, "good");
    const shown = await page.waitForSelector(`${card} td:text-is('GPL-3.0-only')`, { timeout: 3000 }).catch(() => null);
    expect(shown, `${tag}: a rule added as GPL-3.0-only is not shown as typed`);
    page.expected(1, 400);
    await page.fill(`${card} input`, "Not A Licence!!");
    await page.click(`${card} button[type=submit]`);
    const said = await toastText(page, "bad");
    expect(said.includes("Not A Licence!!"), `${tag}: "Not A Licence!!" as a licence rule said ${JSON.stringify(said)}`);
    await page.click(`${card} tr:has(td:text-is('GPL-3.0-only')) button:text-is('Remove')`);
    await toastText(page, "good");
    await go(page, tag, "#/activity");
    const rows = await page.$$eval(".content tbody tr", (tr) => tr.slice(0, 2).map((r) => [r.children[2].textContent, r.children[3].textContent]));
    expect(rows.length === 2 && rows[0][0] !== rows[1][0],
      `${tag}: adding and removing a licence rule read the same in Activity: ${JSON.stringify(rows)}`);
    expect(!rows.some(([, d]) => d.includes('{"')), `${tag}: Activity shows raw JSON: ${rows.map(([, d]) => d).join(" | ")}`);
  });

  await stage("npm scopes", async () => {
    await go(page, tag, "#/policy");
    const card = ".card:has(h2:text-is('npm scopes'))";
    await page.waitForSelector(card, { timeout: 3000 });
    expect(((await page.textContent(card)) || "").includes("@acme"), `${tag}: the organization's own scope is not listed`);
    await page.fill(`${card} input`, "@walk");
    await page.click(`${card} button[type=submit]`);
    await toastText(page, "good");
    await page.waitForSelector(`${card} td:text-is('@walk')`, { timeout: 3000 });
    page.expected(1, 409);
    await page.click(`${card} tr:has(td:text-is('@acme')) button:text-is('Remove')`);
    const said = await toastText(page, "bad");
    expect(/holds/.test(said), `${tag}: removing a scope that holds packages said ${JSON.stringify(said)}`);
    await page.click(`${card} tr:has(td:text-is('@walk')) button:text-is('Remove')`);
    await toastText(page, "good");
  });

  await stage("connect", async () => {
    await go(page, tag, "#/connect");
    await page.click("button:text-is('Mint an install token')");
    await page.waitForSelector(".secret");
    await page.click("button:text-is('Mint a publish token')");
    await page.waitForFunction(() => document.querySelectorAll(".secret").length >= 2, null, { timeout: 3000 }).catch(() => {});
    const secrets = await page.$$eval(".secret", (s) => s.map((e) => e.textContent));
    expect(secrets.length === 2 && secrets[0] !== secrets[1], `${tag}: the publish token replaced the install token, which was "shown once"`);
    await page.click(".tabs button:text-is('npm')");
    const npm = (await page.textContent(".card:has(.tabs)")) || "";
    expect(npm.includes("@acme:registry="), `${tag}: the npm snippet does not route @acme`);
    expect(!/Or everything through Skein/.test(npm), `${tag}: "everything through Skein" is offered while npm is private, where it would 404 every public dependency`);
    await go(page, tag, "#/tokens");
    const labels = await page.$$eval(".content tbody tr td:first-child", (t) => t.map((e) => e.textContent));
    expect(new Set(labels).size === labels.length, `${tag}: two tokens share a label: ${labels.join(" | ")}`);
    const asked = answerNext(page, false);
    await page.click(".content tbody tr:first-child button:text-is('Revoke')");
    const msg = await asked;
    expect(/package:(read|write)/.test(msg) && /\d{4}-\d{2}-\d{2}/.test(msg), `${tag}: the revoke confirm says only ${JSON.stringify(msg)}`);
  });

  await stage("remove a person", async () => {
    await go(page, tag, "#/people");
    const asked = answerNext(page, true);
    await page.click("tr:has(strong:text-is('pat')) button:text-is('Remove')");
    await asked;
    await toastText(page, "good");
    await go(page, tag, `#/packages/${await packageId(page, "@acme/pat-lib")}`);
    const by = (await page.textContent(".card:has(h2:has-text('Versions')) tbody tr td:nth-child(3)")) || "";
    expect(by.includes("pat"), `${tag}: after pat was removed, @acme/pat-lib says it was published by ${JSON.stringify(by)}`);
    await go(page, tag, "#/activity");
    const who = await page.$$eval(".content tbody tr td:nth-child(2)", (t) => t.map((e) => e.textContent));
    const raw = who.find((w) => w.startsWith("user:"));
    expect(!raw, `${tag}: Activity names a removed person by id: ${raw}`);
  });

  await stage("session ended", async () => {
    const rita = await open("flows/rita", { width: 1280, height: 900, scheme: "dark" });
    await signIn(rita, "rita", READER_PW);
    await go(rita, "flows/rita", "#/tokens");
    const scopes = await rita.$$eval("select option", (o) => o.map((e) => e.textContent));
    expect(!scopes.some((o) => o.startsWith("org:read")), `${tag}: a reader is offered "${scopes.find((o) => o.startsWith("org:read"))}", and a reader cannot read settings`);
    await go(page, tag, "#/people");
    await page.click("tr:has(strong:text-is('rita')) button:text-is('Set password')");
    await page.waitForSelector("form.set-password", { timeout: 3000 });
    await page.click("form.set-password button:text-is('Generate')");
    const pw = await page.inputValue("form.set-password input");
    expect(pw.length >= 16, `${tag}: a generated password is ${pw.length} characters`);
    expect((await page.getAttribute("form.set-password input", "type")) === "text", `${tag}: a generated password is hidden from the admin who has to pass it on`);
    await page.click("form.set-password button[type=submit]");
    expect(/password set/i.test(await toastText(page, "good")), `${tag}: setting rita's password said nothing`);
    rita.expected(4, 401);
    await rita.click("nav a:has-text('Admission policy')");
    await rita.waitForSelector("input[name=username]", { timeout: 5000 });
    const why = (await rita.textContent(".login")) || "";
    expect(/session (has )?ended/i.test(why), `${tag}: rita's session ended underneath her without a word`);
    await rita.fill("input[name=username]", "rita");
    await rita.fill("input[name=password]", pw);
    await rita.click("button[type=submit]");
    await rita.waitForSelector(".sidebar");
    await rita.waitForTimeout(300);
    expect(rita.url().endsWith("#/policy"), `${tag}: signing in again took rita to ${rita.url().split("#")[1]}, not where she was going`);
    await rita.context().close();
  });

  await stage("lockout", async () => {
    const tom = await open("flows/tom", { width: 390, height: 844, scheme: "light" });
    await tom.goto(BASE + "/");
    tom.expected(8, [401, 429]);
    for (let i = 0; i < 6; i++) {
      await tom.fill("input[name=username]", "tom");
      await tom.fill("input[name=password]", "wrong-" + i);
      await tom.click("button[type=submit]");
      await tom.waitForFunction(() => !document.querySelector("button[type=submit]").disabled);
    }
    const said = (await tom.textContent(".login .notice.bad")) || "";
    expect(/minute/.test(said) && !/\d{3,} seconds/.test(said), `${tag}: the lock reads ${JSON.stringify(said)}`);
    await tom.context().close();
  });

  await stage("org name", async () => {
    await go(page, tag, "#/settings");
    const input = ".card:has(h2:text-is('Organization name')) input";
    await page.fill(input, "Bad Name!");
    await page.click(".card:has(h2:text-is('Organization name')) button[type=submit]");
    await page.waitForTimeout(400);
    expect(!(await page.$eval(input, (i) => i.checkValidity())), `${tag}: "Bad Name!" passes the name field's own check`);
    await page.fill(input, "acme-corp");
    await page.click(".card:has(h2:text-is('Organization name')) button[type=submit]");
    await toastText(page, "good");
    await go(page, tag, "#/connect");
    await page.click(".tabs button:text-is('npm')");
    const npm = (await page.textContent(".card:has(.tabs)")) || "";
    expect(npm.includes("@acme:registry=") && npm.includes("@acme-corp:registry="),
      `${tag}: after renaming acme to acme-corp the npm snippet routes ${JSON.stringify((npm.match(/@[a-z0-9-]+:registry=/g) || []).join(" "))}; every @acme package would go to npmjs`);
    await go(page, tag, "#/settings");
    await page.fill(input, "acme");
    await page.click(".card:has(h2:text-is('Organization name')) button[type=submit]");
    await toastText(page, "good");
  });

  if (OUT) await page.screenshot({ path: `${OUT}/flows-end.png`, fullPage: true });
  await page.context().close();
}

// ------------------------------------------------------ every page, 2x2

for (const scheme of ["dark", "light"]) {
  for (const [width, height, size] of [[1280, 900, "desktop"], [390, 844, "phone"]]) {
    const tag = `${scheme}/${size}`;
    const page = await open(tag, { width, height, scheme });
    await stage(tag, async () => {
      await signIn(page, "admin", PW);
      const routes = ["#/", "#/connect", "#/tokens", "#/people", "#/policy", "#/findings", "#/activity", "#/settings"];
      const list = await page.request.get(BASE + "/api/v1/packages", { headers: { "x-skein-csrf": "1" } });
      for (const p of (await list.json()).packages) routes.push(`#/packages/${p.id}`);
      for (const route of routes) {
        await page.goto(BASE + "/" + route);
        await settled(page, tag, route);
        if (OUT) {
          const name = route.replace(/[#/]+/g, "_").replace(/^_|_$/g, "") || "packages";
          await page.screenshot({ path: `${OUT}/${scheme}-${size}-${name}.png`, fullPage: true });
        }
      }
    });
    await page.context().close();
  }
}

await browser.close();
for (const p of problems) console.log(p);
if (threw) console.log(`!!! ${threw} stage(s) threw`);
console.log(problems.length ? `${problems.length} problem(s)` : "0 problems");
process.exit(problems.length ? 1 : 0);
