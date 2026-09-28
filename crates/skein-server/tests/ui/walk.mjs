// A person's-eye walk through Skein's UI, in a real Chromium.
//
// Driven by `tests/ui_e2e.rs`, which starts a server, seeds it — a
// package whose metadata is markup, a yanked version, a person with a
// hostile display name — and hands over:
//
//   BASE          the server
//   PW            the admin's password
//   READER_PW     the password of `rita`, a reader
//   LICENSE_KEY   a valid licence key that covers one seat fewer than
//                 the install has
//   OUT           optional: a directory for screenshots
//
// It prints every problem, then `N problem(s)` or `0 problems`, and exits
// non-zero on any. A problem is: a console error or uncaught error that
// was not provoked on purpose, a 5xx, a page that never finished
// loading, a page that scrolls sideways, an error notice, markup from
// data executing, `null`/`undefined`/`NaN` rendered as text, or a step
// of the licence flow not doing what it says.

import { chromium } from "playwright";

const { BASE, PW, READER_PW, LICENSE_KEY, OUT } = process.env;
const problems = [];
const expect = (cond, msg) => { if (!cond) problems.push(msg); };
const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
);

// A page that records its own problems. `expected(n, status)` declares
// that the next `n` console errors about a response with that status are
// refusals the walk provokes on purpose.
async function open(tag, { width, height, scheme }) {
  const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme });
  const page = await ctx.newPage();
  let allowed = { n: 0, status: 0 };
  page.expected = (n, status) => { allowed = { n, status }; };
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    if (allowed.n > 0 && m.text().includes(`status of ${allowed.status}`)) { allowed.n--; return; }
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

async function settled(page, tag, route) {
  await page.waitForFunction(
    () => !document.querySelector(".content p.muted")?.textContent?.startsWith("Loading"),
    null, { timeout: 8000 },
  ).catch(() => problems.push(`${tag} ${route}: never finished loading`));
  await page.waitForTimeout(150);
  const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (over > 1) problems.push(`${tag} ${route}: the page scrolls sideways by ${over}px`);
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

// ------------------------------------------------------ every page, 2x2

for (const scheme of ["dark", "light"]) {
  for (const [width, height, size] of [[1280, 900, "desktop"], [390, 844, "phone"]]) {
    const tag = `${scheme}/${size}`;
    const page = await open(tag, { width, height, scheme });
    await signIn(page, "admin", PW);
    const routes = ["#/", "#/connect", "#/tokens", "#/people", "#/policy", "#/findings", "#/activity", "#/settings"];
    const list = await page.request.get(BASE + "/api/v1/packages", { headers: { "x-skein-csrf": "1" } });
    for (const p of (await list.json()).packages) routes.push(`#/packages/${p.id}`);
    for (const route of routes) {
      await page.goto(BASE + "/" + route);
      await settled(page, tag, route);
      if (OUT && size === "desktop") {
        const name = route.replace(/[#/]+/g, "_").replace(/^_|_$/g, "") || "packages";
        await page.screenshot({ path: `${OUT}/${scheme}-${name}.png`, fullPage: true });
      }
    }
    await page.context().close();
  }
}

await browser.close();
for (const p of problems) console.log(p);
console.log(problems.length ? `${problems.length} problem(s)` : "0 problems");
process.exit(problems.length ? 1 : 0);
