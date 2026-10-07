// The web UI against a REAL controller (scripts/ci-web-e2e.sh starts netrad with the
// built UI and seeded agent data). Unlike investigation-smoke.cjs, nothing is
// intercepted: this proves the built UI, the API and the auth model work together.
//
//   login      wrong username / wrong key are refused with an alert and open no session;
//              the right key signs in with an HttpOnly session cookie (the bearer is in no
//              browser storage and not in the cookie); signing out ends the session
//   pages      every page in the navigation loads with the real API behind it: no uncaught
//              exception, no error boundary, non-empty content, no 401 after sign-in, and
//              no request to an API path that does not exist (404); every /api/ failure is
//              printed so an operator can read it
//   data       the seeded agent's node and traffic actually appear in several pages
//   actions    a deny rule added in the Firewall page reaches the controller and its audit
//              trail, and removing it in the page removes it; the enforcement lease
//              controls switch the mode and back
//
// Env: NETRA_URL, NETRA_API_KEY, OUT_DIR (screenshots + report), SEED_NODE, SEED_IP.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BASE = (process.env.NETRA_URL || 'http://127.0.0.1:30870').replace(/\/$/, '');
const KEY = process.env.NETRA_API_KEY || '';
const OUT = process.env.OUT_DIR || '/tmp/netra-web-e2e';
const SEED_NODE = process.env.SEED_NODE || 'ci-web';
const SEED_IP = process.env.SEED_IP || '203.0.113.5';
fs.mkdirSync(OUT, { recursive: true });

// Kept in step with web/src/lib/investigation.ts's `pages` const by a check below.
const PAGES = ['overview', 'connections', 'workloads', 'explain', 'pods', 'vms', 'health', 'path', 'drops', 'l7',
  'insights', 'topology', 'incidents', 'policies', 'flows', 'ebpf', 'audit', 'report', 'scorecard', 'talkers', 'fleet',
  'surfaces', 'features', 'traffic', 'capture', 'congestion', 'sysctl-audit', 'node-resources', 'security-review',
  'metrics', 'metric-anomalies', 'metric-alerts'];

const api = async (p, opts = {}) => {
  const r = await fetch(BASE + p, { ...opts, headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json', ...(opts.headers || {}) } });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const check = (cond, msg, failures) => { if (!cond) { failures.push(msg); console.log('  FAIL:', msg); } return cond; };

(async () => {
  const failures = [];
  // The page list must match the navigation the UI ships.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'lib', 'investigation.ts'), 'utf8');
  const pagesLine = src.slice(src.indexOf('export const pages ='), src.indexOf('\n', src.indexOf('export const pages =')));
  const declared = [...pagesLine.matchAll(/'([a-z0-9-]+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual([...PAGES].sort(), declared, 'PAGES in this test no longer matches investigation.ts; update it');

  const browser = await chromium.launch({ headless: true, executablePath: process.env.NETRA_CHROMIUM_EXECUTABLE || undefined, args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.on('dialog', (d) => d.accept()); // the UI confirms risky actions with window.confirm

  let current = 'login';
  const perPage = {};
  const bucket = (id) => (perPage[id] ||= { pageErrors: [], consoleErrors: [], apiFailures: [], apiOk: 0 });
  page.on('pageerror', (e) => bucket(current).pageErrors.push(String(e.message).slice(0, 200)));
  page.on('console', (m) => { if (m.type() === 'error') bucket(current).consoleErrors.push(m.text().slice(0, 200)); });
  page.on('response', (r) => {
    const u = new URL(r.url());
    if (!u.pathname.startsWith('/api/')) return;
    const b = bucket(current);
    if (r.status() >= 400) b.apiFailures.push({ path: u.pathname, status: r.status() });
    else b.apiOk++;
  });

  // ---- login -------------------------------------------------------------------
  console.log('==> login');
  await page.goto(BASE + '/');
  await page.getByRole('heading', { name: 'Sign in.' }).waitFor({ timeout: 15000 });
  // The dashboard session is an HttpOnly cookie; the bearer must be in no browser storage.
  const session = async () => (await context.cookies(BASE)).find((c) => c.name === 'netra_session');
  const stored = () => page.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]));
  const whoami = () => page.evaluate(() => fetch('/api/v1/whoami').then((r) => r.status));
  check((await session()) === undefined, 'a session cookie exists before anyone signed in', failures);
  check((await whoami()) === 401, 'the API answered without a session or bearer', failures);

  for (const [user, pass, label] of [['admin', 'not-the-key', 'a wrong key'], ['root', KEY, 'a wrong username']]) {
    await page.getByLabel('Username').fill(user);
    await page.getByLabel('Password').fill(pass);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('alert').waitFor({ timeout: 15000 });
    check(/Wrong username or password/.test(await page.getByRole('alert').innerText()), `${label}: no "Wrong username or password" alert`, failures);
    check((await session()) === undefined, `${label}: a session was opened after a refused sign-in`, failures);
    check(!(await stored()).includes(KEY), `${label}: the key was written to browser storage`, failures);
  }
  await page.screenshot({ path: path.join(OUT, 'login-refused.png') });

  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill(KEY);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Sign in.' }).waitFor({ state: 'detached', timeout: 15000 });
  const sess = await session();
  check(sess !== undefined, 'no session cookie after a successful sign-in', failures);
  if (sess) {
    check(sess.httpOnly === true, 'the session cookie is readable by page scripts (not HttpOnly)', failures);
    check(sess.sameSite === 'Strict', `the session cookie SameSite is ${sess.sameSite}, want Strict`, failures);
    check(!sess.value.includes(KEY), 'the session cookie contains the API key', failures);
  }
  check(!(await stored()).includes(KEY), 'the key was written to browser storage after sign-in', failures);
  check(!(await page.evaluate(() => document.cookie)).includes('netra_session'), 'page scripts can read the session cookie', failures);
  check((await whoami()) === 200, 'the session cookie does not authenticate the API', failures);
  console.log('    refused twice, then signed in');

  // ---- every page, against the real API -----------------------------------------
  console.log('==> every page loads against the real controller');
  const shows = {};
  for (const id of PAGES) {
    current = id;
    await page.evaluate((h) => { window.location.hash = h; }, `#page=${id}`);
    await page.waitForTimeout(1800); // let the page's first fetches finish
    const text = await page.evaluate(() => document.body.innerText || '');
    const b = bucket(id);
    check(text.trim().length > 40, `${id}: the page is empty`, failures);
    check(!/Something went wrong|Application error|Unexpected Application Error|Minified React error/i.test(text), `${id}: an error screen is showing`, failures);
    check(b.pageErrors.length === 0, `${id}: uncaught exception(s): ${b.pageErrors.join(' | ')}`, failures);
    const bad = b.consoleErrors.filter((m) => /Uncaught|TypeError|ReferenceError|Cannot read|is not a function|is not defined/.test(m));
    check(bad.length === 0, `${id}: console error(s): ${bad.join(' | ')}`, failures);
    check(!b.apiFailures.some((f) => f.status === 401), `${id}: a 401 after signing in: ${JSON.stringify(b.apiFailures.filter((f) => f.status === 401))}`, failures);
    check(!b.apiFailures.some((f) => f.status === 404), `${id}: the UI called an API path that does not exist: ${JSON.stringify(b.apiFailures.filter((f) => f.status === 404))}`, failures);
    shows[id] = text.includes(SEED_NODE) || text.includes(SEED_IP);
    if (id === 'overview') {
      // Regression: one failing feed (insights/summary answers 502 without Kubernetes) used to zero every
      // board here. The seeded agent is live, so the "node agents" board must read 1, not 0.
      // Poll, do not read once: the tile shows 0 until its /status fetch lands and then counts up over 600 ms,
      // and on a loaded runner a single read at a fixed delay caught it at "0" (a flake on main). A board
      // that STAYS at 0 for 15 s is still the regression this check exists for.
      const readBoard = () => page.evaluate(() => {
        const el = [...document.querySelectorAll('*')].find((n) => n.children.length === 0 && /^node agents$/i.test((n.textContent || '').trim()));
        return el && el.parentElement ? (el.parentElement.innerText || '').replace(/\s+/g, ' ').trim() : '';
      });
      const agentsOn = (b) => { const x = /(\d+)\s*node agents/i.exec(b); return x ? Number(x[1]) : 0; };
      let board = await readBoard();
      for (let i = 0; i < 30 && agentsOn(board) < 1; i++) { await page.waitForTimeout(500); board = await readBoard(); }
      check(agentsOn(board) >= 1, `overview: the node-agents board reads "${board}" although one agent is reporting`, failures);
    }
    await page.screenshot({ path: path.join(OUT, `page-${id}.png`), fullPage: true });
  }
  const seenOn = PAGES.filter((id) => shows[id]);
  console.log(`    seeded data (${SEED_NODE} / ${SEED_IP}) is visible on ${seenOn.length} pages: ${seenOn.join(', ')}`);
  check(seenOn.length >= 3, `the seeded agent data appears on only ${seenOn.length} pages (${seenOn.join(', ')}); the UI is not showing what the API serves`, failures);

  // A bare controller has no Kubernetes API, Hubble or Cilium CRDs, so the endpoints that
  // need them answer 502 / 409. That is the documented behaviour and the pages cope; any
  // OTHER failing endpoint, or a different status from these, is a regression.
  const EXPECTED_UNAVAILABLE = {
    '/api/v1/policies': [409], '/api/v1/policies/gitops/status': [409],
    '/api/v1/ebpf/workloads': [502], '/api/v1/flows/summary': [502],
    '/api/v1/insights/dependencies': [502], '/api/v1/insights/exposure': [502], '/api/v1/insights/new-since-start': [502],
    '/api/v1/insights/recommendations': [502], '/api/v1/insights/remediations': [502], '/api/v1/insights/summary': [502],
    '/api/v1/pods': [502], '/api/v1/vms': [502],
  };
  for (const id of PAGES) {
    const unexpected = perPage[id].apiFailures.filter((f) => !(EXPECTED_UNAVAILABLE[f.path] || []).includes(f.status));
    check(unexpected.length === 0, `${id}: unexpected API failure(s): ${JSON.stringify(unexpected)}`, failures);
  }
  console.log('    expected /api unavailability on a bare controller (no Kubernetes, Hubble or Cilium):');
  const seenFail = {};
  for (const id of PAGES) for (const f of perPage[id].apiFailures) (seenFail[`${f.status} ${f.path}`] ||= new Set()).add(id);
  for (const [k, v] of Object.entries(seenFail).sort()) console.log(`      ${k}  <- ${[...v].join(', ')}`);

  // ---- a real action through the UI ----------------------------------------------
  console.log('==> a deny rule and the enforcement lease, through the Firewall page');
  current = 'ebpf-actions';
  await page.evaluate(() => { window.location.hash = '#page=ebpf'; });
  const IP = '203.0.113.88';
  // The form is a .ruleform row: the input, the direction select and the Add button share a parent.
  const ipInput = page.getByLabel('IP address', { exact: true });
  await ipInput.waitFor({ timeout: 15000 });
  const row = ipInput.locator('xpath=..');
  await ipInput.fill(IP);
  await row.getByLabel('Deny direction').selectOption('both');
  await row.getByRole('button', { name: 'Add', exact: true }).click();
  // A bare controller answers /api/v1/ebpf/workloads with 502 (it needs the Kubernetes API). The rule
  // must still appear: with Promise.all in the page's loader that one failure left the page unpopulated.
  await page.getByRole('button', { name: `Remove ${IP}` }).waitFor({ timeout: 15000 });
  let cfg = (await api('/api/v1/ebpf/config')).body;
  check((cfg.blockedIPv4 || []).includes(IP), 'the deny rule added in the UI is not in the controller config', failures);
  check((cfg.blockedIngressIPv4 || []).includes(IP), 'direction "both" did not reach the ingress list', failures);
  const audit = (await api('/api/v1/audit?limit=50')).body.items || [];
  check(audit.some((e) => /deny/.test(e.action) && JSON.stringify(e).includes(IP)), 'the UI action is not in the audit trail', failures);

  await page.getByRole('button', { name: 'Enforce lease' }).click();
  await page.getByText('Lease expires', { exact: false }).waitFor({ timeout: 15000 });
  check((await api('/api/v1/ebpf/config')).body.mode === 'enforce', 'the Enforce lease button did not put the controller in enforce', failures);
  await page.getByRole('button', { name: 'Observe', exact: true }).click();
  for (let i = 0; i < 30 && (await api('/api/v1/ebpf/config')).body.mode !== 'observe'; i++) await page.waitForTimeout(300);
  check((await api('/api/v1/ebpf/config')).body.mode === 'observe', 'the Observe button did not return the controller to observe', failures);

  await page.getByRole('button', { name: `Remove ${IP}` }).click();
  await page.getByRole('button', { name: `Remove ${IP}` }).waitFor({ state: 'detached', timeout: 15000 });
  cfg = (await api('/api/v1/ebpf/config')).body;
  check(!(cfg.blockedIPv4 || []).includes(IP), 'the rule removed in the UI is still in the controller config', failures);
  await page.screenshot({ path: path.join(OUT, 'firewall-after-actions.png'), fullPage: true });
  console.log('    added, seen in the audit trail, lease on and off, removed');

  // The Audit page shows what was just done.
  await page.evaluate(() => { window.location.hash = '#page=audit'; });
  await page.waitForTimeout(1800);
  check(/deny/.test(await page.evaluate(() => document.body.innerText)), 'the Audit page does not show the deny actions just taken', failures);

  // ---- sign out -----------------------------------------------------------------
  console.log('==> sign out');
  const out = page.getByRole('button', { name: /log ?out|sign ?out/i });
  if (await out.count()) {
    await out.first().click();
    await page.getByRole('heading', { name: 'Sign in.' }).waitFor({ timeout: 15000 });
    check((await session()) === undefined, 'the session cookie survived signing out', failures);
    check((await whoami()) === 401, 'the API still answers after signing out', failures);
    console.log('    signed out: the login form is back and the session is gone');
  } else {
    check(false, 'there is no sign-out button in the navigation', failures);
  }

  fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify({ perPage, seenOn, failures }, null, 2));
  await browser.close();
  if (failures.length) {
    console.error(`\n${failures.length} check(s) failed`);
    process.exit(1);
  }
  console.log('all web e2e checks passed');
})().catch((e) => { console.error(e); process.exit(1); });
