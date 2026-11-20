// Run with Vite on localhost:5173 and Playwright available to Node.
// All API calls are intercepted; this tests UI behavior, not a live kernel.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.NETRA_CHROMIUM_EXECUTABLE || undefined, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.addInitScript(() => localStorage.setItem('netra-token', 'fixture-token'));
  let failAgents = false, emptyAgents = false, agentRequests = 0;
  const report = { node: 'edge-01', stale: false, ageSeconds: 2, mode: 'observe', observedAt: '2026-09-12T10:00:00Z', programs: [{ name: 'cgroup', attached: true }], workloads: [{ namespace: 'production', pod: 'payments-api', workloadKind: 'ReplicaSet', workloadName: 'payments-abc' }], events: [
    { namespace: 'production', pod: 'payments-api', sourceIp: '10.42.0.8', sourcePort: 44321, destinationIp: '203.0.113.20', destinationPort: 443, protocol: 'TCP', direction: 'egress', hook: 'cgroup', action: 'blocked', reason: 'cidr-deny', observedAt: '2026-09-12T09:59:00Z', comm: 'worker', pid: 210 },
    { namespace: 'development', pod: 'preview-api', sourceIp: '10.42.0.9', destinationIp: '10.43.0.10', destinationPort: 53, protocol: 'UDP', direction: 'egress', hook: 'cgroup', action: 'observed', observedAt: '2026-09-12T09:58:00Z' },
  ] };
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    let body = {};
    if (path === '/api/v1/agents') { agentRequests++; if (failAgents) return route.fulfill({ status: 503, body: 'Agent reports unavailable' }); body = { items: emptyAgents ? [] : [report, { node: 'edge-02', stale: true, observedAt: '2026-09-12T08:00:00Z' }] }; }
    if (path === '/api/v1/status') body = { fastPath: { mode: 'observe', shield: { mode: 'audit' } }, agents: emptyAgents ? 0 : 2, staleAgents: emptyAgents ? 0 : 1 };
    if (path === '/api/v1/ebpf/health') body = { summary: { healthScore: 86, dnsFailures: 12, estimatedConnectFailures: 3, anomalies: [{ severity: 'warning', message: 'DNS failure ratio elevated', subject: 'production' }] } };
    if (path === '/api/v1/insights/summary') body = { driftFindings: 4, rateDriftFindings: 2, highExposure: 1 };
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('http://127.0.0.1:5173');
  const nodeAgents = (n) => page.locator('div:has(> span:text-is("node agents")) > b').filter({ hasText: new RegExp(`^${n}$`) });
  await page.getByRole('heading', { name: 'See the network. Diagnose it. Contain it.' }).waitFor();
  await page.getByText('One or more agents are stale.', { exact: false }).waitFor();
  await nodeAgents(2).waitFor();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'the Overview scrolls sideways at desktop width');
  await page.screenshot({ path: '/tmp/netra-overview.png', fullPage: true });
  await page.getByRole('button', { name: 'Investigate', exact: true }).click();
  await page.getByRole('region', { name: 'Investigate' }).getByRole('button', { name: /^Connections/ }).click();
  await page.getByRole('button', { name: 'Explain connection', exact: true }).first().waitFor();
  assert.equal(await page.getByRole('button', { name: 'Explain connection', exact: true }).count(), 2);
  await page.getByLabel('namespace (exact)', { exact: true }).fill('production');
  await page.waitForFunction(() => location.hash.includes('namespace=production'));
  await page.reload();
  await page.getByRole('button', { name: 'Explain connection', exact: true }).waitFor();
  assert.equal(await page.getByLabel('namespace (exact)', { exact: true }).inputValue(), 'production');
  assert.equal(await page.getByRole('button', { name: 'Explain connection', exact: true }).count(), 1);
  await page.getByRole('button', { name: 'Explain connection', exact: true }).click();
  await page.getByRole('dialog').waitFor();
  assert.match(await page.getByRole('dialog').innerText(), /does not identify a stable rule ID/);
  await page.screenshot({ path: '/tmp/netra-connection.png', fullPage: true });
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('dialog').count(), 0);
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Explain connection');
  await page.getByRole('button', { name: 'Explain connection', exact: true }).click();
  await page.getByRole('button', { name: 'Open workload', exact: true }).click();
  await page.getByRole('heading', { name: 'production/payments-api', exact: true }).waitFor();
  await page.getByText('Owner: ReplicaSet/payments-abc').waitFor();
  await page.getByRole('button', { name: 'Open filtered connections' }).click();
  await page.goBack();
  await page.getByRole('heading', { name: 'production/payments-api', exact: true }).waitFor();
  await page.goForward();
  await page.getByRole('button', { name: 'Pause updates' }).click();
  const requestsBefore = agentRequests;
  await page.waitForTimeout(10500);
  assert.equal(agentRequests, requestsBefore, 'pause prevents polling');
  await page.getByRole('button', { name: 'Resume updates' }).click();
  failAgents = true;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await page.getByRole('alert').waitFor();
  assert.equal(await page.getByRole('button', { name: 'Explain connection', exact: true }).count(), 1, 'retain last snapshot on error');
  failAgents = false; emptyAgents = true;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await page.getByText('No sampled events match this view.', { exact: false }).waitFor();
  await page.getByRole('button', { name: 'Overview', exact: true }).click();
  await nodeAgents(0).waitFor();
  assert.equal(await page.getByText('One or more agents are stale.', { exact: false }).count(), 0, 'no stale-agent notice with no agents');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '/tmp/netra-mobile.png', fullPage: true });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'mobile layout fits viewport');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light', 'light is the default theme');
  await page.getByRole('button', { name: 'Switch to dark mode' }).click();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await page.getByRole('button', { name: 'Switch to light mode' }).click();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
  assert.deepEqual(errors, []);
  await browser.close();
  console.log('PASS: navigation, scoped reload, evidence drawer/focus, workload drill-down, history, pause, failure retention, empty coverage, mobile, theme toggle; no page errors.');
})().catch(e => { console.error(e); process.exit(1); });
