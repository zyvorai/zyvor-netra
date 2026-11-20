// Screenshot every dashboard page in light, dark and mobile for visual review.
//
//   NETRA_DEV_API=https://<lab>:30870 npx vite &          # dev server proxied to a live controller
//   NETRA_TOKEN=<api key> node tests/page-shots.cjs [page ...]
//
// Writes $NETRA_SHOTS_DIR (default /tmp/netra-shots)/<page>-<variant>.png and fails on page
// errors or sideways scroll. Read-only: it only navigates and scrolls, never clicks controls.
const { chromium } = require('playwright');
const fs = require('node:fs');

const ALL = ['overview', 'connections', 'workloads', 'pods', 'vms', 'explain', 'traffic', 'capture', 'health', 'path', 'drops', 'congestion', 'sysctl-audit', 'node-resources', 'l7', 'surfaces', 'features', 'insights', 'topology', 'incidents', 'ebpf', 'policies', 'audit', 'flows', 'report', 'scorecard', 'talkers', 'fleet'];
const pages = process.argv.slice(2).length ? process.argv.slice(2) : ALL;
const base = process.env.NETRA_WEB_URL || 'http://127.0.0.1:5173';
const token = process.env.NETRA_TOKEN || '';
const out = process.env.NETRA_SHOTS_DIR || '/tmp/netra-shots';
const variants = (process.env.NETRA_SHOTS_VARIANTS || 'light,dark,mobile').split(',');
const settle = Number(process.env.NETRA_SHOTS_SETTLE_MS || 7000);

(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.NETRA_CHROMIUM_EXECUTABLE || undefined, args: ['--no-sandbox'] });
  const failures = [];
  for (const page of pages) {
    for (const v of variants) {
      const mobile = v === 'mobile';
      const ctx = await browser.newContext({ viewport: mobile ? { width: 390, height: 844 } : { width: 1440, height: 1000 }, ignoreHTTPSErrors: true });
      const p = await ctx.newPage();
      const errors = [];
      p.on('pageerror', (e) => errors.push(e.message));
      await p.addInitScript(([t, theme]) => {
        if (t) localStorage.setItem('netra-token', t);
        localStorage.setItem('netra-theme', theme);
      }, [token, v === 'dark' ? 'dark' : 'light']);
      await p.goto(`${base}/#page=${page}`);
      await p.waitForTimeout(settle);
      const height = await p.evaluate(() => document.documentElement.scrollHeight);
      for (let y = 0; y < height; y += 500) {
        await p.mouse.wheel(0, 500);
        await p.waitForTimeout(80);
      }
      await p.waitForTimeout(800);
      await p.evaluate(() => window.scrollTo(0, 0));
      const file = `${out}/${page}-${v}.png`;
      await p.screenshot({ path: file, fullPage: true });
      const vp = p.viewportSize();
      await p.screenshot({ path: file.replace(/\.png$/, '-top.png'), fullPage: true, clip: { x: 0, y: 0, width: vp.width, height: Math.min(height, mobile ? 1700 : 1800) } });
      const fits = await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
      if (!fits) failures.push(`${page}/${v}: scrolls sideways`);
      if (errors.length) failures.push(`${page}/${v}: ${errors.join('; ')}`);
      console.log(`${fits && !errors.length ? 'ok  ' : 'FAIL'} ${file}`);
      await ctx.close();
    }
  }
  await browser.close();
  if (failures.length) {
    console.error(failures.join('\n'));
    process.exit(1);
  }
})();
