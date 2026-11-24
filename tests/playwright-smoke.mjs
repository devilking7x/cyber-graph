// CyberGraph Playwright smoke test — drives the real page (local server or live URL)
// through the actual Relate WASM engine in Chromium.
// Usage: node tests/playwright-smoke.mjs [baseUrl] [screenshotPath]
//   default baseUrl: http://127.0.0.1:8901/  (serves the repo root itself if needed)
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const BASE = process.argv[2] || 'http://127.0.0.1:8901/';
const SHOT = process.argv[3] || null;
const CHROME = process.env.HOME + '/.cache/ms-playwright/chromium-1254/chrome-linux64/chrome';

let server = null;
async function ensureServer() {
  if (process.argv[2]) return; // testing a given URL, no local server
  try {
    const res = await fetch(BASE);
    if (res.ok) return;
  } catch { /* start server */ }
  server = spawn('python3', ['-m', 'http.server', '8901', '--bind', '127.0.0.1'], { cwd: process.cwd() });
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 300));
    try { if ((await fetch(BASE)).ok) return; } catch { /* retry */ }
  }
  throw new Error('local server did not come up');
}

const checks = [];
function check(name, ok, detail = '') {
  checks.push({ name, ok: !!ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
}

try {
  await ensureServer();
  const browser = await chromium.launch({ executablePath: CHROME, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  await page.goto(BASE, { waitUntil: 'load', timeout: 30000 });
  await page.waitForSelector('#status.ok', { timeout: 30000 });
  const status = await page.textContent('#status');
  check('status shows Relate ready with 34 nodes / 39 relationships',
    /34 nodes, 39 relationships/.test(status), status.slice(0, 120));

  const stats = await page.textContent('#stats');
  check('stats bar lists counts', /34.*nodes/.test(stats) && /39.*relationships/.test(stats), stats.slice(0, 120));

  const nodeCount = await page.locator('#graph .node').count();
  const edgeCount = await page.locator('#graph .edge').count();
  check('SVG renders 34 nodes', nodeCount === 34, `got ${nodeCount}`);
  check('SVG renders 39 edges', edgeCount === 39, `got ${edgeCount}`);

  // Click a node -> details panel populates.
  await page.locator('#graph .node').first().click();
  const details = await page.textContent('#details');
  check('clicking a node shows details + neighbours', /Neighbours \(\d+\)/.test(details), details.slice(0, 100));

  // Path finder (defaults: CVE-2024-3094 -> CVE-2021-44228 via T1059).
  await page.click('#path-run');
  await page.waitForFunction(() => !document.querySelector('#path-result').textContent.includes('No path searched'), null, { timeout: 10000 });
  const pathText = await page.textContent('#path-result');
  check('shortestPath finds CVE-2024-3094 -> T1059 -> CVE-2021-44228',
    pathText.includes('CVE-2024-3094') && pathText.includes('T1059') && pathText.includes('CVE-2021-44228'), pathText.slice(0, 160));

  // Query box default query returns 8 CVE rows.
  await page.click('#cypher-run');
  await page.waitForSelector('#cypher-result table', { timeout: 10000 });
  const rows = await page.locator('#cypher-result tbody tr').count();
  check('default Cypher query returns 8 CVE rows', rows === 8, `got ${rows}`);

  // Bad query surfaces a Relate error, honestly.
  await page.fill('#cypher', 'MATCH (n RETURN n');
  await page.click('#cypher-run');
  await page.waitForSelector('#cypher-result .error', { timeout: 10000 });
  check('invalid Cypher shows an engine error', true);

  // Add-node form works in-session.
  await page.fill('#add-id', 'CVE-2024-99999');
  await page.fill('#add-name', 'Smoke test flaw');
  await page.click('#add-run');
  await page.waitForFunction(() => document.querySelector('#stats').textContent.includes('35'), null, { timeout: 10000 });
  const stats2 = await page.textContent('#stats');
  check('add-node form grows graph to 35 nodes (session only)', /35/.test(stats2), stats2.slice(0, 120));

  if (SHOT) { await page.screenshot({ path: SHOT, fullPage: true }); console.log('screenshot:', SHOT); }
  check('no page errors / console errors', errors.length === 0, errors.slice(0, 3).join(' | '));
  await browser.close();
} finally {
  if (server) server.kill();
}

const failed = checks.filter((c) => !c.ok).length;
console.log(`\n${checks.length - failed}/${checks.length} smoke checks passed`);
process.exit(failed ? 1 : 0);
