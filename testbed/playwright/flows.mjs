// Drives flows-app in a Chrome that jsharvest watches, as an automation
// script would: Playwright attached over CDP, nothing to do with jsharvest.
// It works through the steps of flows.truth.json and logs when each began,
// for testbed flowscore.
//   node flows.mjs <flows.truth.json> <steps.jsonl> [cdp endpoint]
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { chromium } from 'playwright-core';

const [truthPath, logPath, endpoint = 'http://127.0.0.1:9333'] = process.argv.slice(2);
const truth = JSON.parse(await readFile(truthPath, 'utf8'));
const browser = await chromium.connectOverCDP(endpoint);
const page = browser.contexts().flatMap((c) => c.pages()).find((p) => p.url().startsWith(truth.url));
if (!page) throw new Error('no tab on ' + truth.url);
await writeFile(logPath, '');
for (const [i, s] of truth.steps.entries()) {
  await appendFile(logPath, JSON.stringify({ step: i, started: new Date().toISOString() }) + '\n');
  if (s.do === 'click') {
    await page.click(s.selector);
  } else if (s.text.endsWith('\r')) {
    await page.fill(s.selector, s.text.slice(0, -1));
    await page.press(s.selector, 'Enter');
  } else {
    await page.fill(s.selector, s.text);
  }
  console.log(`step ${i}: ${s.do} ${s.selector}`);
  await page.waitForTimeout(s.pause_ms ?? truth.pause_ms);
}
// Leave the browser and the tab as they are: they are the user's.
process.exit(0);
