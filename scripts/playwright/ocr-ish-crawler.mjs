import { chromium } from 'playwright';

const base = process.env.BW_BASE || 'http://127.0.0.1:4000';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
await page.goto(base, { waitUntil: 'domcontentloaded' });

for (let i = 0; i < 5; i += 1) {
  await page.screenshot({ path: `/tmp/bw-shot-${i}.png` });
  const links = await page.locator('a').all();
  if (!links.length) break;
  await links[Math.min(i, links.length - 1)].click({ timeout: 2000 }).catch(() => {});
  await page.waitForTimeout(300);
}

console.log('final url', page.url());
await browser.close();
