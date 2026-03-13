import { chromium } from 'playwright';

const base = process.env.BW_BASE || 'http://127.0.0.1:4000';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
await page.goto(base, { waitUntil: 'domcontentloaded' });

for (let i = 0; i < 8; i += 1) {
  await page.mouse.move(20 + i * 15 + Math.random() * 10, 100 + Math.random() * 80);
  await page.waitForTimeout(80 + Math.random() * 120);
}

await page.waitForTimeout(700);
const res = await page.request.get(`${base}/__dashboard`, { headers: { accept: 'application/json' } });
console.log('dashboard status', res.status());
await browser.close();
