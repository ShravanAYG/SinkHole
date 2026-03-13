import { chromium } from 'playwright';

const base = process.env.BW_BASE || 'http://127.0.0.1:4000';
const browser = await chromium.launch({ headless: false });
const page = await browser.newPage();
await page.goto(base, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(1500);
await page.mouse.wheel(0, 350);
await page.waitForTimeout(1200);
console.log('decision header:', (await page.request.get(base)).headers()['x-botwall-decision']);
await browser.close();
