# Playwright Adversarial Simulation

These scripts are optional adversarial checks for the Botwall demo.

## Prerequisites

- Node.js 20+
- `npm i -D playwright`

## Run

```bash
node scripts/playwright/clean-browser.mjs
node scripts/playwright/randomized-bot.mjs
node scripts/playwright/ocr-ish-crawler.mjs
```

All scripts target `http://127.0.0.1:4000` by default.
