import { chromium } from '@playwright/test';

const [origin, tracePath, widthRaw, heightRaw] = process.argv.slice(2);
const viewport = { width: Number(widthRaw), height: Number(heightRaw) };
if (!origin || !tracePath || !Number.isInteger(viewport.width) || !Number.isInteger(viewport.height)) {
  throw new Error('usage: trace-adm-vpn-secret-audit.mjs <origin> <trace> <width> <height>');
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ baseURL: origin, viewport });
await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
try {
  const page = await context.newPage();
  const response = await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });
  if (!response?.ok()) throw new Error(`ADM VPN fixture returned ${response?.status() ?? 'no response'}`);
  await page.getByRole('button', { name: 'Details for edge.example.test' }).click();
  await page.locator('#vpn-detail-7').getByRole('button', { name: 'Edit edge.example.test' }).click();
  await page.getByRole('dialog', { name: 'Edit configuration' }).waitFor({ state: 'visible' });
} finally {
  await context.tracing.stop({ path: tracePath });
  await context.close();
  await browser.close();
}
