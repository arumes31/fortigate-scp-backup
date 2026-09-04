import { expect, test } from './quality-fixture';
import { expect as rawExpect, test as rawTest } from '@playwright/test';

const expectedCSP = [
  "default-src 'self'",
  "script-src 'self'",
  "script-src-attr 'none'",
  "style-src 'self'",
  "style-src-elem 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

test('Core, public, and extension pages share the script-strict CSP', async ({ page }) => {
  for (const path of ['/login', '/dashboard', '/topology/shared/fixture-token', '/fgt-conftail/']) {
    await test.step(path, async () => {
      const response = await page.goto(path, { waitUntil: 'networkidle' });
      expect(response?.headers()['content-security-policy']).toBe(expectedCSP);
    });
  }
});

rawTest('the CSP blocks a deliberately injected inline script', async ({ page }) => {
  const violations: string[] = [];
  page.on('console', message => {
    if (/content security policy/i.test(message.text())) violations.push(message.text());
  });

  const response = await page.goto('/dashboard', { waitUntil: 'networkidle' });
  rawExpect(response?.headers()['content-security-policy']).toBe(expectedCSP);
  await page.evaluate(() => {
    const script = document.createElement('script');
    script.textContent = 'window.__fortisafeInlineExecuted = true';
    document.body.appendChild(script);
  });

  await rawExpect.poll(() => violations.length).toBeGreaterThan(0);
  rawExpect(await page.evaluate(() => (window as Window & { __fortisafeInlineExecuted?: boolean }).__fortisafeInlineExecuted)).toBeUndefined();
});
