import AxeBuilder from '@axe-core/playwright';
import { expect as rawExpect, test as rawTest } from '@playwright/test';

import { expect, test } from './quality-fixture';

test('public topology explains access, expiry, and included data without authenticated controls', async ({ page }, testInfo) => {
  await page.goto('/topology/shared/fixture-token', { waitUntil: 'networkidle' });

  await expect(page.getByRole('heading', { name: 'Network topology' })).toBeVisible();
  await expect(page.getByText('Read-only public view')).toBeVisible();
  await expect(page.getByText('Expires', { exact: false })).toContainText('2026-09-09 10:30:00 UTC');
  await expect(page.getByText('Live client devices included')).toBeVisible();
  await expect(page.getByLabel('Devices', { exact: true })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Interactive network topology graph' })).toBeVisible();
  await expect(page.getByRole('navigation')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Share', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Debug', exact: true })).toHaveCount(0);
  await expect(page.getByText('Account', { exact: true })).toHaveCount(0);

  const fullAxe = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(fullAxe.violations).toEqual([]);

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('shared-topology.png'),
    fullPage: true,
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);

  let deviceRequests = 0;
  page.on('request', request => {
    if (new URL(request.url()).pathname.endsWith('/devices')) deviceRequests += 1;
  });
  await page.goto('/topology/shared/structure-token', { waitUntil: 'networkidle' });
  await expect(page.getByText('Does not expire')).toBeVisible();
  await expect(page.getByText('Network structure only')).toBeVisible();
  await expect(page.getByLabel('Devices', { exact: true })).toHaveCount(0);
  expect(deviceRequests).toBe(0);

  const structureAxe = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(structureAxe.violations).toEqual([]);
});

rawTest('expired and revoked public topology tokens stay unavailable', async ({ page }) => {
  for (const token of ['expired-token', 'revoked-token']) {
    const response = await page.goto(`/topology/shared/${token}`, { waitUntil: 'domcontentloaded' });
    rawExpect(response?.status()).toBe(404);
    await rawExpect(page.locator('#topoSvg')).toHaveCount(0);
  }
});
