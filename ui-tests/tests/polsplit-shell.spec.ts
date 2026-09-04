import { expect, test } from './quality-fixture';

test('Policy Split uses the shared shell and completes one analysis', async ({ page }, testInfo) => {
  await page.goto('/fgt-polsplit/', { waitUntil: 'networkidle' });

  await expect(page.locator('.app-rail')).toBeVisible();
  await expect(page.locator('.app-rail [aria-current="page"]')).toHaveText(/Policy Split/);
  await expect(page.getByRole('heading', { level: 1, name: 'FortiGate Policy Split Advisor' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => ({
    loadPolicy: typeof (window as unknown as { loadPolicy?: unknown }).loadPolicy,
    analyze: typeof (window as unknown as { analyze?: unknown }).analyze,
  }))).toEqual({ loadPolicy: 'undefined', analyze: 'undefined' });

  const firewall = page.getByRole('combobox', { name: 'Firewall' });
  await firewall.click();
  await page.getByRole('option', { name: 'edge.example.test' }).click();
  await page.getByLabel('Policy ID').fill('42');
  await page.getByRole('button', { name: 'Load Policy' }).click();

  await expect(page.getByRole('heading', { name: /Current definition/ })).toBeVisible();
  await expect(page.locator('#ps-policy-summary')).toContainText('Synthetic open policy');
  await page.getByRole('button', { name: 'Analyze Traffic' }).click();

  await expect(page.getByRole('heading', { name: 'Observed Traffic' })).toBeVisible();
  await expect(page.locator('#ps-tuples-table')).toContainText('10.0.0.10');
  await page.getByRole('tab', { name: /Per service/ }).click();
  await expect(page.locator('#ps-strategy-panels')).toContainText('config firewall policy');

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('polsplit-analysis.png'),
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});
