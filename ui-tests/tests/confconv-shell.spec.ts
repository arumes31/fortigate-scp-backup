import { expect, test } from './quality-fixture';

test('Config Converter uses the shared shell and completes one conversion', async ({ page }, testInfo) => {
  await page.goto('/fgt-confconv/', { waitUntil: 'networkidle' });

  await expect(page.locator('.app-rail')).toBeVisible();
  await expect(page.locator('.app-rail [aria-current="page"]')).toHaveText(/Config Converter/);
  await expect(page.getByRole('heading', { level: 1, name: /Configuration Conversions/ })).toBeVisible();
  await expect(page.locator('.cc-primary-action .cc-alpha')).toHaveText('Alpha');
  await expect.poll(() => page.evaluate(() => ({
    loadSummary: typeof (window as unknown as { loadSummary?: unknown }).loadSummary,
    generate: typeof (window as unknown as { generate?: unknown }).generate,
  }))).toEqual({ loadSummary: 'undefined', generate: 'undefined' });

  const firewall = page.getByRole('combobox', { name: 'Firewall' });
  await firewall.click();
  await page.getByRole('option', { name: 'edge.example.test' }).click();
  await expect(page.locator('#cc-backup-info')).toContainText('FortiOS 7.6.1');

  await page.getByLabel('SD-WAN static routes → SD-WAN rules').check();
  await page.getByRole('button', { name: 'Generate', exact: true }).click();

  await expect(page.getByRole('heading', { name: 'Results' })).toBeVisible();
  await expect(page.locator('#cc-sections')).toContainText('config system sdwan');

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('confconv-result.png'),
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});
