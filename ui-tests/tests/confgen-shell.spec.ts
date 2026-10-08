import { expect, test } from './quality-fixture';

test.use({ trace: 'off', screenshot: 'off' });

test('ConfGen uses the shared shell and preserves template-to-generation workflow', async ({ page }, testInfo) => {
  await page.goto('/fgt-confgen/', { waitUntil: 'networkidle' });

  await expect(page.locator('.app-rail')).toBeVisible();
  await expect(page.locator('.app-rail [aria-current="page"]')).toHaveText(/Policy Generator/);
  await expect(page.getByRole('heading', { level: 1, name: 'FortiGate Policy Generator' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => ({
    loadTemplate: typeof (window as unknown as { loadTemplate?: unknown }).loadTemplate,
    searchable: typeof (window as unknown as { initSearchableSelect?: unknown }).initSearchableSelect,
  }))).toEqual({ loadTemplate: 'undefined', searchable: 'undefined' });

  await page.getByLabel('Load Template').selectOption('Synthetic baseline');
  await page.getByRole('button', { name: 'Load', exact: true }).click();

  const policy = page.getByText('Synthetic allow', { exact: true });
  await expect(policy).toBeVisible();
  await policy.click();
  await expect(page.getByLabel('Policy Name')).toHaveValue('Synthetic allow');

  await page.getByRole('button', { name: 'Generate All Policies' }).click();
  await expect(page.locator('#output1')).toContainText('config firewall policy');

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('confgen-generated.png'),
    animations: 'disabled',
    maskColor: '#181518',
    mask: [page.locator('#policy-form'), page.locator('.output-section')],
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});
