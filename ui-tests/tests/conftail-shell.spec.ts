import { expect, test } from './quality-fixture';

test('ConfTail index and session use isolated shared-shell pages', async ({ page }, testInfo) => {
  await page.goto('/fgt-conftail/', { waitUntil: 'networkidle' });

  await expect(page.locator('.app-rail')).toBeVisible();
  await expect(page.locator('.app-rail [aria-current="page"]')).toHaveText(/Configuration Tail/);
  await expect(page.getByRole('heading', { level: 1, name: 'Configuration Change Tail' })).toBeVisible();
  await expect(page.locator('.conftail-page')).toBeVisible();

  const coverage = page.locator('details.ct-coverage');
  await expect(coverage).toBeVisible();
  await expect(coverage).not.toHaveAttribute('open', '');
  await expect(coverage.getByText('0 Graylog-enabled firewall(s)')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Clear pending queue' })).toBeDisabled();

  const indexScreenshot = await page.screenshot({
    path: testInfo.outputPath('conftail-index.png'),
    animations: 'disabled',
  });
  expect(indexScreenshot.byteLength).toBeGreaterThan(10_000);

  await page.goto('/fgt-conftail/?scenario=warning', { waitUntil: 'networkidle' });
  const clearQueue = page.getByRole('button', { name: 'Clear pending queue' });
  await expect(clearQueue).toBeEnabled();
  await expect(page.getByText('3 queued delivery(s)')).toBeVisible();
  page.once('dialog', confirmation => confirmation.dismiss());
  await clearQueue.click();
  await expect(page).toHaveURL(/\/fgt-conftail\/\?scenario=warning$/);

  await page.goto('/fgt-conftail/chain/fixture-chain', { waitUntil: 'networkidle' });

  await expect(page.locator('.app-rail')).toBeVisible();
  await expect(page.locator('.app-rail [aria-current="page"]')).toHaveText(/Configuration Tail/);
  await expect(page.getByRole('heading', { level: 1, name: 'Complete Redacted Timeline' })).toBeVisible();
  await expect(page.getByRole('link', { name: /Back to configuration change sessions/ })).toBeVisible();
  await expect(page.locator('.ct-session-facts').getByText('#7 edge.example.test')).toBeVisible();
  await expect(page.locator('.topbar, .sysfooter')).toHaveCount(0);

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('conftail-session.png'),
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});
