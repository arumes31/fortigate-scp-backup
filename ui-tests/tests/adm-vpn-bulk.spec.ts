import { expect, test } from './quality-fixture';

test('ADM VPN bulk actions select all rows and report partial failures', async ({ page }) => {
  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });
  const exportButton = page.getByRole('button', { name: 'Export selected CSV' });
  const generateButton = page.getByRole('button', { name: 'Generate selected' });
  const count = page.locator('#vpnSelectionCount');
  const feedback = page.locator('#vpnBulkFeedback');

  await expect(exportButton).toBeDisabled();
  await expect(generateButton).toBeDisabled();
  await expect(page.locator('[formaction*="delete"]')).toHaveCount(0);

  // Select all ignores the search filter.
  await page.getByLabel('Search VPN entries').fill('Synthetic customer');
  await page.getByRole('button', { name: 'Select all' }).click();
  await expect(count).toHaveText('2 selected');
  await expect(page.getByLabel('Select edge.example.test')).toBeChecked();
  await page.getByLabel('Search VPN entries').fill('');
  await expect(page.getByLabel(/Select branch-with-an-intentionally/)).toBeChecked();
  await page.getByLabel(/Select branch-with-an-intentionally/).uncheck();
  await expect(count).toHaveText('1 selected');

  const exportDownload = page.waitForEvent('download');
  await exportButton.click();
  expect((await exportDownload).suggestedFilename()).toBe('vpn_configs_1_selected.csv');
  await expect(feedback).toHaveText('1 succeeded, 0 failed.');

  await page.getByLabel(/Select branch-with-an-intentionally/).check();
  await expect(count).toHaveText('2 selected');
  const generateDownload = page.waitForEvent('download');
  await generateButton.click();
  expect((await generateDownload).suggestedFilename()).toBe('fgt_adm_configs_2_selected.zip');
  await expect(feedback).toContainText('1 succeeded, 1 failed. Failed IDs: 8.');
});

test('ADM VPN bulk selection has no 100-entry limit', async ({ page }) => {
  await page.goto('/fgt-adm-vpn-conf/?scenario=loading', { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Select all' }).click();
  await expect(page.locator('#vpnSelectionCount')).toHaveText('101 selected');
  await expect(page.locator('[data-vpn-checkbox]:not(:checked)')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Generate selected' })).toBeEnabled();
  await expect(page.locator('#vpnBulkFeedback')).toBeHidden();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export selected CSV' }).click();
  expect((await download).suggestedFilename()).toBe('vpn_configs_101_selected.csv');
});
