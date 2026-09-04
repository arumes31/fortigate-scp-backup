import { expect, test } from './quality-fixture';

test('ADM VPN bulk actions select only visible rows and report partial failures', async ({ page }) => {
  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });
  const exportButton = page.getByRole('button', { name: 'Export selected CSV' });
  const generateButton = page.getByRole('button', { name: 'Generate selected' });
  const count = page.locator('#vpnSelectionCount');
  const feedback = page.locator('#vpnBulkFeedback');

  await expect(exportButton).toBeDisabled();
  await expect(generateButton).toBeDisabled();
  await expect(page.locator('[formaction*="delete"]')).toHaveCount(0);

  await page.getByLabel('Search VPN entries').fill('Synthetic customer');
  await page.getByRole('button', { name: 'Select visible' }).click();
  await expect(count).toHaveText('1 selected');
  await expect(page.getByLabel('Select edge.example.test')).toBeChecked();
  await expect(page.getByLabel(/Select branch-with-an-intentionally/)).not.toBeChecked();
  await page.getByLabel('Search VPN entries').fill('');

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

test('ADM VPN bulk selection enforces the 100-entry client limit', async ({ page }) => {
  await page.goto('/fgt-adm-vpn-conf/?scenario=loading', { waitUntil: 'networkidle' });
  const feedback = page.locator('#vpnBulkFeedback');
  await page.getByRole('button', { name: 'Select visible' }).click();
  await expect(page.locator('#vpnSelectionCount')).toHaveText('100 selected');
  await expect(page.locator('[data-vpn-checkbox]:checked')).toHaveCount(100);
  await expect(feedback).toContainText('1 exceed the limit');

  let bulkRequests = 0;
  page.on('request', request => {
    if (request.url().includes('/bulk/')) bulkRequests += 1;
  });
  await page.locator('[data-vpn-checkbox]:not(:checked)').evaluate((checkbox: HTMLInputElement) => {
    checkbox.checked = true;
  });
  await page.locator('#admBulkForm').evaluate((form: HTMLFormElement) => {
    form.requestSubmit(form.querySelector('[data-bulk-action="generate"]') as HTMLButtonElement);
  });
  await expect(feedback).toHaveText('A maximum of 100 entries can be processed at once.');
  await page.waitForTimeout(100);
  expect(bulkRequests).toBe(0);
});
