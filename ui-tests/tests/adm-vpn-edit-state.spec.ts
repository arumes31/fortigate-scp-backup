import { expect, test } from './quality-fixture';

const restoreKey = 'fortisafe.adm-vpn.after-edit.v1';

test('ADM VPN saving retains search, selected firewall, and scroll position', async ({ page }) => {
  // Keep the long synthetic fleet available after the normal save redirect.
  await page.route('**/fgt-adm-vpn-conf/', async route => {
    const response = await route.fetch({ url: route.request().url() + '?scenario=loading' });
    await route.fulfill({ response });
  });
  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });
  const search = page.getByLabel('Search VPN entries');
  await search.fill('bulk');
  await page.getByLabel('Column preset').selectOption('diagnostic');
  const row = page.locator('[data-vpn-row="75"]');
  await row.getByRole('button', { name: 'Details for bulk-075.example.test' }).click();
  const detail = page.locator('#vpn-detail-75');
  await detail.getByRole('button', { name: 'Edit bulk-075.example.test' }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit configuration' });
  await expect(dialog.locator('form')).toBeVisible();
  const before = await page.evaluate(() => ({
    y: window.scrollY,
    table: document.querySelector('.adm-fleet-table-wrap')!.scrollTop,
  }));
  expect(before.table).toBeGreaterThan(0);
  const submission = page.waitForRequest(request => request.method() === 'POST' && request.url().endsWith('/edit/75'));
  await Promise.all([
    page.waitForEvent('framenavigated', frame => frame === page.mainFrame()),
    dialog.getByRole('button', { name: 'Update Entry' }).click(),
  ]);
  await submission;
  await expect(search).toHaveValue('bulk');
  await expect(page.locator('[data-vpn-row="7"]')).toBeHidden();
  await expect(row).toHaveAttribute('aria-selected', 'true');
  await expect(detail).toBeVisible();
  await expect(page.getByLabel('Column preset')).toHaveValue('diagnostic');
  await expect.poll(() => page.evaluate(() => document.querySelector('.adm-fleet-table-wrap')!.scrollTop)).toBeCloseTo(before.table, 0);
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeCloseTo(before.y, 0);
  expect(new URL(page.url()).search).toBe('');
  expect(await page.evaluate(key => sessionStorage.getItem(key), restoreKey)).toBeNull();

  // The saved view is a one-time handoff, not a persistent search preference.
  await page.reload({ waitUntil: 'networkidle' });
  await expect(search).toHaveValue('');
});

test('ADM VPN retains the filter when the saved firewall no longer matches', async ({ page }) => {
  let saved = false;
  await page.route('**/fgt-adm-vpn-conf/edit/7', async route => {
    if (route.request().method() === 'POST') saved = true;
    await route.continue();
  });
  await page.route('**/fgt-adm-vpn-conf/', async route => {
    const response = await route.fetch();
    const body = await response.text();
    await route.fulfill({ response, body: saved ? body.replaceAll('edge.example.test', 'renamed.example.test') : body });
  });
  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });
  const search = page.getByLabel('Search VPN entries');
  await search.fill('edge.example.test');
  await page.getByRole('button', { name: 'Details for edge.example.test' }).click();
  await page.locator('#vpn-detail-7').getByRole('button', { name: 'Edit edge.example.test' }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit configuration' });
  await dialog.getByLabel('Firewall name').fill('renamed.example.test');
  await Promise.all([
    page.waitForEvent('framenavigated', frame => frame === page.mainFrame()),
    dialog.getByRole('button', { name: 'Update Entry' }).click(),
  ]);
  await expect(search).toHaveValue('edge.example.test');
  await expect(page.locator('#vpnSearchCount')).toHaveText('0 / 2');
  await expect(page.locator('#vpn-detail-7')).toBeHidden();
  await expect(page.locator('#vpnDetailEmpty')).toBeVisible();
  await expect(search).toBeFocused();
});

test('ADM VPN failed edits keep the current view and do not store form values', async ({ page }) => {
  await page.route('**/fgt-adm-vpn-conf/edit/7', async route => {
    if (route.request().method() !== 'POST') return route.continue();
    await route.fulfill({ status: 400, headers: { 'X-FortiSafe-Test-Expected-Error': '1' }, body: 'Synthetic validation failure' });
  });
  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });
  await page.getByLabel('Search VPN entries').fill('edge');
  await page.getByRole('button', { name: 'Details for edge.example.test' }).click();
  await page.locator('#vpn-detail-7').getByRole('button', { name: 'Edit edge.example.test' }).click();
  const dialog = page.getByRole('dialog', { name: 'Edit configuration' });
  await dialog.getByLabel('IPsec PSK RO').fill('synthetic-unsaved-secret');
  await dialog.getByRole('button', { name: 'Update Entry' }).click();
  await expect(page.locator('#editFeedback')).toContainText('Synthetic validation failure');
  await expect(dialog).toBeVisible();
  await expect(page.getByLabel('Search VPN entries')).toHaveValue('edge');
  expect(await page.evaluate(key => sessionStorage.getItem(key), restoreKey)).toBeNull();
  expect(await page.evaluate(() => JSON.stringify({ ...sessionStorage, ...localStorage }))).not.toContain('synthetic-unsaved-secret');
});
