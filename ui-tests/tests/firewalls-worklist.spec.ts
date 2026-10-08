import { expect, test } from './quality-fixture';

test('firewall worklist filters and keeps destructive actions secondary', async ({ page }) => {
  await page.goto('/', { waitUntil: 'networkidle' });

  const filter = page.getByRole('searchbox', { name: 'Filter firewalls' });
  await expect(filter).toBeVisible();
  const toolbar = page.locator('.firewall-filter-toolbar');
  await expect(toolbar).toHaveCSS('flex-wrap', 'nowrap');

  const rows = page.locator('#fwTable tbody tr[data-fw]');
  await expect(rows).toHaveCount(3);
  await filter.fill('industrial-campus');
  await expect(rows.filter({ visible: true })).toHaveCount(1);
  const longRow = page.locator('tr[data-fw="23"]');
  await expect(longRow).toBeVisible();
  await expect(longRow.locator('.fw-fqdn')).toHaveCSS('white-space', 'nowrap');
  await expect(longRow).toContainText('In Progress');

  await filter.fill('branch.example.test');
  const row = page.locator('tr[data-fw="12"]');
  await expect(row.getByRole('button', { name: 'Backup Now' })).toBeVisible();
  await expect(row.getByRole('button', { name: 'Test' })).toBeVisible();
  await expect(row.getByRole('button', { name: 'Delete' })).toHaveCount(0);

  await row.getByText('More', { exact: true }).click();
  await row.getByRole('button', { name: 'Delete' }).click();
  const dialog = page.getByRole('dialog', { name: 'Delete branch.example.test' });
  await expect(dialog).toBeVisible();
  const confirm = dialog.getByRole('button', { name: 'Delete firewall' });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel('Type branch.example.test to confirm').fill('branch.example.test');
  await expect(confirm).toBeEnabled();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(row.getByRole('button', { name: 'Delete' })).toBeFocused();

  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
});
