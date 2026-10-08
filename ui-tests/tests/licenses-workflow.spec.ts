import { expect, test } from './quality-fixture';

test('license presets combine with child-aware search and expose hierarchy', async ({ page }, testInfo) => {
  await page.goto('/licenses?scenario=full', { waitUntil: 'networkidle' });
  await expect(page.locator('#licProgress')).toContainText('Last successful refresh');
  await expect(page.locator('#licSearchCount')).toHaveText('3 of 3 devices');

  const expired = page.getByRole('button', { name: 'Expired' });
  await expired.click();
  await page.getByLabel('Search licenses').fill('CHILD-EXPIRED-001');
  await expect(page.locator('#licSearchCount')).toHaveText('1 of 3 devices');
  await expect(page.locator('tr[data-fw]:visible')).toHaveCount(1);
  await expect(page.locator('tr[data-fw]:visible')).toHaveAttribute('data-fw', '12');

  await page.getByRole('button', { name: 'Expiring' }).click();
  await expect(page.locator('#licSearchCount')).toHaveText('0 of 3 devices');
  await page.getByRole('button', { name: 'All', exact: true }).click();

  const details = page.locator('tr[data-fw="12"]').getByRole('button', { name: 'Details' });
  await expect(details).toHaveAttribute('aria-expanded', 'false');
  await details.focus();
  await page.keyboard.press('Enter');
  await expect(details).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('#license-detail-12')).toBeVisible();
  await expect.poll(() => page.locator('#licTable').evaluate(table => table.parentElement?.scrollLeft)).toBe(0);
  await page.screenshot({ path: testInfo.outputPath('licenses-inventory.png'), fullPage: true, animations: 'disabled' });
});

test('license refresh states and empty action stay explicit', async ({ page }) => {
  await page.goto('/licenses?scenario=loading', { waitUntil: 'networkidle' });
  await expect(page.locator('#licProgress')).toContainText('Refreshing 1 of 3');

  await page.goto('/licenses?scenario=error', { waitUntil: 'networkidle' });
  await expect(page.locator('#licProgress')).toContainText('Refresh status unavailable');

  await page.goto('/licenses?scenario=empty', { waitUntil: 'networkidle' });
  await expect(page.getByText('No firewalls configured.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Refresh All' })).toBeVisible();
});
