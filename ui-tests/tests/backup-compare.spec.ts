import { expect, test } from './quality-fixture';

test('two selected backup IDs open a bounded side-by-side comparison', async ({ page }) => {
  await page.goto('/backups/7', { waitUntil: 'networkidle' });
  await page.getByRole('checkbox', { name: 'Compare backup 1' }).check();
  await page.getByRole('checkbox', { name: 'Compare backup 2' }).check();
  await page.getByRole('button', { name: 'Compare selected' }).click();
  await expect(page).toHaveURL(/\/backups\/7\/compare\?backup=1&backup=2$/);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('edge.example.test #7');
  await expect(page.getByText('set value old', { exact: true })).toBeVisible();
  await expect(page.getByText('set value new', { exact: true })).toBeVisible();
});

test('truncated comparison is explicit', async ({ page }) => {
  await page.goto('/backups/7/compare?backup=1&backup=2&scenario=warning', { waitUntil: 'networkidle' });
  await expect(page.getByRole('status')).toContainText('Comparison is truncated');
});
