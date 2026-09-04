import { expect, test } from './quality-fixture';

test('backups expose identity, checksum copy, and exactly-two comparison selection', async ({ page }) => {
  await page.goto('/backups/7', { waitUntil: 'networkidle' });

  await expect(page.getByRole('heading', { level: 1 })).toContainText('edge.example.test #7');
  await expect(page.getByText('a'.repeat(64), { exact: true })).toBeVisible();
  await expect(page.getByText('Not recorded', { exact: true })).toBeVisible();
  await expect(page.getByText('edge-with-a-very-long-synthetic-backup-filename_20260831_103000.conf', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Copy' }).first().click();
  await expect(page.getByText('Checksum copied', { exact: true })).toBeVisible();

  const compare = page.getByRole('button', { name: 'Compare selected' });
  const first = page.getByRole('checkbox', { name: 'Compare backup 1' });
  const second = page.getByRole('checkbox', { name: 'Compare backup 2' });
  const third = page.getByRole('checkbox', { name: 'Compare backup 3' });
  await expect(compare).toBeDisabled();
  await first.check();
  await expect(compare).toBeDisabled();
  await second.check();
  await expect(compare).toBeEnabled();
  await expect(third).toBeDisabled();
  await first.uncheck();
  await expect(compare).toBeDisabled();
  await expect(third).toBeEnabled();
  await expect(page.getByText('1 of 2 selected', { exact: true })).toBeVisible();

  const dimensions = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
});

test('empty backup history keeps the firewall context', async ({ page }) => {
  await page.goto('/backups/7?scenario=empty', { waitUntil: 'networkidle' });
  await expect(page.getByRole('heading', { level: 1 })).toContainText('edge.example.test #7');
  await expect(page.getByText('No backups recorded for this firewall yet.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Compare selected' })).toHaveCount(0);
});
