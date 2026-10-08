import { expect, test } from './quality-fixture';

test('backup failures expose diagnosis context and safe retry', async ({ page }) => {
  await page.goto('/errors');

  const failure = page.getByRole('article', { name: /branch\.example\.test/i });
  await expect(failure).toContainText('synthetic connection timeout while reading configuration after the SSH handshake');
  await expect(failure).toContainText('Last attempt');
  await expect(failure).toContainText('Last success');
  await expect(failure).toContainText('Next scheduled');
  await expect(failure.getByRole('link', { name: 'Firewall' })).toHaveAttribute('href', '/#firewall-12');
  await expect(failure.getByRole('link', { name: 'Backups' })).toHaveAttribute('href', '/backups/12');

  const retry = failure.getByRole('button', { name: 'Retry now' });
  await expect(retry).toBeVisible();
  await Promise.all([
    page.waitForURL(/\/errors\?retry=queued/),
    retry.click(),
  ]);
  await expect(page.getByRole('status')).toContainText('Backup retry queued');
});

test('backup errors has a distinct all-healthy state', async ({ page }) => {
  await page.goto('/errors?scenario=empty');
  await expect(page.getByText('Everything is healthy')).toBeVisible();
  await expect(page.getByText('Could not load backup failures')).toHaveCount(0);
});

test('backup errors has a distinct database failure state', async ({ page }) => {
  await page.goto('/errors?scenario=error');
  await expect(page.getByText('Could not load backup failures')).toBeVisible();
  await expect(page.getByText('Everything is healthy')).toHaveCount(0);
});
