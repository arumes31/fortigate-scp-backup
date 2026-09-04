import { expect, test } from './quality-fixture';

for (const scenario of ['full', 'empty', 'warning', 'error', 'loading']) {
  test(`dashboard ${scenario} state is explicit and stable`, async ({ page }) => {
    await page.goto(`/dashboard?scenario=${scenario}`, { waitUntil: 'networkidle' });

    const groups = page.locator('.metric-group');
    await expect(groups).toHaveCount(3);
    await expect(groups.nth(0).getByRole('heading', { name: 'Health' })).toBeVisible();
    await expect(groups.nth(1).getByRole('heading', { name: 'Operations' })).toBeVisible();
    await expect(groups.nth(2).getByRole('heading', { name: 'Storage' })).toBeVisible();

    const diagnostics = page.locator('details.diagnostic-console');
    await expect(diagnostics).not.toHaveAttribute('open', '');
    await expect(page.locator('details.issue-details')).not.toHaveAttribute('open', '');

    if (scenario === 'warning') {
      const rows = page.locator('.attention-item');
      await expect(rows).toHaveCount(1);
      for (const text of ['Backup', 'Critical', '8h', 'Retry or inspect', 'branch.example.test']) {
        await expect(rows.first()).toContainText(text);
      }
    }
    if (scenario === 'error') {
      await expect(page.getByRole('alert').filter({ hasText: 'Issue data could not be loaded' })).toBeVisible();
      await expect(page.locator('#dashboardRefreshStatus')).toContainText(/incomplete|failed/i);
    }
    if (scenario === 'loading') {
      await expect(page.locator('#runningCard')).toBeVisible();
      await expect(page.locator('#runningList')).toContainText('Downloading synthetic configuration');
      await expect(page.locator('#runningList .skeleton-row')).toHaveCount(0);
    }

    const dimensions = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      content: document.documentElement.scrollWidth,
    }));
    expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
  });
}
