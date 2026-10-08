import { expect, test } from './quality-fixture';

test('activity filters run on the server and survive pagination', async ({ page }) => {
  await page.goto('/activity_log', { waitUntil: 'networkidle' });

  await page.getByLabel('Search').fill('deep-synthetic-match');
  await page.getByLabel('User').fill('automation');
  await page.getByLabel('Action').fill('Configuration');
  await page.locator('input[name="from"]').fill('2026-09-01');
  await page.locator('input[name="to"]').fill('2026-09-02');
  await page.getByRole('button', { name: 'Apply filters' }).click();

  await expect(page.getByText('Synthetic match originally beyond the first 100 rows')).toBeVisible();
  await expect(page.getByText('101 matching')).toBeVisible();
  await expect(page.getByText('Page 1 of 2')).toBeVisible();
  await expect(page).toHaveURL(/q=deep-synthetic-match/);
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);

  await page.getByRole('link', { name: 'Next ›' }).click();
  const current = new URL(page.url());
  expect(current.searchParams.get('q')).toBe('deep-synthetic-match');
  expect(current.searchParams.get('user')).toBe('automation');
  expect(current.searchParams.get('action')).toBe('Configuration');
  expect(current.searchParams.get('from')).toBe('2026-09-01');
  expect(current.searchParams.get('to')).toBe('2026-09-02');
  expect(current.searchParams.get('page')).toBe('2');

  await page.getByLabel('Search').fill('no-match');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByText('No activity matches these filters.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Clear' })).toBeVisible();
});
