import { expect, test } from './quality-fixture';

test('search is results-first, keyboard-safe, highlighted, and POST-only', async ({ page }, testInfo) => {
  await page.goto('/search?scenario=empty', { waitUntil: 'networkidle' });
  const help = page.locator('details.search-help');
  await expect(help).toHaveAttribute('open', '');

  const example = page.getByRole('button', { name: 'config system admin', exact: true });
  await example.focus();
  await page.keyboard.press('Enter');
  const query = page.getByRole('searchbox', { name: 'Search term' });
  await expect(query).toHaveValue('config system admin');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/search$/);
  await expect(page.locator('details.search-help')).not.toHaveAttribute('open', '');

  const results = page.locator('.search-results');
  const resultsBeforeTips = await page.evaluate(() => {
    const result = document.querySelector('.search-results');
    const tip = document.querySelector('details.search-help');
    return Boolean(result && tip && (result.compareDocumentPosition(tip) & Node.DOCUMENT_POSITION_FOLLOWING));
  });
  expect(resultsBeforeTips).toBe(true);
  await expect(results.locator('mark')).toHaveText('config system admin');
  await expect(results).toContainText('<sentinel-config>');
  await expect(results.locator('script')).toHaveCount(0);
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
  await page.screenshot({ path: testInfo.outputPath('search-results.png'), fullPage: true, animations: 'disabled' });
});

test('broad search truncation is explicit at the 1000-result cap', async ({ page }) => {
  await page.goto('/search?scenario=warning', { waitUntil: 'networkidle' });
  await expect(page.locator('.search-results tbody tr')).toHaveCount(1000);
  await expect(page.getByRole('status')).toContainText('showing the first 1000');
  await expect(page.locator('details.search-help')).not.toHaveAttribute('open', '');
});
