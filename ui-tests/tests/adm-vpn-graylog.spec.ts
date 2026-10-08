import { expect, test } from './quality-fixture';

test('ADM VPN reveals monitoring queries for offline cluster and single sources', async ({ page }) => {
  await page.goto('/fgt-adm-vpn-conf/?scenario=error', { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Details for edge.example.test' }).click();
  const detail = page.locator('#vpn-detail-7');
  await expect(detail.getByText('Graylog offline', { exact: true })).toBeVisible();
  const toggle = detail.getByRole('button', { name: /^(Show|Hide) Graylog query$/ });
  const query = page.locator('#graylog-query-7');
  await expect(query).toBeHidden();
  await toggle.focus();
  await page.keyboard.press('Enter');
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await expect(query.locator('code')).toHaveText(['source:"edge-a"', 'source:"edge-b"']);
  await expect(query).toContainText('Lookback (seconds): 300');
  await expect(query).toContainText('All must have logs to be online.');
  await detail.getByRole('button', { name: 'Hide Graylog query' }).click();
  await expect(query).toBeHidden();

  await page.getByRole('button', { name: 'Details for branch-with-an-intentionally-long-hostname.europe.example.test' }).click();
  const single = page.locator('#vpn-detail-8');
  await single.getByRole('button', { name: 'Show Graylog query' }).click();
  await expect(single.locator('code').filter({ hasText: 'source:' })).toHaveText('source:"branch-with-an-intentionally-long-hostname.europe.example.test"');
  expect(await single.locator('.adm-graylog-query').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
