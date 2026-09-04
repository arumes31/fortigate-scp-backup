import AxeBuilder from '@axe-core/playwright';

import { expect, test } from './quality-fixture';

const preferenceKey = 'fortisafe.adm-vpn.columns.v1';

async function expectAccessible(page: import('@playwright/test').Page, state: string) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(results.violations.map(violation => ({
    rule: violation.id,
    nodes: violation.nodes.map(node => ({ target: node.target.join(' '), summary: node.failureSummary })),
  })), `${state} axe violations`).toEqual([]);
}

test('ADM VPN fleet view keeps core facts visible and details keyboard-operable across presets', async ({ page }, testInfo) => {
  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });

  const root = page.locator('#adm-vpn-page');
  const table = page.locator('#vpnTable');
  const preset = page.getByLabel('Column preset');
  for (const column of ['identity', 'enabled', 'health', 'last-check', 'details']) {
    await expect(table.locator(`[data-column="${column}"]`).first()).toBeVisible();
  }
  await expect(root).toHaveAttribute('data-column-preset', 'standard');
  await expect(table.locator('[data-column="endpoint"]').first()).toBeVisible();
  await expect(table.locator('[data-column="evidence"]').first()).toBeHidden();

  await preset.selectOption('compact');
  await expect(root).toHaveAttribute('data-column-preset', 'compact');
  await expect(table.locator('[data-column="endpoint"]').first()).toBeHidden();
  await preset.selectOption('diagnostic');
  await expect(root).toHaveAttribute('data-column-preset', 'diagnostic');
  await expect(table.locator('[data-column="endpoint"]').first()).toBeVisible();
  await expect(table.locator('[data-column="evidence"]').first()).toBeVisible();
  const preferences = await page.evaluate(() => Object.fromEntries(
    Object.keys(localStorage).map(key => [key, localStorage.getItem(key)]),
  ));
  expect(preferences).toEqual({ [preferenceKey]: 'diagnostic' });

  const row = table.locator('[data-vpn-row="7"]');
  await row.focus();
  await row.press('Enter');
  const detail = page.locator('#vpn-detail-7');
  await expect(detail).toBeVisible();
  await expect(detail).toBeFocused();
  await expect(detail).toContainText('Configuration checks only');
  await expect(detail).toContainText('Graylog online');
  await expect(detail).toContainText('DNS verified');
  await expect(detail.getByRole('button', { name: 'Edit edge.example.test' })).toBeVisible();
  await expect(detail.getByRole('button', { name: 'Remove edge.example.test' })).toBeVisible();
  await expect(detail.getByRole('link', { name: 'Download configuration' })).toBeVisible();

  const longRow = table.locator('[data-vpn-row="8"]');
  await longRow.getByRole('button', { name: /Details for branch-with-an-intentionally-long-hostname/ }).click();
  await expect(page.locator('#vpn-detail-8')).toBeVisible();
  await expect(page.locator('#vpn-detail-8')).toContainText('DNS mismatch');
  await expect(page.locator('body')).not.toContainText('Tunnel online');
  await page.screenshot({ path: testInfo.outputPath('adm-vpn-fleet-detail.png'), animations: 'disabled' });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, 'fleet page has document-level horizontal overflow').toBeLessThanOrEqual(1);

  await page.reload({ waitUntil: 'networkidle' });
  await expect(root).toHaveAttribute('data-column-preset', 'diagnostic');
  await expect(preset).toHaveValue('diagnostic');
  await expectAccessible(page, 'ADM VPN fleet detail');
});

test('ADM VPN fleet view has clear empty and unhealthy factual states', async ({ page }) => {
  await page.goto('/fgt-adm-vpn-conf/?scenario=empty', { waitUntil: 'networkidle' });
  await expect(page.locator('#vpnTable')).toContainText('No entries yet.');
  await expect(page.locator('#vpnDetailEmpty')).toContainText('Select an entry');

  await page.goto('/fgt-adm-vpn-conf/?scenario=error', { waitUntil: 'networkidle' });
  const row = page.locator('[data-vpn-row="7"]');
  await expect(row).toContainText('Attention');
  await expect(row).toContainText('Graylog offline');
  await row.press(' ');
  const detail = page.locator('#vpn-detail-7');
  await expect(detail).toBeVisible();
  await expect(detail).toContainText('Graylog offline');
  await expect(detail).toContainText('DNS mismatch');
  await expectAccessible(page, 'ADM VPN unhealthy detail');
});
