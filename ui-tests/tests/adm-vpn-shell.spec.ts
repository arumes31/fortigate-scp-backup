import AxeBuilder from '@axe-core/playwright';

import { expect, test } from './quality-fixture';

async function expectAccessible(page: import('@playwright/test').Page, state: string) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(results.violations.map(violation => ({
    rule: violation.id,
    nodes: violation.nodes.map(node => ({ target: node.target.join(' '), summary: node.failureSummary })),
  })), `${state} axe violations`).toEqual([]);
}

test('ADM VPN uses the shared shell and keyboard-safe add, edit, and removal flows', async ({ page }, testInfo) => {
  await page.goto('/fgt-adm-vpn-conf/', { waitUntil: 'networkidle' });

  await expect(page.locator('.app-rail')).toBeVisible();
  await expect(page.locator('.app-rail [aria-current="page"]')).toHaveText(/ADM VPN Config/);
  await expect(page.getByRole('heading', { level: 1, name: 'FGT ADM VPN Config' })).toBeVisible();

  const addPanel = page.locator('details', { hasText: 'Add new entry' });
  await expect(addPanel).not.toHaveAttribute('open', '');
  await addPanel.getByText('Add new entry', { exact: true }).click();
  await expect(addPanel).toHaveAttribute('open', '');
  await expect(addPanel.getByLabel('Firewall name')).toBeVisible();
  await expect(addPanel.getByLabel('Customer name')).toBeVisible();
  await expectAccessible(page, 'add form');
  await expect(page.locator('#removeConfirmBtn')).toBeDisabled();

  const editOpener = page.getByRole('button', { name: 'Edit edge.example.test' });
  await editOpener.click();
  const editDialog = page.getByRole('dialog', { name: 'Edit configuration' });
  await expect(editDialog).toBeVisible();
  await expect(editDialog.getByLabel('Firewall name')).toHaveValue('edge.example.test');
  await expectAccessible(page, 'edit dialog');
  await page.keyboard.press('Escape');
  await expect(editDialog).toBeHidden();
  await expect(editOpener).toBeFocused();

  const removeOpener = page.getByRole('button', { name: 'Remove edge.example.test' });
  await removeOpener.click();
  const removeDialog = page.getByRole('dialog', { name: 'Remove configuration' });
  await expect(removeDialog).toBeVisible();
  await expect(removeDialog.locator('#removalCommands')).toContainText('config vpn ipsec phase1-interface');
  const confirmation = removeDialog.getByLabel('Type edge.example.test to confirm');
  await confirmation.fill('edge.example.test');
  await expect(removeDialog.getByRole('button', { name: 'Remove entry' })).toBeEnabled();
  await expectAccessible(page, 'removal dialog');
  const screenshot = await page.screenshot({
    path: testInfo.outputPath('adm-vpn-removal-dialog.png'),
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
  await page.keyboard.press('Escape');
  await expect(removeDialog).toBeHidden();
  await expect(removeOpener).toBeFocused();
});
