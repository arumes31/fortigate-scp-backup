import { expect, test } from './quality-fixture';

const attributeMatch = 'type[fortimanager->fortimanager]fmg["manager.example.test"->"manager.example.test"]serial-number["FMGVMTEST00000001"->"FMGVMTEST00000001"]';

test('ConfTail creates and manages an exact global ignore rule', async ({ page }) => {
  await page.goto('/fgt-conftail/chain/fixture-chain', { waitUntil: 'networkidle' });

  const openButton = page.getByRole('button', { name: 'Ignore globally…' });
  await expect(openButton).toBeVisible();
  await openButton.click();

  const dialog = page.getByRole('dialog', { name: 'Confirm global ignore' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText(attributeMatch, { exact: true })).toBeVisible();
  await expect(dialog.getByText('Edit system.central-management', { exact: true })).toBeVisible();
  await expect(dialog.getByRole('radio', { name: /Exact attribute change/ })).toBeChecked();

  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(openButton).toBeFocused();

  await openButton.click();
  await dialog.getByRole('radio', { name: /Operation and path/ }).check();
  await dialog.getByRole('button', { name: 'Confirm global ignore' }).click();
  await expect(page).toHaveURL(/\/fgt-conftail\/\?ignore=created#ct-global-ignores$/);

  const management = page.locator('#ct-global-ignores');
  await management.locator('summary').click();
  await expect(management).toHaveAttribute('open', '');
  await expect(management.getByText('Edit system.central-management', { exact: true })).toBeVisible();
  await expect(management.getByText('enabled', { exact: true })).toBeVisible();

  await management.getByRole('button', { name: 'Disable' }).click();
  await expect(page).toHaveURL(/\/fgt-conftail\/\?ignore=updated#ct-global-ignores$/);

  await page.locator('#ct-global-ignores summary').click();
  page.once('dialog', confirmation => confirmation.accept());
  await page.locator('#ct-global-ignores').getByRole('button', { name: 'Delete' }).click();
  await expect(page).toHaveURL(/\/fgt-conftail\/\?ignore=deleted#ct-global-ignores$/);
});
