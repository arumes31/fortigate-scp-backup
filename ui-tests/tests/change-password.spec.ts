import { expect, test } from './quality-fixture';

test('password guidance covers policy, match, reveal, and Caps Lock', async ({ page }) => {
  await page.goto('/change_password');

  const current = page.getByLabel('Current password', { exact: true });
  const next = page.getByLabel('New password', { exact: true });
  const confirm = page.getByLabel('Confirm new password');
  await expect(page.getByText('16–72 UTF-8 bytes')).toBeVisible();

  await current.fill('current-password-value');
  await next.fill('short');
  await expect(page.locator('[data-password-rule="length"]')).toHaveAttribute('data-valid', 'false');
  await expect(page.locator('#passwordByteCount')).toContainText('5 UTF-8 bytes');

  await next.fill('current-password-value');
  await expect(page.locator('[data-password-rule="different"]')).toHaveAttribute('data-valid', 'false');
  await confirm.fill('different-password-value');
  await expect(page.locator('[data-password-rule="match"]')).toHaveAttribute('data-valid', 'false');

  const reveal = page.locator('[data-password-toggle="new_password"]');
  await reveal.click();
  await expect(next).toHaveAttribute('type', 'text');
  await expect(reveal).toHaveAccessibleName('Hide new password');
  await reveal.click();
  await expect(next).toHaveAttribute('type', 'password');

  await next.focus();
  await next.evaluate(input => {
    const event = new KeyboardEvent('keydown', { key: 'A', bubbles: true });
    Object.defineProperty(event, 'getModifierState', { value: (key: string) => key === 'CapsLock' });
    input.dispatchEvent(event);
  });
  await expect(page.locator('#capsLockWarning')).toBeVisible();
});

test('password mismatch and store errors return blank fields', async ({ page }) => {
  await page.goto('/change_password');
  await page.getByLabel('Current password', { exact: true }).fill('current-password-value');
  await page.getByLabel('New password', { exact: true }).fill('new-password-value');
  await page.getByLabel('Confirm new password').fill('different-password-value');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByRole('alert')).toContainText('confirmation does not match');
  await expect(page.getByLabel('Current password', { exact: true })).toHaveValue('');
  await expect(page.getByLabel('New password', { exact: true })).toHaveValue('');

  await page.getByLabel('Current password', { exact: true }).fill('incorrect-current-password');
  await page.getByLabel('New password', { exact: true }).fill('new-password-value');
  await page.getByLabel('Confirm new password').fill('new-password-value');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByRole('alert')).toContainText('Current password is incorrect');
  await expect(page.getByLabel('Current password', { exact: true })).toHaveValue('');
});

test('successful password change uses PRG and announces completion', async ({ page }) => {
  await page.goto('/change_password');
  await page.getByLabel('Current password', { exact: true }).fill('current-password-value');
  await page.getByLabel('New password', { exact: true }).fill('new-password-value');
  await page.getByLabel('Confirm new password').fill('new-password-value');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page).toHaveURL(/\/change_password\?updated=1/);
  await expect(page.getByRole('status').filter({ hasText: 'Password updated successfully' })).toBeVisible();
  await expect(page.getByLabel('Current password', { exact: true })).toHaveValue('');
});
