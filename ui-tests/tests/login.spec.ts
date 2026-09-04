import { expect, test } from './quality-fixture';

test('login form supports keyboard use without disclosing the account type', async ({ page }) => {
  await page.goto('/login', { waitUntil: 'networkidle' });

  const username = page.getByLabel('Username');
  const password = page.getByLabel('Password', { exact: true });
  const totp = page.getByLabel('TOTP Code');
  const reveal = page.locator('[data-password-toggle="password"]');

  await expect(username).toHaveAttribute('required', '');
  await expect(password).toHaveAttribute('required', '');
  await expect(totp).toBeVisible();
  await expect(totp).toHaveAttribute('pattern', '[0-9]{6}');

  await username.fill('admin');
  await expect(totp).toBeVisible();
  await expect(page.getByText('RADIUS / MFA:')).toBeVisible();
  await username.fill('radius-user');
  await expect(totp).toBeVisible();
  await expect(page.getByText('RADIUS / MFA:')).toBeVisible();

  await password.fill('do-not-change-this-value');
  await reveal.focus();
  await page.keyboard.press('Enter');
  await expect(password).toHaveAttribute('type', 'text');
  await expect(password).toHaveValue('do-not-change-this-value');
  await expect(reveal).toHaveAttribute('aria-pressed', 'true');
  await expect(reveal).toHaveAccessibleName('Hide password');

  await page.keyboard.press('Space');
  await expect(password).toHaveAttribute('type', 'password');
  await expect(password).toHaveValue('do-not-change-this-value');
  await expect(reveal).toHaveAccessibleName('Show password');
});

test('login waiting state is announced without changing submitted values', async ({ page }) => {
  await page.goto('/login', { waitUntil: 'networkidle' });
  await page.getByLabel('Username').fill('operator');
  await page.getByLabel('Password', { exact: true }).fill('secret-value');

  await page.locator('#login-form').evaluate((form) => {
    form.addEventListener('submit', (event) => event.preventDefault(), { once: true });
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });

  const status = page.getByRole('status');
  await expect(status).toBeVisible();
  await expect(status).toContainText('Signing in');
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('secret-value');
  await expect(page.getByRole('button', { name: 'Signing in…' })).toBeDisabled();
});
