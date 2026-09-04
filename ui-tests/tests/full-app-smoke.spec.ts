import { expect, test } from '@playwright/test';

const stagingBaseURL = process.env.FORTISAFE_STAGING_BASE_URL;
const stagingUsername = process.env.FORTISAFE_STAGING_USERNAME;
const stagingPassword = process.env.FORTISAFE_STAGING_PASSWORD;

test('staged image serves login, health, and every enabled extension', async ({ page, request }) => {
  test.skip(!stagingBaseURL || !stagingUsername || !stagingPassword, 'staging credentials are required');

  const health = await request.get(`${stagingBaseURL}/healthz`);
  expect(health.status()).toBe(200);
  expect((await health.json()).status).toBe('ok');
  const readiness = await request.get(`${stagingBaseURL}/readyz`);
  expect(readiness.status()).toBe(200);
  expect(await readiness.text()).toBe('ready');

  await page.goto('/login', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: 'Login' })).toBeVisible();
  await page.getByLabel('Username').fill(stagingUsername!);
  await page.getByLabel('Password', { exact: true }).fill(stagingPassword!);
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForURL(/\/(dashboard|change_password)$/);
  if (new URL(page.url()).pathname === '/change_password') {
    const rotatedPassword = 'FortiSafe-Staging-Rotated-2026';
    await page.getByLabel('Current password', { exact: true }).fill(stagingPassword!);
    await page.getByLabel('New password', { exact: true }).fill(rotatedPassword);
    await page.getByLabel('Confirm new password', { exact: true }).fill(rotatedPassword);
    await page.getByRole('button', { name: 'Update password' }).click();
    await expect(page.locator('.alert-success')).toContainText('Password updated successfully');
    await page.goto('/dashboard', { waitUntil: 'domcontentloaded' });
  }
  await expect(page).toHaveURL(/\/dashboard$/);

  const routes = [
    { path: '/dashboard', heading: 'Dashboard' },
    { path: '/fgt-adm-vpn-conf/', heading: 'FGT ADM VPN Config' },
    { path: '/fgt-confgen/', heading: 'FortiGate Policy Generator' },
    { path: '/fgt-polsplit/', heading: 'FortiGate Policy Split Advisor' },
    { path: '/fgt-confconv/', heading: 'Configuration Conversions' },
    { path: '/fgt-conftail/', heading: 'Configuration Change Tail' },
  ];
  for (const route of routes) {
    await test.step(route.path, async () => {
      const response = await page.goto(route.path, { waitUntil: 'domcontentloaded' });
      expect(response?.status()).toBe(200);
      await expect(page.getByRole('heading', { level: 1, name: route.heading })).toBeVisible();
      await expect(page.locator('.app-rail [aria-current="page"]')).toHaveCount(1);
    });
  }
});
