import { expect, test } from './quality-fixture';

const pageRoutes = [
  { name: 'login', path: '/login', heading: 'Login' },
  { name: 'firewalls', path: '/', heading: 'Firewalls' },
  { name: 'dashboard', path: '/dashboard', heading: 'Dashboard' },
  { name: 'search', path: '/search', heading: 'Search Configurations' },
  { name: 'audit', path: '/audit', heading: 'Audit & Compliance Insights' },
  { name: 'licenses', path: '/licenses', heading: 'License Inventory' },
  { name: 'IPAM', path: '/ipam', heading: 'Fleet IPAM' },
  { name: 'topology', path: '/topology', heading: 'Network topology' },
  { name: 'activity', path: '/activity_log', heading: 'Activity Log' },
  { name: 'ADM VPN', path: '/fgt-adm-vpn-conf/', heading: 'FGT ADM VPN Config' },
  { name: 'Policy Generator', path: '/fgt-confgen/', heading: 'FortiGate Policy Generator' },
  { name: 'Policy Split', path: '/fgt-polsplit/', heading: 'FortiGate Policy Split Advisor' },
  { name: 'Config Converter', path: '/fgt-confconv/', heading: 'Configuration Conversions' },
  { name: 'ConfTail', path: '/fgt-conftail/', heading: 'Configuration Change Tail' },
];

test('all primary pages render through the deterministic fixture', async ({ page }) => {
  for (const route of pageRoutes) {
    await test.step(route.name, async () => {
      const response = await page.goto(route.path, { waitUntil: 'networkidle' });
      expect(response?.status()).toBe(200);
      await expect(page.getByRole('heading', { level: 1, name: route.heading })).toBeVisible();
    });
  }
});

test('dashboard fits the desktop viewport and produces review evidence', async ({ page }, testInfo) => {
  await page.goto('/dashboard?scenario=warning', { waitUntil: 'networkidle' });
  await expect(page.locator('body')).not.toContainText(/NaN|undefined/i);
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('dashboard-warning.png'),
    fullPage: true,
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});

test('ConfTail loading state is deterministic', async ({ page }) => {
  await page.goto('/fgt-conftail/?scenario=loading', { waitUntil: 'networkidle' });
  await expect(page.locator('[data-ct-poll-status]')).toHaveAttribute('data-poll-running', 'true');
  await expect(page.locator('[data-next-poll]')).toHaveAttribute('data-next-poll', '2026-09-02T10:31:00Z');
});
