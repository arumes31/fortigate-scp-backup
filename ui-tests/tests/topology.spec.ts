import AxeBuilder from '@axe-core/playwright';

import { expect, test } from './quality-fixture';

test.setTimeout(60_000);

test('topology keeps the graph primary and makes share, debug, maximize, and faceplate flows keyboard safe', async ({ page }, testInfo) => {
  let shares: Array<{ token: string; fw_id: number; created_at: string; expires_at: string; include_devices: boolean }> = [];
  await page.route('**/topology/**', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === '/topology/shares') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(shares) });
      return;
    }
    if (url.pathname === '/topology/share' && request.method() === 'POST') {
      const share = {
        token: '0123456789abcdef0123456789abcdef0123456789abcdef',
        fw_id: 7,
        created_at: '2026-09-02 10:30:00',
        expires_at: '2026-09-09 10:30:00',
        include_devices: false,
      };
      shares = [share];
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(share) });
      return;
    }
    if (url.pathname === '/topology/share/revoke' && request.method() === 'POST') {
      shares = [];
      await route.fulfill({ status: 204 });
      return;
    }
    await route.continue();
  });

  await page.goto('/topology', { waitUntil: 'networkidle' });
  await expect(page.getByRole('heading', { name: 'Explore topology' })).toBeVisible();
  await expect(page.getByRole('group', { name: 'View' })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Data' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Legend' })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Interactive network topology graph' })).toBeVisible();

  const deviceFilter = page.getByLabel('Devices', { exact: true }).first();
  await deviceFilter.uncheck();
  await expect(deviceFilter).not.toBeChecked();
  await deviceFilter.check();

  const firewallSelect = page.getByRole('combobox', { name: 'Firewall:' });
  await firewallSelect.fill('branch');
  await page.getByRole('option', { name: 'branch.example.test' }).click();
  await expect(page.locator('#topoMeta')).toContainText('FortiGate-VM');

  const graph = page.locator('#topoSvg');
  const graphRoot = graph.locator(':scope > g').first();
  const initialTransform = await graphRoot.getAttribute('transform');
  await graph.hover();
  await page.mouse.wheel(0, -420);
  await expect.poll(() => graphRoot.getAttribute('transform')).not.toBe(initialTransform);
  const zoomedTransform = await graphRoot.getAttribute('transform');
  await page.getByRole('button', { name: /Reset view/ }).click();
  await expect.poll(() => graphRoot.getAttribute('transform')).not.toBe(zoomedTransform);

  const maximize = page.getByRole('button', { name: 'Maximize' });
  await maximize.click();
  await expect(page.locator('body')).toHaveClass(/topo-max/);
  await expect(page.getByRole('button', { name: 'Exit' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('body')).not.toHaveClass(/topo-max/);
  await expect(maximize).toBeFocused();

  const shareOpener = page.getByRole('button', { name: 'Share', exact: true });
  const shareDialog = page.getByRole('dialog', { name: 'Share topology' });
  await shareOpener.click();
  await expect(shareDialog).toBeVisible();
  await expect(shareDialog.getByLabel('Link expires after')).toBeFocused();
  await shareDialog.getByRole('button', { name: 'Create link' }).click();
  await expect(shareDialog.getByLabel('New public link')).toHaveValue(/\/topology\/shared\/0123456789abcdef/);
  await expect(shareDialog.getByRole('button', { name: /0123456789ab/ })).toBeVisible();
  await shareDialog.getByRole('button', { name: 'Revoke' }).click();
  await expect(shareDialog).toContainText('No active links for this firewall.');
  await page.keyboard.press('Escape');
  await expect(shareDialog).toBeHidden();
  await expect(shareOpener).toBeFocused();

  const debugOpener = page.getByRole('button', { name: 'Debug', exact: true });
  const debugDialog = page.getByRole('dialog', { name: /Debug/ });
  await debugOpener.click();
  await expect(debugDialog).toBeVisible();
  await expect(debugDialog.getByRole('button', { name: 'Close' })).toBeFocused();
  const debugEntry = debugDialog.locator('[data-debug-entry]').first();
  await expect(debugEntry).toBeVisible();
  await debugEntry.click();
  await expect(debugEntry).toHaveAttribute('aria-expanded', 'true');
  await page.keyboard.press('Escape');
  await expect(debugDialog).toBeHidden();
  await expect(debugOpener).toBeFocused();

  const firewallNode = page.getByRole('button', { name: 'edge.example.test', exact: true });
  await firewallNode.focus();
  await page.keyboard.press('Enter');
  const faceplate = page.locator('#facePanel');
  await expect(faceplate).toHaveAttribute('aria-hidden', 'false');
  await expect(page.getByRole('button', { name: 'Close faceplate' })).toBeFocused();
  const widen = page.getByRole('button', { name: 'Widen or restore faceplate' });
  await widen.click();
  await expect(widen).toHaveAttribute('aria-pressed', 'true');
  await page.keyboard.press('Escape');
  await expect(faceplate).toHaveAttribute('aria-hidden', 'true');
  await expect(firewallNode).toBeFocused();

  const axe = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(axe.violations).toEqual([]);

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('topology-workspace.png'),
    fullPage: true,
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
});
