import { expect, test } from './quality-fixture';

test.use({ trace: 'off', screenshot: 'off' });

test('Policy Split lazily reviews large ordered results and exports each artifact type', async ({ page }) => {
  const resultID = '00000000-0000-4000-8000-000000000099';
  let trafficAttempts = 0;
  const tuples = Array.from({ length: 600 }, (_, index) => ({
    srcip: `10.0.${Math.floor(index / 250)}.${(index % 250) + 1}`,
    dstip: `203.0.113.${(index % 250) + 1}`,
    proto: 'tcp', port: 443, service: 'HTTPS', hits: 600 - index,
    last_seen: '2026-09-02T10:30:00Z', flow: index === 0 ? 'new' : '',
  }));

  await page.route('**/fgt-polsplit/analyze', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        result_id: resultID,
        total_messages: 12000,
        tuple_count: 600,
        src_count: 600,
        dst_count: 250,
        svc_count: 1,
        warning_count: 1,
        unresolved_count: 4,
        artifact_count: 2,
        warnings: ['Four objects require review.'],
        panels: [
          { key: 'traffic', label: 'Observed traffic', kind: 'traffic', count: 600 },
          { key: 'hybrid', label: 'Hybrid', kind: 'strategy', count: 2, recommended: true },
          { key: 'per_destination', label: 'Per destination', kind: 'strategy', count: 0 },
        ],
      }),
    });
  });
  await page.route('**/fgt-polsplit/results/*/panels/*', async route => {
    const key = new URL(route.request().url()).pathname.split('/').pop();
    if (key === 'traffic') {
      trafficAttempts++;
      if (trafficAttempts === 1) {
        await route.fulfill({
          status: 500,
          headers: { 'content-type': 'application/json', 'x-fortisafe-test-expected-error': '1' },
          body: JSON.stringify({ error: 'Synthetic lazy-load failure.' }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ key, kind: 'traffic', data: { tuples, stale_tuples: [], dns_suggestions: [], isdb_suggestions: [], user_activity: [], app_usage: [], utm_blocked: [] } }),
      });
      return;
    }
    const empty = key === 'per_destination';
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        key,
        kind: 'strategy',
        data: {
          key,
          label: key === 'hybrid' ? 'Hybrid' : 'Per destination',
          recommended: key === 'hybrid',
          policies: empty ? [] : [{ id: 100, name: 'PS42_HTTPS', src: [], dst: [], services: [], hits: 24 }],
          new_objects: [],
          config: empty ? '' : 'config firewall policy\n    edit 100\nend',
        },
      }),
    });
  });
  await page.goto('/fgt-polsplit/', { waitUntil: 'networkidle' });
  const firewall = page.getByRole('combobox', { name: 'Firewall' });
  await firewall.click();
  await page.getByRole('option', { name: 'edge.example.test' }).click();
  await page.getByLabel('Policy ID').fill('42');
  await page.getByRole('button', { name: 'Load Policy' }).click();
  await page.getByRole('button', { name: 'Analyze Traffic' }).click();

  await expect(page.locator('#ps-summary-stats')).toContainText('600');
  await expect(page.locator('#ps-summary-stats')).toContainText('4');
  await expect(page.locator('#ps-warnings')).toContainText('Four objects require review');
  const tabLabels = await page.getByRole('tab').allTextContents();
  expect(tabLabels).toEqual(['Observed traffic (600)', 'Hybrid (2) · Recommended', 'Per destination (0)']);
  await expect(page.locator('#ps-panel-state-text')).toContainText('Synthetic lazy-load failure');
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.locator('#ps-tuples-table tbody tr')).toHaveCount(600);

  const trafficTab = page.getByRole('tab', { name: /Observed traffic/ });
  await trafficTab.focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: /Hybrid/ })).toBeFocused();
  await expect(page.locator('#ps-strategy-panels')).toContainText('config firewall policy');
  await page.keyboard.press('End');
  await expect(page.getByRole('tab', { name: /Per destination/ })).toBeFocused();
  await expect(page.locator('#ps-strategy-panels')).toContainText('No traffic observed');
  await page.keyboard.press('ArrowLeft');
  await expect(page.getByRole('tab', { name: /Hybrid/ })).toBeFocused();

  for (const exportCase of [
    { button: 'Export summary JSON', filename: 'polsplit-policy-42-summary.json' },
    { button: 'Export traffic CSV', filename: 'polsplit-policy-42-traffic.csv' },
    { button: 'Export selected config', filename: 'polsplit-policy-42-hybrid.conf' },
  ]) {
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: exportCase.button }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe(exportCase.filename);
  }
});
