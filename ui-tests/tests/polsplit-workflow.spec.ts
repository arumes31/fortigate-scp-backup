import { expect, test } from './quality-fixture';

type PolicyMode = 'success' | 'single' | 'multiple' | 'error';

const policyResponse = (policyID: number, vdom = 'root') => ({
  firewall: { id: 7, fqdn: 'edge.example.test' },
  policy: {
    id: policyID,
    name: `Synthetic policy ${policyID}`,
    vdom,
    srcintf: ['lan'],
    dstintf: ['wan1'],
    srcaddr: ['all'],
    dstaddr: ['all'],
    services: ['ALL'],
    action: 'accept',
    schedule: 'always',
    nat: 'enable',
  },
  action_display: 'accept',
  backup_time: '2026-09-02 10:30',
  warnings: [],
});

async function selectTarget(page: import('@playwright/test').Page, policyID: string) {
  const firewall = page.getByRole('combobox', { name: 'Firewall' });
  await firewall.click();
  await page.getByRole('option', { name: 'edge.example.test' }).click();
  await page.getByLabel('Policy ID').fill(policyID);
}

test('Policy Split resolves VDOM ambiguity with a contained keyboard dialog and supports retry', async ({ page }) => {
  let mode: PolicyMode = 'success';
  await page.route('**/fgt-polsplit/policy_info?*', async route => {
    const url = new URL(route.request().url());
    const policyID = Number(url.searchParams.get('policy_id'));
    const selectedVDOM = url.searchParams.get('vdom');
    if (selectedVDOM || mode === 'success') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(policyResponse(policyID, selectedVDOM || 'root')) });
      return;
    }
    if (mode === 'error') {
      await route.fulfill({ status: 500, headers: { 'content-type': 'application/json', 'x-fortisafe-test-expected-error': '1' }, body: JSON.stringify({ error: 'Synthetic backup failure.' }) });
      return;
    }
    const vdoms = mode === 'single' ? ['root'] : ['root', 'dmz'];
    await route.fulfill({
      status: 400,
      headers: { 'content-type': 'application/json', 'x-fortisafe-test-expected-error': '1' },
      body: JSON.stringify({ ambiguous: true, vdoms, error: 'Choose a VDOM.' }),
    });
  });

  await page.goto('/fgt-polsplit/', { waitUntil: 'networkidle' });

  mode = 'single';
  await selectTarget(page, '43');
  await page.getByRole('button', { name: 'Load Policy' }).click();
  const dialog = page.getByRole('dialog', { name: 'Choose a VDOM' });
  await expect(dialog).toBeVisible();
  await expect(page.getByRole('radio', { name: 'root' })).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(page.getByRole('button', { name: 'Load selected VDOM' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('radio', { name: 'root' })).toBeFocused();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await expect(page.locator('#ps-context-vdom')).toHaveText('root');

  mode = 'multiple';
  await selectTarget(page, '44');
  await page.getByRole('button', { name: 'Load Policy' }).click();
  await expect(dialog).toBeVisible();
  await page.keyboard.press('ArrowDown');
  await expect(page.getByRole('radio', { name: 'dmz' })).toBeChecked();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await expect(page.locator('#ps-context-vdom')).toHaveText('dmz');

  await selectTarget(page, '45');
  await page.getByRole('button', { name: 'Load Policy' }).click();
  await expect(dialog).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Cancel' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await expect(page.getByRole('button', { name: 'Load Policy' })).toBeFocused();
  await expect(page.locator('#ps-feedback')).toContainText('cancelled');

  await selectTarget(page, '47');
  await page.getByRole('button', { name: 'Load Policy' }).click();
  await expect(dialog).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(page.getByRole('button', { name: 'Load Policy' })).toBeFocused();
  await expect(page.locator('#ps-feedback')).toContainText('cancelled');

  mode = 'error';
  await selectTarget(page, '46');
  await page.getByRole('button', { name: 'Load Policy' }).click();
  await expect(page.locator('#ps-feedback')).toContainText('Synthetic backup failure');
  await expect(page.locator('#ps-context-phase')).toHaveText('Load failed');
  mode = 'success';
  await page.getByRole('button', { name: 'Load Policy' }).click();
  await expect(page.locator('#ps-policy-summary')).toContainText('Synthetic policy 46');
  await expect(page.locator('#ps-context-phase')).toHaveText('Ready to analyze');
});

test('Policy Split keeps context visible and submits the compatible option contract', async ({ page }) => {
  let analyzeBody: Record<string, unknown> | undefined;
  page.on('request', request => {
    if (request.url().endsWith('/fgt-polsplit/analyze')) analyzeBody = request.postDataJSON();
  });
  await page.goto('/fgt-polsplit/', { waitUntil: 'networkidle' });
  await selectTarget(page, '42');
  await page.getByRole('button', { name: 'Load Policy' }).click();
  await expect(page.locator('#ps-context-target')).toContainText('edge.example.test · Policy 42');
  await expect(page.locator('#ps-context-vdom')).toHaveText('root');

  await expect(page.locator('#ps-advanced-options')).not.toHaveAttribute('open', '');
  await page.getByLabel('Compare with baseline (flags new/stale flows)').selectOption('604800');
  await page.getByLabel('Roll up destination hosts into subnets').check();
  await page.getByLabel('Change ticket (optional, added to comments)').fill('CHG-4242');
  await page.getByText('Advanced options', { exact: true }).click();
  await page.getByLabel('Rollup threshold (hosts per net)').fill('8');
  await page.getByLabel('Rollup mask (/bits)').fill('23');
  await page.getByLabel('New object prefix').fill('SAFE42');
  await page.getByLabel('Internet destinations (WAN) as "all"').selectOption('on');
  await page.getByLabel('Resolve destination DNS names (PTR)').check();
  await page.getByLabel('Add explicit fallthrough deny+log policy').check();

  await expect(page.locator('#ps-options-summary')).toContainText('Window 24h');
  await expect(page.locator('#ps-options-summary')).toContainText('destination rollup on');
  await expect(page.locator('#ps-options-summary')).toContainText('Previous 7 days');
  await expect(page.locator('#ps-options-summary')).toContainText('WAN mode on');
  await expect(page.locator('#ps-options-summary')).toContainText('fallthrough deny on');

  await page.getByRole('button', { name: 'Analyze Traffic' }).click();
  await expect(page.locator('#ps-context-phase')).toHaveText('Review results');
  expect(analyzeBody).toMatchObject({
    fw_id: 7,
    policy_id: 42,
    vdom: '',
    rollup_src: true,
    rollup_dst: true,
    rollup_threshold: 8,
    rollup_mask: 23,
    prefix: 'SAFE42',
    compare_seconds: 604800,
    resolve_dns: true,
    ticket: 'CHG-4242',
    wan_mode: 'on',
    emit_deny: true,
    range_seconds: 86400,
  });

  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect(page.locator('.ps-context-bar')).toBeVisible();
  const contextTop = await page.locator('.ps-context-bar').evaluate(element => element.getBoundingClientRect().top);
  expect(contextTop).toBeGreaterThanOrEqual(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
});
