import { expect, test } from './quality-fixture';

test('audit prioritizes high findings and exposes labeled management', async ({ page }, testInfo) => {
  await page.goto('/audit?scenario=full', { waitUntil: 'networkidle' });
  await expect(page.locator('#auditLoadStatus')).toHaveText('All 2 audit results loaded.');
  await expect(page.locator('#statCritical')).toHaveText('1');

  const rows = page.locator('tr.audit-row-item');
  await expect(rows.first()).toHaveAttribute('data-fwid', '7');
  await expect(rows.first()).toContainText('1 critical');
  await expect(rows.first()).not.toContainText('clean');

  const rules = page.locator('details.audit-management').first();
  await expect(rules).not.toHaveAttribute('open', '');
  await rules.locator('summary').click();
  await expect(rules.getByLabel(/Rule name/)).toBeVisible();
  await expect(rules.getByLabel(/Search pattern/)).toBeVisible();
  await expect(rules.getByLabel('Severity')).toBeVisible();
  await expect(rules.getByLabel(/Remediation/)).toBeVisible();

  const detail = rows.first().locator('[data-audit-detail="7"]');
  await detail.focus();
  await page.keyboard.press('Enter');
  await expect(detail).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('#detail-7')).toBeVisible();
  await expect(rows.first().getByLabel('Ticket ID')).toBeVisible();
  await expect(rows.first().getByLabel('Comment')).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath('audit-prioritized.png'),
    fullPage: true,
    animations: 'disabled',
  });
});

test('audit empty and partial-error states cannot look all-clear', async ({ page }) => {
  await page.goto('/audit?scenario=empty', { waitUntil: 'networkidle' });
  await expect(page.locator('details.audit-exemptions')).not.toHaveAttribute('open', '');
  await expect(page.locator('#auditLoadStatus')).toHaveText('All 0 audit results loaded.');

  await page.goto('/audit?scenario=error', { waitUntil: 'networkidle' });
  await expect(page.locator('#auditLoadStatus')).toContainText('1/2 loaded · 1 failed. Results are incomplete.');
  await expect(page.locator('#statLoaded')).toContainText('⚠1');
  await expect(page.locator('#statCritical')).toContainText('1 ⚠');
  await expect(page.locator('tr.audit-row-item').first()).toHaveAttribute('data-fwid', '12');
  await expect(page.locator('tr.audit-row-item').first()).toContainText('Failed to load');
  await expect(page.locator('.audit-cve-error')).toContainText('Synthetic CVE refresh failure');
  await expect(page.getByRole('button', { name: 'Refresh now' })).toBeVisible();
});
