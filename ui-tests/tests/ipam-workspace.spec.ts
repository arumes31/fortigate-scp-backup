import { expect, test } from './quality-fixture';

test('IPAM filters entries and prioritized overlaps with source context', async ({ page }, testInfo) => {
  await page.goto('/ipam?scenario=full', { waitUntil: 'networkidle' });

  await expect(page.locator('#ipamSearchMode')).toContainText('Text mode');
  await expect(page.locator('#ipamSearchCount')).toContainText('1,000 of 1,205');
  await expect(page.locator('#ipamBody > tr')).toHaveCount(1_001);
  await expect(page.locator('#ipamOverlapBody > tr')).toHaveCount(501);

  const overlapBeforeFilters = await page.locator('#ipamOverlapCard').evaluate((overlap, filters) =>
    Boolean(overlap.compareDocumentPosition(filters as Node) & Node.DOCUMENT_POSITION_FOLLOWING),
    await page.locator('#ipamFilters').elementHandle(),
  );
  expect(overlapBeforeFilters).toBe(true);

  await page.getByRole('button', { name: 'IP address mode' }).click();
  await page.getByLabel('Search prefixes', { exact: true }).fill('10.10.5.5');
  await expect(page.locator('#ipamSearchMode')).toContainText('IP address mode');
  await expect(page.locator('#ipamSearchCount')).toContainText('1 of 1,205');
  await expect(page.locator('#ipamBody')).toContainText('10.10.0.0/16');

  await page.getByRole('button', { name: 'Text mode' }).click();
  await page.getByLabel('Search prefixes', { exact: true }).fill('');
  await page.getByLabel('Firewall', { exact: true }).selectOption('branch.example.test');
  await page.getByLabel('VDOM', { exact: true }).selectOption('tenant-a');
  await page.getByRole('button', { name: 'Routes' }).click();
  await expect(page.locator('#ipamSearchCount')).toContainText('1 of 1,205');
  await expect(page.locator('#ipamBody')).toContainText('branch.example.test');
  await expect(page.locator('#ipamBody')).toContainText('tenant-a');
  await expect(page.locator('#ipamOverlapBody')).toContainText('tenant-a');
  await expect(page.locator('#ipamOverlapBody')).toContainText('static route');
  await expect(page.locator('#ipamActiveFilters').getByRole('button')).toHaveCount(3);

  await page.locator('#ipamActiveFilters').getByRole('button', { name: /Remove VDOM/ }).click();
  await expect(page.getByLabel('VDOM', { exact: true })).toHaveValue('all');
  await page.screenshot({ path: testInfo.outputPath('ipam-filter-workspace.png'), fullPage: true, animations: 'disabled' });
});

test('IPAM CSV exports the selected view and neutralizes spreadsheet formulas', async ({ page }) => {
  await page.goto('/ipam?scenario=full', { waitUntil: 'networkidle' });
  await page.getByLabel('Firewall', { exact: true }).selectOption('edge.example.test');
  await page.getByRole('button', { name: 'Interfaces' }).click();

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export filtered CSV' }).click();
  const download = await downloadPromise;
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const csv = Buffer.concat(chunks).toString('utf8');

  expect(csv).toContain('"Prefix","Firewall","VDOM","Source","Name / detail"');
  expect(csv).toContain('edge.example.test');
  expect(csv).not.toContain('branch.example.test');
  expect(csv).toContain("'=HYPERLINK(");
  expect(csv).not.toMatch(/(?:^|,)="?HYPERLINK/m);
});

test('IPAM loading, error, and empty states stay explicit', async ({ page }) => {
  await page.goto('/ipam?scenario=loading', { waitUntil: 'networkidle' });
  await expect(page.locator('#ipamProgressWrap')).toBeVisible();
  await expect(page.locator('#ipamProgressText')).toContainText('Updating');

  await page.goto('/ipam?scenario=error', { waitUntil: 'networkidle' });
  await expect(page.locator('#ipamLoadState')).toContainText('Failed to load IPAM data');

  await page.goto('/ipam?scenario=empty', { waitUntil: 'networkidle' });
  await expect(page.locator('#ipamLoadState')).toContainText('No prefixes found');
  await expect(page.getByRole('button', { name: 'Update now' })).toBeVisible();
});
