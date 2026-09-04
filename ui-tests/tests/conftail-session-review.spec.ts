import { expect, test } from './quality-fixture';

test('ConfTail session separates session and delivery facts across lifecycle states', async ({ page }) => {
  const states = [
    { path: '/fgt-conftail/chain/fixture-chain', label: 'Accepted by Hookwise', preview: true },
    { path: '/fgt-conftail/chain/fixture-chain?scenario=warning', label: 'Queued', preview: true },
    { path: '/fgt-conftail/chain/fixture-chain?scenario=error', label: 'Delivery failed', preview: true },
    { path: '/fgt-conftail/chain/fixture-chain?scenario=loading', label: 'Not queued', preview: false },
    { path: '/fgt-conftail/chain/fixture-chain?scenario=empty', label: 'No delivery record', preview: false },
  ];

  for (const state of states) {
    await page.goto(state.path, { waitUntil: 'networkidle' });
    await expect(page.getByRole('heading', { name: 'Session facts' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Hookwise delivery' })).toBeVisible();
    await expect(page.locator('.ct-delivery-facts')).toContainText(state.label);
    await expect(page.getByText('Duration', { exact: true })).toBeVisible();
    await expect(page.getByText('102', { exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Hookwise ticket preview' })).toHaveCount(state.preview ? 1 : 0);
    const horizontalOverflow = await page.locator('main').evaluate(element => element.scrollWidth > element.clientWidth);
    expect(horizontalOverflow).toBe(false);
  }

  await page.goto('/fgt-conftail/chain/fixture-chain', { waitUntil: 'networkidle' });
  const ticketLink = page.getByRole('link', { name: 'Open Hookwise ticket' });
  await expect(ticketLink).toHaveAttribute('href', 'https://tickets.example.test/ticket/123');
  await page.getByText('View plain-text description preview').click();
  const preview = page.locator('.ct-ticket-description');
  await expect(preview).toContainText('Affected objects:');
  await expect(preview).toContainText('Change excerpts (oldest first):');
  await expect(preview).not.toContainText('{"');
});

test('ConfTail grouping is a stable projection over canonical paginated events', async ({ page }) => {
  await page.goto('/fgt-conftail/chain/fixture-chain', { waitUntil: 'networkidle' });
  await expect(page.getByRole('link', { name: 'Chronological' })).toHaveAttribute('aria-current', 'page');
  await expect(page.locator('[data-canonical-position]').first()).toHaveAttribute('data-canonical-position', '1');

  await page.getByRole('link', { name: 'By transaction' }).focus();
  await page.getByRole('link', { name: 'By transaction' }).press('Enter');
  await page.waitForLoadState('networkidle');
  await expect(page).toHaveURL(/view=transaction/);
  await expect(page.getByRole('link', { name: 'By transaction' })).toHaveAttribute('aria-current', 'page');
  await expect(page.getByRole('heading', { name: 'Transaction 82378752' })).toBeVisible();
  const firstGroupPositions = await page.locator('.ct-event-group').first().locator('[data-canonical-position]').evaluateAll(
    elements => elements.map(element => element.getAttribute('data-canonical-position')),
  );
  expect(firstGroupPositions).toEqual(['1', '3']);
  const groupedOverflow = await page.locator('main').evaluate(element => element.scrollWidth > element.clientWidth);
  expect(groupedOverflow).toBe(false);

  await page.getByRole('link', { name: 'Next' }).click();
  await page.waitForLoadState('networkidle');
  await expect(page).toHaveURL(/page=2/);
  await expect(page).toHaveURL(/view=transaction/);
  const secondPagePositions = await page.locator('[data-canonical-position]').evaluateAll(
    elements => elements.map(element => element.getAttribute('data-canonical-position')),
  );
  expect(secondPagePositions).toEqual(['101', '102']);
  await expect(page.getByRole('link', { name: 'Previous' })).toHaveAttribute('href', /view=transaction/);

  await page.getByRole('link', { name: 'By object' }).click();
  await page.waitForLoadState('networkidle');
  await expect(page).toHaveURL(/page=2/);
  await expect(page).toHaveURL(/view=object/);
  await expect(page.getByRole('heading', { name: 'system.central-management' })).toBeVisible();

  await page.goto('/fgt-conftail/chain/fixture-chain?page=2&view=object#ct-event-141', { waitUntil: 'networkidle' });
  await expect(page.locator('#ct-event-141')).toBeVisible();
  const horizontalOverflow = await page.locator('main').evaluate(element => element.scrollWidth > element.clientWidth);
  expect(horizontalOverflow).toBe(false);
});
