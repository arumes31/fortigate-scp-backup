import { expect, test } from './quality-fixture';

test('shared dialog traps focus, requires a name, and returns focus', async ({ page }) => {
  await page.goto('/__ux/primitives', { waitUntil: 'networkidle' });
  const opener = page.getByRole('button', { name: 'Remove synthetic firewall' });
  const dialog = page.getByRole('dialog', { name: 'Confirm removal' });

  await opener.click();
  await expect(dialog).toBeVisible();
  const confirmation = dialog.getByLabel('Type edge.example.test to confirm');
  await expect(confirmation).toBeFocused();
  const remove = dialog.getByRole('button', { name: 'Remove firewall' });
  await expect(remove).toBeDisabled();

  await confirmation.fill('wrong.example.test');
  await expect(remove).toBeDisabled();
  await confirmation.fill('edge.example.test');
  await expect(remove).toBeEnabled();

  await page.keyboard.press('Tab');
  await expect(remove).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(confirmation).toBeFocused();

  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(opener).toBeFocused();
});

test('shared disclosure, tabs, copy feedback, and time preference are keyboard safe', async ({ page }, testInfo) => {
  await page.goto('/__ux/primitives', { waitUntil: 'networkidle' });

  const details = page.locator('details', { hasText: 'Synthetic details' });
  await expect(details).not.toHaveAttribute('open', '');
  await details.getByText('Synthetic details', { exact: true }).click();
  await expect(details).toHaveAttribute('open', '');

  const firstTab = page.getByRole('tab', { name: 'Summary' });
  const secondTab = page.getByRole('tab', { name: 'Raw data' });
  await firstTab.focus();
  await page.keyboard.press('ArrowRight');
  await expect(secondTab).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tabpanel', { name: 'Raw data' })).toBeVisible();
  await page.keyboard.press('Home');
  await expect(firstTab).toHaveAttribute('aria-selected', 'true');

  const copyButton = page.getByRole('button', { name: 'Copy synthetic value' });
  await expect(copyButton.locator('svg')).toHaveAttribute('aria-hidden', 'true');
  await expect(copyButton.locator('span')).toHaveText('Copy synthetic value');
  await copyButton.click();
  await expect(page.getByRole('status', { name: 'Copy result' })).toHaveText('Copied');
  await expect(page.getByRole('status', { name: 'Loading state' })).toHaveAttribute('aria-live', 'polite');
  await expect(page.getByRole('status', { name: 'Success state' })).toHaveAttribute('aria-live', 'polite');
  await expect(page.getByRole('status', { name: 'Warning state' })).toHaveAttribute('aria-live', 'polite');
  await expect(page.getByRole('alert', { name: 'Error state' })).toHaveAttribute('aria-live', 'assertive');

  const utc = page.getByRole('button', { name: 'UTC', exact: true });
  const browserTime = page.getByRole('button', { name: 'Browser time' });
  await expect(utc).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('time').first()).toHaveAttribute('datetime', '2026-09-02T10:30:00Z');
  await browserTime.click();
  await expect(browserTime).toHaveAttribute('aria-pressed', 'true');
  await expect.poll(() => page.evaluate(() => localStorage.getItem('fortisafe.ui.v1.timeMode'))).toBe('local');

  await page.reload({ waitUntil: 'networkidle' });
  await expect(page.getByRole('button', { name: 'Browser time' })).toHaveAttribute('aria-pressed', 'true');

  const screenshot = await page.screenshot({
    path: testInfo.outputPath('shared-primitives.png'),
    fullPage: true,
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);

  await page.goto('/dashboard?scenario=warning', { waitUntil: 'networkidle' });
  await expect(page.getByRole('button', { name: 'Browser time' })).toHaveAttribute('aria-pressed', 'true');
});
