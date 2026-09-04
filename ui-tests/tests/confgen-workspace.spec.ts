import { expect, test } from './quality-fixture';

test.use({ trace: 'off', screenshot: 'off' });

test('ConfGen guards meaningful edits without persisting raw policy text', async ({ page }) => {
  const sentinel = 'SENSITIVE-POLICY-TEXT-91e4';
  const consoleMessages: string[] = [];
  const frontendLogs: string[] = [];
  page.on('console', message => consoleMessages.push(message.text()));
  page.on('request', request => {
    if (request.url().endsWith('/fgt-confgen/log')) frontendLogs.push(request.postData() || '');
  });

  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/fgt-confgen/', { waitUntil: 'networkidle' });
  const root = page.locator('#confgen-page');
  const dirty = page.locator('#confgen-dirty');
  await expect(page.locator('.confgen-target-context')).toBeVisible();
  await expect(page.locator('.sidebar')).toBeVisible();
  await expect(page.locator('#policy-form')).toBeVisible();
  await expect(page.locator('.confgen-review-rail')).toBeVisible();
  await expect(root).toHaveAttribute('data-dirty', 'false');
  await expect(dirty).toBeHidden();

  const workspaceGeometry = await page.evaluate(() => {
    const rectangle = (selector: string) => {
      const bounds = document.querySelector(selector)?.getBoundingClientRect();
      return bounds && { x: bounds.x, y: bounds.y, width: bounds.width, height: bounds.height };
    };
    return {
      sidebar: rectangle('.confgen-workspace .sidebar'),
      editor: rectangle('.confgen-workspace #policy-form'),
      review: rectangle('.confgen-review-rail'),
      viewportWidth: window.innerWidth,
    };
  });
  expect(workspaceGeometry.sidebar).toBeTruthy();
  expect(workspaceGeometry.editor).toBeTruthy();
  expect(workspaceGeometry.review).toBeTruthy();
  if (workspaceGeometry.viewportWidth >= 1280) {
    expect(workspaceGeometry.sidebar!.x).toBeLessThan(workspaceGeometry.editor!.x);
    expect(workspaceGeometry.editor!.x).toBeLessThan(workspaceGeometry.review!.x);
  } else {
    expect(workspaceGeometry.review!.y).toBeGreaterThan(workspaceGeometry.editor!.y);
  }
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
  const transitionDuration = await page.locator('.confgen-page .btn').first().evaluate((element) => (
    Number.parseFloat(getComputedStyle(element).transitionDuration)
  ));
  expect(transitionDuration).toBeLessThanOrEqual(0.001);

  const targetCombobox = page.locator('.confgen-target-context [role="combobox"]');
  await targetCombobox.focus();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Load Config' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Load Template')).toBeFocused();

  await page.getByLabel('Load Template').selectOption('Synthetic baseline');
  await page.getByRole('button', { name: 'Load', exact: true }).click();
  await page.getByText('Synthetic allow', { exact: true }).click();
  await expect(root).toHaveAttribute('data-dirty', 'false');

  await page.getByLabel('Policy Name').fill(sentinel);
  await expect(root).toHaveAttribute('data-dirty', 'true');
  await expect(dirty).toBeVisible();
  const dirtyUnload = await page.evaluate(() => {
    const event = new Event('beforeunload', { cancelable: true });
    return { dispatched: window.dispatchEvent(event), prevented: event.defaultPrevented };
  });
  expect(dirtyUnload).toEqual({ dispatched: false, prevented: true });

  await page.getByRole('button', { name: 'Reset current policy' }).click();
  await expect(root).toHaveAttribute('data-dirty', 'false');
  const cleanUnload = await page.evaluate(() => {
    const event = new Event('beforeunload', { cancelable: true });
    return event.defaultPrevented;
  });
  expect(cleanUnload).toBe(false);

  await page.getByLabel('Policy Name').fill(sentinel);
  await page.getByRole('button', { name: 'Save Policy' }).click();
  await expect(root).toHaveAttribute('data-dirty', 'true');
  await page.getByRole('button', { name: 'Generate All Policies' }).click();
  await expect(page.locator('#output1')).toContainText('config firewall policy');
  await expect(root).toHaveAttribute('data-dirty', 'false');
  await expect(dirty).toBeHidden();

  const longMessage = 'Validation detail '.repeat(80);
  await page.locator('#confgen-feedback').evaluate((element, message) => { element.textContent = message; }, longMessage);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, 'ConfGen has document-level horizontal overflow').toBeLessThanOrEqual(1);

  const storage = await page.evaluate(() => JSON.stringify(localStorage));
  const evidence = [storage, consoleMessages.join('\n'), frontendLogs.join('\n')].join('\n');
  expect(evidence).not.toContain(sentinel);
});
