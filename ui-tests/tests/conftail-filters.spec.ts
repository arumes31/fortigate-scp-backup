import { expect, test } from './quality-fixture';

const currentViewsKey = 'fortisafe.conftail.views.v2';
const legacyViewsKey = 'fortisafe.conftail.views.v1';

test('ConfTail migrates, saves, loads, and deletes bounded local views safely', async ({ page }) => {
  await page.addInitScript(({ currentKey, legacyKey }) => {
    const legacy: Record<string, Record<string, string>> = {
      'Legacy safe': {
        firewall: '7',
        user: 'legacy-operator',
        state: 'retry',
        q: 'legacy-event-text-sentinel',
        token: 'legacy-token-sentinel',
        payload: 'legacy-payload-sentinel',
        password: 'legacy-password-sentinel',
      },
    };
    for (let index = 0; index < 11; index += 1) {
      legacy[`View ${index + 1}`] = { firewall: `${index + 1}`, state: 'all' };
    }
    legacy['View 1'].firewall = '9999999999';
    window.localStorage.setItem(currentKey, '{malformed-json');
    window.localStorage.setItem(legacyKey, JSON.stringify(legacy));
  }, { currentKey: currentViewsKey, legacyKey: legacyViewsKey });

  await page.goto('/fgt-conftail/', { waitUntil: 'networkidle' });

  const migrated = await page.evaluate(({ currentKey, legacyKey }) => ({
    current: window.localStorage.getItem(currentKey),
    legacy: window.localStorage.getItem(legacyKey),
  }), { currentKey: currentViewsKey, legacyKey: legacyViewsKey });
  expect(migrated.legacy).toBeNull();
  expect(migrated.current).not.toBeNull();
  const migratedJSON = JSON.parse(migrated.current || '{}');
  expect(migratedJSON.version).toBe(2);
  expect(migratedJSON.views).toHaveLength(10);
  expect(migratedJSON.views.find((view: { name: string }) => view.name === 'View 1').filters.firewall).toBeUndefined();
  expect(migrated.current).not.toContain('legacy-event-text-sentinel');
  expect(migrated.current).not.toContain('legacy-token-sentinel');
  expect(migrated.current).not.toContain('legacy-payload-sentinel');
  expect(migrated.current).not.toContain('legacy-password-sentinel');

  await page.getByLabel('Local view name').fill('Legacy safe');
  await page.getByLabel('Search redacted event text').fill('new-event-text-sentinel');
  await page.getByLabel('Administrator contains').fill('saved-operator');
  await page.getByRole('button', { name: 'Save current' }).click();
  await expect(page.getByRole('status')).toContainText('Saved local view');

  const saved = await page.evaluate(key => window.localStorage.getItem(key), currentViewsKey);
  expect(saved).toContain('saved-operator');
  expect(saved).not.toContain('new-event-text-sentinel');
  expect(saved).not.toMatch(/"(?:q|token|payload|password)"/);

  await page.getByLabel('Search redacted event text').fill('history-never-sentinel');
  await page.getByLabel('Administrator contains').fill('temporary-value');
  const loadRequestPromise = page.waitForRequest(request =>
    request.url().endsWith('/fgt-conftail/') && request.method() === 'POST',
  );
  await page.getByRole('button', { name: 'Load' }).click();
  const loadRequest = await loadRequestPromise;
  expect(loadRequest.postData()).toContain('user=saved-operator');
  expect(loadRequest.postData()).not.toContain('history-never-sentinel');
  expect(loadRequest.url()).not.toContain('saved-operator');
  await page.waitForLoadState('networkidle');
  expect(page.url()).not.toContain('history-never-sentinel');

  await page.getByLabel('Saved local view').selectOption('Legacy safe');
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('status')).toContainText('Deleted local view');
  await expect(page.getByLabel('Saved local view').locator('option[value="Legacy safe"]')).toHaveCount(0);
});

test('ConfTail filters, chips, and pagination submit sensitive values only by POST', async ({ page }) => {
  await page.goto('/fgt-conftail/', { waitUntil: 'networkidle' });

  const advanced = page.locator('details.ct-advanced-filters');
  await expect(advanced).not.toHaveAttribute('open', '');
  await advanced.getByText('Advanced filters').click();
  await expect(page.getByLabel('Graylog source contains')).toBeVisible();

  await page.getByLabel('Search redacted event text').fill('keyboard-event-text-sentinel');
  const keyboardRequestPromise = page.waitForRequest(request =>
    request.url().endsWith('/fgt-conftail/') && request.method() === 'POST',
  );
  await page.getByLabel('Search redacted event text').press('Enter');
  const keyboardRequest = await keyboardRequestPromise;
  expect(keyboardRequest.postData()).toContain('q=keyboard-event-text-sentinel');
  expect(keyboardRequest.url()).not.toContain('keyboard-event-text-sentinel');
  await page.waitForLoadState('networkidle');

  const paginationRequestPromise = page.waitForRequest(request =>
    request.url().endsWith('/fgt-conftail/') && request.method() === 'POST',
  );
  await page.getByRole('button', { name: 'Next' }).click();
  const paginationRequest = await paginationRequestPromise;
  expect(paginationRequest.postData()).toContain('user=body-only-operator');
  expect(paginationRequest.postData()).toContain('page=2');
  expect(paginationRequest.url()).not.toContain('body-only-operator');
  await page.waitForLoadState('networkidle');

  const chipRequestPromise = page.waitForRequest(request =>
    request.url().endsWith('/fgt-conftail/') && request.method() === 'POST',
  );
  await page.getByRole('button', { name: /Remove Source filter/ }).click();
  const chipRequest = await chipRequestPromise;
  expect(chipRequest.postData()).toContain('user=body-only-operator');
  expect(chipRequest.postData()).not.toContain('source=');
  expect(chipRequest.url()).not.toContain('body-only-operator');
  await page.waitForLoadState('networkidle');

  const browserURLs = await page.evaluate(() => [
    window.location.href,
    document.referrer,
    ...performance.getEntriesByType('navigation').map(entry => entry.name),
  ]);
  expect(browserURLs.join('\n')).not.toContain('keyboard-event-text-sentinel');
  expect(browserURLs.join('\n')).not.toContain('body-only-operator');
});

test('ConfTail failed health stays actionable and bounded', async ({ page }) => {
  await page.goto('/fgt-conftail/?scenario=error', { waitUntil: 'networkidle' });

  const healthCards = page.locator('.ct-metrics > .ct-metric');
  await expect(healthCards).toHaveCount(3);
  await expect(healthCards.first()).toContainText('Synthetic Graylog failure');
  await expect(healthCards.first()).toContainText('Evidence:');
  await expect(healthCards.first()).toContainText('Last check:');
  await expect(healthCards.first()).toContainText('Next: Retry poll');

  const overflow = await page.locator('.ct-metrics').evaluate(element =>
    element.scrollWidth > element.clientWidth,
  );
  expect(overflow).toBe(false);
});
