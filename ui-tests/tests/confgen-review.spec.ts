import { expect, test } from './quality-fixture';

test.use({ trace: 'off', screenshot: 'off' });

test('ConfGen review handles validation states and safe CLI exports', async ({ page }) => {
  type ValidationMode = 'warning' | 'invalid' | 'oversized' | 'timeout';
  let validationMode: ValidationMode = 'warning';
  let generationValid = false;

  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          (window as unknown as { __copiedOutput: string }).__copiedOutput = value;
        },
      },
    });
  });
  await page.route('**/fgt-confgen/validate_policy', async route => {
    const responses = {
      warning: {
        status: 200,
        body: { valid: true, errors: [], warnings: [{ code: 'policy_comment_empty', message: 'Policy comment is empty.', policy_index: 0 }] },
      },
      invalid: {
        status: 200,
        body: { valid: false, errors: [{ code: 'invalid_action', message: 'Action must be accept or deny.', policy_index: 0 }], warnings: [] },
      },
      oversized: {
        status: 413,
        body: { code: 'request_too_large', message: 'Request exceeds the size limit.' },
      },
      timeout: {
        status: 408,
        body: { code: 'request_timeout', message: 'Policy processing exceeded its time limit.' },
      },
    } satisfies Record<ValidationMode, { status: number; body: object }>;
    const response = responses[validationMode];
    await route.fulfill({
      status: response.status,
      headers: {
        'content-type': 'application/json',
        ...(response.status >= 400 ? { 'x-fortisafe-test-expected-error': '1' } : {}),
      },
      body: JSON.stringify(response.body),
    });
  });
  await page.route('**/fgt-confgen/generate_policy', async route => {
    if (!generationValid) {
      await route.fulfill({
        status: 422,
        headers: { 'content-type': 'application/json', 'x-fortisafe-test-expected-error': '1' },
        body: JSON.stringify({
          code: 'validation_failed',
          message: 'Policy validation failed.',
          validation: { valid: false, errors: [{ code: 'invalid_action', message: 'Action must be accept or deny.', policy_index: 0 }], warnings: [] },
        }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        validation: { valid: true, errors: [], warnings: [] },
        outputs: [{
          policy_id: 'fixture-policy',
          policy_name: 'Synthetic allow',
          output1: '<img src=x onerror="window.__confgenInjected=true">\nconfig firewall policy',
          output2: 'config firewall policy\n    edit 2\nend',
          output3: 'config firewall policy\n    edit 3\nend',
        }],
      }),
    });
  });

  await page.goto('/fgt-confgen/', { waitUntil: 'networkidle' });
  await page.getByLabel('Load Template').selectOption('Synthetic baseline');
  await page.getByRole('button', { name: 'Load', exact: true }).click();

  await page.getByRole('button', { name: 'Validate policies' }).click();
  await expect(page.locator('#warning-count')).toHaveText('1');
  await expect(page.locator('#review-warnings-panel')).toBeVisible();
  await expect(page.locator('#warning-list')).toContainText('policy_comment_empty');

  const warningsTab = page.getByRole('tab', { name: /Warnings/ });
  await warningsTab.focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'CLI output' })).toBeFocused();
  await expect(page.getByRole('tab', { name: 'CLI output' })).toHaveAttribute('aria-selected', 'true');

  validationMode = 'invalid';
  await page.getByRole('button', { name: 'Validate policies' }).click();
  await expect(page.locator('#validation-count')).toHaveText('1');
  await expect(page.locator('#validation-list')).toContainText('invalid_action');

  validationMode = 'oversized';
  await page.getByRole('button', { name: 'Validate policies' }).click();
  await expect(page.locator('#validation-list')).toContainText('request_too_large');
  await expect(page.locator('#confgen-feedback')).toContainText('size limit');

  validationMode = 'timeout';
  await page.getByRole('button', { name: 'Validate policies' }).click();
  await expect(page.locator('#validation-list')).toContainText('request_timeout');
  await expect(page.locator('#confgen-feedback')).toContainText('time limit');

  await page.getByRole('button', { name: 'Generate All Policies' }).click();
  await expect(page.locator('#validation-list')).toContainText('invalid_action');
  await expect(page.locator('.output-section')).toBeHidden();

  generationValid = true;
  await page.getByRole('button', { name: 'Generate All Policies' }).click();
  await expect(page.locator('#review-cli-panel')).toBeVisible();
  await expect(page.locator('#output1')).toContainText('<img src=x');
  await expect(page.locator('#review-cli-panel img')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __confgenInjected?: boolean }).__confgenInjected)).not.toBe(true);

  await page.getByRole('button', { name: 'Copy', exact: true }).first().click();
  await expect(page.locator('#confgen-feedback')).toContainText('copied');
  expect(await page.evaluate(() => (window as unknown as { __copiedOutput: string }).__copiedOutput)).toContain('config firewall policy');

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download' }).first().click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('fortisafe-confgen-output1.txt');
  await expect(page.locator('#confgen-feedback')).toContainText('download started');
});
