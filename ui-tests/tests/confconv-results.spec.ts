import { expect, test } from './quality-fixture';

test('Config Converter reviews deterministic impact, warnings, and downloadable CLI safely', async ({ page }) => {
  let noChange = false;
  await page.route('**/fgt-confconv/convert', async route => {
    const body = noChange ? {
      sections: [], warnings: [], appliedOrder: ['sdwan-routes-to-rules'], combined: '',
      changes: [], changeCount: 0, changesTruncated: false,
    } : {
      sections: [{
        recipe: 'sdwan-routes-to-rules',
        label: '<img src=x onerror="window.__unsafeLabel=true">',
        lines: ['config system sdwan', '    config service', '        edit 9', '        next', '    end', 'end'],
      }],
      warnings: [{
        recipe: 'sdwan-routes-to-rules',
        detail: '<script>window.__unsafeWarning=true</script> Review generated endpoint.',
      }],
      appliedOrder: ['sdwan-routes-to-rules'],
      combined: 'config system sdwan\n    config service\n        edit 9\n        next\n    end\nend\n',
      changes: [
        { kind: 'static route', name: '3', action: 'disable', summary: 'Disabled superseded static route.' },
        { kind: 'SD-WAN rule', name: '<b>9</b>', action: 'create', summary: 'Created SD-WAN rule.' },
      ],
      changeCount: 2,
      changesTruncated: false,
    };
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });

  await page.goto('/fgt-confconv/', { waitUntil: 'networkidle' });
  const firewall = page.getByRole('combobox', { name: 'Firewall' });
  await firewall.click();
  await page.getByRole('option', { name: 'edge.example.test' }).click();
  await page.getByRole('checkbox', { name: 'SD-WAN static routes → SD-WAN rules' }).check();
  await page.getByRole('button', { name: 'Generate', exact: true }).click();

  await expect(page.locator('#cc-result-summary')).toHaveText('2 modeled changes · 1 warning · 1 CLI section');
  await expect(page.locator('#cc-impact-rows tr')).toHaveCount(2);
  await expect(page.locator('#cc-impact-rows tr').nth(0)).toContainText('static route');
  await expect(page.locator('#cc-impact-rows tr').nth(1)).toContainText('<b>9</b>');
  await expect(page.locator('#cc-impact-rows b')).toHaveCount(0);

  const impactTab = page.getByRole('tab', { name: /Impact/ });
  const warningsTab = page.getByRole('tab', { name: /Warnings/ });
  const cliTab = page.getByRole('tab', { name: /CLI/ });
  await impactTab.focus();
  await page.keyboard.press('ArrowRight');
  await expect(warningsTab).toBeFocused();
  await expect(page.locator('#cc-warnings')).toContainText('<script>window.__unsafeWarning=true</script>');
  await expect(page.locator('#cc-warnings script')).toHaveCount(0);

  await page.keyboard.press('End');
  await expect(cliTab).toBeFocused();
  await expect(page.locator('#cc-sections')).toContainText('<img src=x onerror="window.__unsafeLabel=true">');
  await expect(page.locator('#cc-sections img')).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => ({
    label: (window as unknown as { __unsafeLabel?: boolean }).__unsafeLabel,
    warning: (window as unknown as { __unsafeWarning?: boolean }).__unsafeWarning,
  }))).toEqual({ label: undefined, warning: undefined });

  await page.getByRole('button', { name: 'Copy all CLI' }).click();
  await expect(page.locator('#cc-copy-feedback')).toContainText(/All CLI copied|Copy failed/);

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download CLI' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('confconv-firewall-7.conf');
  expect(await download.createReadStream()).not.toBeNull();

  noChange = true;
  await page.getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(page.locator('#cc-no-changes')).toHaveText('No modeled configuration changes were detected.');
  await expect(page.locator('#cc-no-changes')).toBeVisible();
  await expect(page.locator('#cc-result-summary')).toHaveText('0 modeled changes · 0 warnings · 0 CLI sections');
});
