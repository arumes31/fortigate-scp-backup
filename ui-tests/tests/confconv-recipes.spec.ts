import { expect, test } from './quality-fixture';

test('Config Converter recipes keep canonical order and use an accessible port dialog', async ({ page }) => {
  await page.goto('/fgt-confconv/', { waitUntil: 'networkidle' });

  const firewall = page.getByRole('combobox', { name: 'Firewall' });
  await firewall.click();
  await page.getByRole('option', { name: 'edge.example.test' }).click();
  await expect(page.locator('#cc-backup-info')).toContainText('FortiOS 7.6.1');

  for (const name of [
    'Interface(s) → FortiLink',
    'WAN interface(s) → SD-WAN',
    'Interface-based → zone-based policies',
    'SD-WAN static routes → SD-WAN rules',
  ]) {
    const recipe = page.locator('.cc-recipe').filter({ has: page.getByRole('checkbox', { name }) });
    await expect(recipe).toContainText('Intent');
    await expect(recipe).toContainText('Prerequisites');
    await expect(recipe).toContainText('Expected impact');
  }

  for (const name of [
    'SD-WAN static routes → SD-WAN rules',
    'Interface-based → zone-based policies',
    'WAN interface(s) → SD-WAN',
    'Interface(s) → FortiLink',
  ]) {
    await page.getByRole('checkbox', { name }).check();
  }

  await expect.poll(() => page.locator('#cc-pipeline-preview [data-recipe-key]').evaluateAll(items =>
    items.map(item => item.getAttribute('data-recipe-key')),
  )).toEqual([
    'iface-to-fortilink',
    'wan-to-sdwan',
    'iface-to-zone',
    'sdwan-routes-to-rules',
  ]);

  const addPorts = page.getByRole('button', { name: 'Choose FortiLink ports' });
  await addPorts.click();
  const dialog = page.getByRole('dialog', { name: 'Select FortiLink member ports' });
  await expect(dialog).toBeVisible();
  const search = dialog.getByRole('searchbox', { name: 'Search physical ports' });
  await expect(search).toBeFocused();
  await expect(dialog.getByRole('checkbox')).toHaveCount(4);
  await search.press('Shift+Tab');
  await expect(dialog.getByRole('button', { name: 'Apply selection' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(search).toBeFocused();

  await search.fill('no-such-port');
  await expect(dialog.getByText('No physical ports match this search.')).toBeVisible();
  await search.fill('');
  await expect(dialog.getByRole('checkbox')).toHaveCount(4);
  await search.press('Tab');
  await page.keyboard.press('Space');
  await dialog.getByRole('button', { name: 'Apply selection' }).click();
  await expect(dialog).toBeHidden();
  await expect(addPorts).toBeFocused();
  await expect(page.getByRole('button', { name: /Remove .* from FortiLink selection/ })).toHaveCount(1);

  await addPorts.click();
  await search.fill('wan');
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(addPorts).toBeFocused();

  await expect(page.locator('#cc-primary-impact')).toContainText('Generated CLI changes configuration');
  await expect(page.locator('.cc-primary-action .cc-alpha')).toHaveText('Alpha');

  const duplicateIDs = await page.locator('[id]').evaluateAll(elements => {
    const seen = new Set<string>();
    const duplicates = new Set<string>();
    for (const element of elements) {
      if (seen.has(element.id)) duplicates.add(element.id);
      seen.add(element.id);
    }
    return [...duplicates];
  });
  expect(duplicateIDs).toEqual([]);
});
