import AxeBuilder from '@axe-core/playwright';

import { expect, test } from './quality-fixture';

test.setTimeout(90_000);

const routes = [
  '/login',
  '/dashboard?scenario=warning',
  '/?scenario=empty',
  '/search',
  '/audit',
  '/licenses',
  '/ipam?scenario=full',
  '/topology',
  '/activity_log?q=deep-synthetic-match&user=automation&action=Configuration&from=2026-09-01&to=2026-09-02',
  '/backups/7',
  '/backups/7/compare?backup=1&backup=2',
  '/fgt-adm-vpn-conf/',
  '/fgt-confgen/',
  '/fgt-polsplit/',
  '/fgt-confconv/',
  '/fgt-conftail/?scenario=warning',
  '/fgt-conftail/chain/fixture-chain',
  '/__ux/primitives',
];

test('primary pages have no unwaived WCAG A or AA findings', async ({ page }) => {
  const violations: Array<{ route: string; rule: string; targets: string[] }> = [];
  for (const route of routes) {
    await test.step(route, async () => {
      await page.goto(route, { waitUntil: 'networkidle' });
      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
        .analyze();
      violations.push(...results.violations.map(violation => ({
        route,
        rule: violation.id,
        targets: violation.nodes.map(node => node.target.join(' ')),
      })));
    });
  }
  expect(violations, 'unwaived axe violations').toEqual([]);
});
