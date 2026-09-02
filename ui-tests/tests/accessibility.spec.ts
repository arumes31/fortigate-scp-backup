import AxeBuilder from '@axe-core/playwright';

import { expect, test } from './quality-fixture';

const routes = [
  '/login',
  '/dashboard?scenario=warning',
  '/?scenario=empty',
  '/audit',
  '/topology',
  '/fgt-adm-vpn-conf/',
  '/fgt-confgen/',
  '/fgt-polsplit/',
  '/fgt-confconv/',
  '/fgt-conftail/?scenario=warning',
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
