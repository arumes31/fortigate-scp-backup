import { longContent } from '../fixtures/long-content';
import { expect, test } from './quality-fixture';

test.setTimeout(180_000);

type RouteContract = {
  path: string;
  english: string;
  german: string;
  shell?: boolean;
  forbiddenGerman?: string[];
};

const routes: RouteContract[] = [
  { path: '/login', english: 'Login', german: 'Anmelden', shell: false },
  { path: '/dashboard?scenario=warning', english: 'Dashboard', german: 'Dashboard' },
  { path: '/?scenario=full', english: 'Firewalls', german: 'Firewalls' },
  { path: '/search', english: 'Search Configurations', german: 'Konfigurationen durchsuchen', forbiddenGerman: ['Search Configurations', 'Search Results'] },
  { path: '/audit', english: 'Audit & Compliance Insights', german: 'Audit & Compliance Insights' },
  { path: '/licenses', english: 'License Inventory', german: 'Lizenz-Inventar', forbiddenGerman: ['License Inventory', 'Renewal date'] },
  { path: '/ipam?scenario=full', english: 'Fleet IPAM', german: 'Flotten-IPAM' },
  { path: '/topology', english: 'Network topology', german: 'Netzwerk-Topologie' },
  { path: '/activity_log', english: 'Activity Log', german: 'Aktivitätsprotokoll', forbiddenGerman: ['Activity Log', 'Filter by action'] },
  { path: '/errors?scenario=error', english: 'Backup Errors', german: 'Backup-Fehler', forbiddenGerman: ['Backup Errors', 'Failure reason'] },
  { path: '/backups/7', english: 'Backups · edge.example.test #7', german: 'Backups · edge.example.test #7' },
  { path: '/backups/7/compare?backup=1&backup=2', english: 'Compare backups · edge.example.test #7', german: 'Backups vergleichen · edge.example.test #7' },
  { path: '/change_password', english: 'Change Password', german: 'Passwort ändern', forbiddenGerman: ['Change Password', 'Current Password'] },
  { path: '/fgt-adm-vpn-conf/', english: 'FGT ADM VPN Config', german: 'FGT ADM VPN-Konfiguration', forbiddenGerman: ['Add new entry', 'Fleet entries', 'Select an entry'] },
  { path: '/fgt-confgen/', english: 'FortiGate Policy Generator', german: 'FortiGate-Richtliniengenerator', forbiddenGerman: ['Target context', 'Policy Configuration', 'Validation & output'] },
  { path: '/fgt-polsplit/', english: 'FortiGate Policy Split Advisor', german: longContent.germanHeading, forbiddenGerman: ['Target Policy', 'Analysis Window & Options', 'Options to apply'] },
  { path: '/fgt-confconv/', english: 'Configuration Conversions', german: 'Konfigurationskonvertierung', forbiddenGerman: ['Conversion recipes', 'Generate conversion', 'Impact review'] },
  { path: '/fgt-conftail/?scenario=warning', english: 'Configuration Change Tail', german: 'Konfigurationsänderungen', forbiddenGerman: ['Timeline filters', 'Global ignore rules', 'Active change sessions'] },
  { path: '/fgt-conftail/chain/fixture-chain', english: 'Complete Redacted Timeline', german: 'Vollständiger geschwärzter Verlauf', forbiddenGerman: ['Session facts', 'Ordered changes', 'Confirm global ignore'] },
];

function localizedPath(path: string, lang: 'en' | 'de'): string {
  const url = new URL(path, 'http://fixture.invalid');
  url.searchParams.set('lang', lang);
  return `${url.pathname}${url.search}${url.hash}`;
}

for (const lang of ['en', 'de'] as const) {
  test(`all primary routes satisfy the ${lang.toUpperCase()} semantic contract`, async ({ page }) => {
    for (const route of routes) {
      await test.step(route.path, async () => {
        await page.goto(localizedPath(route.path, lang), { waitUntil: 'networkidle' });

        await expect.soft(page.locator('html')).toHaveAttribute('lang', lang);
        const headings = page.locator('h1:visible');
        await expect.soft(headings).toHaveCount(1);
        await expect.soft(headings).toHaveText(lang === 'de' ? route.german : route.english);

        if (route.shell !== false) {
          await expect.soft(page.locator('.app-rail [aria-current="page"]')).toHaveCount(1);
        }

        if (lang === 'de') {
          const visibleText = await page.locator('body').innerText();
          for (const untranslated of route.forbiddenGerman || []) {
            expect.soft(visibleText, `untranslated German-page text: ${untranslated}`).not.toContain(untranslated);
          }
        }

        const duplicateIDs = await page.locator('[id]').evaluateAll(elements => {
          const counts = new Map<string, number>();
          for (const element of elements) {
            counts.set(element.id, (counts.get(element.id) || 0) + 1);
          }
          return [...counts.entries()].filter(([, count]) => count > 1);
        });
        expect.soft(duplicateIDs, 'duplicate element IDs').toEqual([]);

        const invalidTimes = await page.locator('time:visible').evaluateAll(elements => elements
          .map(element => element.getAttribute('datetime') || '')
          .filter(value => !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)));
        expect.soft(invalidTimes, 'visible times without an RFC3339 datetime').toEqual([]);

        const viewportOverflow = await page.evaluate(() => ({
          documentWidth: document.documentElement.scrollWidth,
          viewportWidth: document.documentElement.clientWidth,
        }));
        expect.soft(viewportOverflow.documentWidth, 'long content caused horizontal page overflow')
          .toBeLessThanOrEqual(viewportOverflow.viewportWidth + 1);
      });
    }
  });
}

test('long synthetic content remains visible and contained', async ({ page }) => {
  await page.goto('/fgt-adm-vpn-conf/?lang=de', { waitUntil: 'networkidle' });
  await expect(page.getByText(longContent.fqdn, { exact: true }).first()).toBeVisible();

  await page.goto('/fgt-conftail/?scenario=error&lang=de', { waitUntil: 'networkidle' });
  await expect(page.getByText(new RegExp(longContent.diagnostic)).first()).toBeVisible();
  const dimensions = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: document.documentElement.clientWidth,
  }));
  expect(dimensions.documentWidth).toBeLessThanOrEqual(dimensions.viewportWidth + 1);
});
