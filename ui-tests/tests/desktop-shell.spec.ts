import { expect, test } from './quality-fixture';

const shellCases = [
  {
    name: 'English',
    path: '/dashboard?scenario=warning',
    lang: 'en',
    groups: ['Overview', 'Network data', 'Tools'],
    utilities: 'Utilities',
    pressedLanguage: 'EN',
  },
  {
    name: 'German',
    path: '/__ux/shell/de?scenario=warning',
    lang: 'de',
    groups: ['Übersicht', 'Netzwerkdaten', 'Werkzeuge'],
    utilities: 'Hilfsfunktionen',
    pressedLanguage: 'DE',
  },
];

for (const shellCase of shellCases) {
  test(`${shellCase.name} desktop shell stays labeled and non-wrapping`, async ({ page }) => {
    await page.goto(shellCase.path, { waitUntil: 'networkidle' });

    await expect(page.locator('html')).toHaveAttribute('lang', shellCase.lang);
    const rail = page.locator('.app-rail');
    await expect(rail).toBeVisible();
    await expect(rail.locator('.nav-group > h2')).toHaveText(shellCase.groups);
    await expect(rail.getByRole('region', { name: shellCase.utilities })).toBeVisible();
    await expect(rail.locator('[aria-current="page"]')).toHaveCount(1);
    await expect(rail.getByRole('button', { name: shellCase.pressedLanguage, exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.hamburger, [aria-label*="menu" i], [aria-label*="menü" i]')).toHaveCount(0);

    const layout = await page.evaluate(() => {
      const rail = document.querySelector<HTMLElement>('.app-rail')!;
      const main = document.querySelector<HTMLElement>('#main-content')!;
      const railBox = rail.getBoundingClientRect();
      const mainBox = main.getBoundingClientRect();
      return {
        viewportWidth: document.documentElement.clientWidth,
        documentWidth: document.documentElement.scrollWidth,
        railLeft: railBox.left,
        railRight: railBox.right,
        railHeight: railBox.height,
        mainLeft: mainBox.left,
        bodyTransform: getComputedStyle(document.body).textTransform,
      };
    });
    expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.railLeft).toBe(0);
    expect(layout.railHeight).toBeGreaterThanOrEqual(page.viewportSize()!.height);
    expect(layout.mainLeft).toBeGreaterThanOrEqual(layout.railRight);
    expect(layout.bodyTransform).toBe('none');
  });
}

test('semantic visual tokens remain distinct and meet contrast contracts', async ({ page }) => {
  await page.goto('/dashboard?scenario=warning', { waitUntil: 'networkidle' });
  await page.keyboard.press('Tab');
  await expect(page.locator('.skip-link')).toBeFocused();
  const result = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    const tokenNames = ['--brand', '--action', '--danger', '--warning', '--success', '--info', '--focus'] as const;
    const tokens = Object.fromEntries(tokenNames.map(name => [name, root.getPropertyValue(name).trim()]));
    const background = root.getPropertyValue('--surface').trim();

    function rgb(value: string): [number, number, number] {
      const probe = document.createElement('span');
      probe.style.color = value;
      document.body.appendChild(probe);
      const match = getComputedStyle(probe).color.match(/[\d.]+/g)!.map(Number);
      probe.remove();
      return [match[0], match[1], match[2]];
    }
    function luminance(value: string): number {
      const channels = rgb(value).map(channel => {
        const normalized = channel / 255;
        return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
    }
    function contrast(foreground: string, backdrop: string): number {
      const light = Math.max(luminance(foreground), luminance(backdrop));
      const dark = Math.min(luminance(foreground), luminance(backdrop));
      return (light + 0.05) / (dark + 0.05);
    }
    return {
      tokens,
      contrasts: Object.fromEntries(tokenNames.map(name => [name, contrast(tokens[name], background)])),
      tableTextTransform: getComputedStyle(document.querySelector('table.data td')!).textTransform,
      controlHeight: document.querySelector<HTMLSelectElement>('#refreshInterval')!.getBoundingClientRect().height,
      focusOutline: {
        style: getComputedStyle(document.activeElement!).outlineStyle,
        width: parseFloat(getComputedStyle(document.activeElement!).outlineWidth),
        color: getComputedStyle(document.activeElement!).outlineColor,
      },
    };
  });

  expect(new Set(Object.values(result.tokens)).size).toBe(Object.keys(result.tokens).length);
  for (const [token, ratio] of Object.entries(result.contrasts)) {
    expect(ratio, `${token} contrast`).toBeGreaterThanOrEqual(token === '--focus' ? 3 : 4.5);
  }
  expect(result.tableTextTransform).toBe('none');
  expect(result.controlHeight).toBeGreaterThanOrEqual(34);
  expect(result.focusOutline.style).toBe('solid');
  expect(result.focusOutline.width).toBeGreaterThanOrEqual(2);
  expect(result.focusOutline.color).toBe('rgb(255, 224, 138)');
});
