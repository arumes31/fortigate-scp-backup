import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

for (const fixture of [
  { path: '/__ux/error/404', status: 404, title: 'Page not found', retry: false },
  { path: '/__ux/error/500', status: 500, title: 'Something went wrong', retry: true },
]) {
  test(`${fixture.status} error recovery page preserves status and actions`, async ({ page }) => {
    const response = await page.goto(fixture.path);
    expect(response?.status()).toBe(fixture.status);
    const errorPanel = page.getByRole('alert');
    await expect(errorPanel).toContainText(fixture.title);
    await expect(page.getByText(`ux-request-${fixture.status}`)).toBeVisible();
    await expect(errorPanel.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('href', '/dashboard');
    await expect(errorPanel.getByRole('link', { name: 'Back' })).toHaveAttribute('href', '/dashboard');
    await expect(page.locator('[data-error-retry]')).toHaveCount(fixture.retry ? 1 : 0);

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();
    expect(results.violations).toEqual([]);
  });
}
