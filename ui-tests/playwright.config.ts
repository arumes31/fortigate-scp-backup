import { defineConfig } from '@playwright/test';

const fixtureOrigin = 'http://127.0.0.1:18901';

export default defineConfig({
  testDir: './tests',
  outputDir: 'test-results',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : 2,
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report' }],
  ],
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: fixtureOrigin,
    browserName: 'chromium',
    headless: true,
    locale: 'en-US',
    timezoneId: 'UTC',
    reducedMotion: 'reduce',
    colorScheme: 'dark',
    serviceWorkers: 'block',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'off',
  },
  projects: [
    { name: 'desktop-1024', use: { viewport: { width: 1024, height: 768 } } },
    { name: 'desktop-1440', use: { viewport: { width: 1440, height: 900 } } },
    { name: 'desktop-1920', use: { viewport: { width: 1920, height: 1080 } } },
  ],
  webServer: {
    command: 'go test ../internal/web -run TestUXAuditPreview -count=1 -v',
    cwd: '.',
    env: {
      FORTISAFE_UX_FIXTURE: '1',
      FORTISAFE_UX_FIXTURE_ADDRESS: '127.0.0.1:18901',
    },
    url: `${fixtureOrigin}/readyz`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
