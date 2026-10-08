import { defineConfig } from '@playwright/test';

const baseURL = process.env.FORTISAFE_STAGING_BASE_URL || 'http://127.0.0.1:18521';

export default defineConfig({
  testDir: './tests',
  testMatch: 'full-app-smoke.spec.ts',
  outputDir: 'staging-test-results',
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'staging-playwright-report' }],
  ],
  use: {
    baseURL,
    browserName: 'chromium',
    headless: true,
    locale: 'en-US',
    timezoneId: 'UTC',
    reducedMotion: 'reduce',
    colorScheme: 'dark',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
