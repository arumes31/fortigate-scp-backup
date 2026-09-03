import { expect, test as base } from '@playwright/test';

const fixtureOrigin = 'http://127.0.0.1:18901';
const fixedTime = new Date('2026-09-02T10:30:00Z');

type BrowserQuality = {
  browserQuality: void;
};

export const test = base.extend<BrowserQuality>({
  browserQuality: [async ({ context, page }, use) => {
    const consoleProblems: string[] = [];
    const pageErrors: string[] = [];
    const failedResponses: string[] = [];
    const externalRequests: string[] = [];

    page.on('console', message => {
      if (message.type() === 'error' || message.type() === 'warning') {
        // Chromium emits this driver diagnostic when axe samples canvas pixels
        // for contrast; it is neither page JavaScript nor an application warning.
        if (/^\[\.WebGL-.*\]GL Driver Message .*GPU stall due to ReadPixels/.test(message.text())) {
          return;
        }
        // Navigating away from the synthetic topology page intentionally
        // destroys its renderer. Chromium reports that normal teardown as a
        // WebGL warning while the multi-route axe test moves to the next page.
        if (message.text() === 'WebGL: CONTEXT_LOST_WEBGL: loseContext: context lost') {
          return;
        }
        consoleProblems.push(`${message.type()}: ${message.text()}`);
      }
    });
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('response', response => {
      if (response.status() >= 400) {
        failedResponses.push(`${response.status()} ${response.url()}`);
      }
    });
    await context.route('**/*', async route => {
      const requestURL = new URL(route.request().url());
      if (requestURL.origin !== fixtureOrigin) {
        externalRequests.push(route.request().url());
        await route.abort('blockedbyclient');
        return;
      }
      await route.continue();
    });
    await page.clock.setFixedTime(fixedTime);

    await use();

    expect(externalRequests, 'browser made external requests').toEqual([]);
    expect(failedResponses, 'browser received failing HTTP responses').toEqual([]);
    expect(pageErrors, 'page emitted uncaught errors').toEqual([]);
    expect(consoleProblems, 'page emitted console errors or warnings').toEqual([]);
  }, { auto: true }],
});

export { expect } from '@playwright/test';
