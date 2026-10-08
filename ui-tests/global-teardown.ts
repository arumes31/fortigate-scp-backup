const fixtureShutdownURL = 'http://127.0.0.1:18901/__fixture/shutdown';

export default async function shutdownFixture(): Promise<void> {
  try {
    await fetch(fixtureShutdownURL, {
      method: 'POST',
      signal: AbortSignal.timeout(2_000),
    });
  } catch {
    // The preview may already have stopped after an early startup or test
    // failure. Playwright reports that original failure; teardown stays best-effort.
  }
}
