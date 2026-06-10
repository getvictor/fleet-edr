// Shared Playwright `test` import that opts into E2E coverage when
// E2E_COVERAGE=1 is set in the environment. Specs import `test` and
// `expect` from this file instead of from "@playwright/test" so the
// V8 JS coverage profile lands automatically on every test that uses
// the default `page` fixture.
//
// Specs that build their own browser contexts via
// `browser.newContext().newPage()` (most of tests/qa/*.spec.ts) get
// captured only for the FIRST page in each test: page.coverage is
// per-page, and the fixture only wraps the default `page`. Those
// specs primarily drive page.request anyway (no UI lines to cover),
// so the gap is operationally small; if it grows, the right fix is
// the `createCoveredPage` helper below.
//
// Output: each test writes a JSON file to test/e2e/coverage-raw/
// containing the page.coverage.stopJSCoverage() payload. After all
// tests, `node scripts/coverage-to-lcov.mjs` merges them into
// test/e2e/coverage/lcov-e2e.info (LCOV format, source-map remapped
// back to ui/src via monocart-coverage-reports). Sonar reads that
// path via sonar.javascript.lcov.reportPaths.

import { test as base, BrowserContext, Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const COVERAGE_DIR = join(__dirname, "..", "coverage-raw");

function coverageEnabled(): boolean {
  return process.env.E2E_COVERAGE === "1";
}

async function startCoverage(page: Page): Promise<void> {
  if (!coverageEnabled()) return;
  await page.coverage.startJSCoverage({ resetOnNavigation: false });
}

async function dumpCoverage(page: Page, testId: string): Promise<void> {
  if (!coverageEnabled()) return;
  let entries: Awaited<ReturnType<typeof page.coverage.stopJSCoverage>>;
  try {
    entries = await page.coverage.stopJSCoverage();
  } catch {
    // Page may already be closed; coverage was discarded with the
    // context. Not a failure of the test under test.
    return;
  }
  await mkdir(COVERAGE_DIR, { recursive: true });
  // randomUUID() rather than Math.random: the filename only needs to
  // be unique across concurrent test executions, but Math.random
  // trips Sonar's typescript:S2245 (pseudorandom for security-
  // sensitive use); crypto-grade randomness is the right primitive
  // for "unique tag" semantics regardless.
  const slug = `${testId}-${Date.now()}-${randomUUID()}`;
  await writeFile(join(COVERAGE_DIR, `${slug}.json`), JSON.stringify(entries));
}

export const test = base.extend<{ page: Page }>({
  page: async ({ page }, use, testInfo) => {
    await startCoverage(page);
    await use(page);
    await dumpCoverage(page, testInfo.testId);
  },
});

// createCoveredPage spawns a page off the given BrowserContext with
// V8 coverage capture wired up the same way the default `page`
// fixture has it. Specs that need a fresh context per test should
// use this instead of `ctx.newPage()` so their UI lines also feed
// the LCOV. The returned cleanup function MUST be called before
// `ctx.close()` so the coverage payload is flushed before the page
// disappears.
export async function createCoveredPage(
  ctx: BrowserContext,
  testId: string,
): Promise<{ page: Page; flush: () => Promise<void> }> {
  const page = await ctx.newPage();
  await startCoverage(page);
  return {
    page,
    flush: () => dumpCoverage(page, testId),
  };
}

export { expect } from "@playwright/test";
