import { defineConfig, devices } from "@playwright/test";

// Playwright config for the demo smoke test (tests/demo/). Unlike the main
// playwright.config.ts, it does NOT manage a webServer: the demo stack is
// already running via `docker compose -f docker-compose.demo.yml -f
// docker-compose.demo.build.yml up`, so this config just points the browser at
// the published https://localhost:8088 and runs one read-only journey against
// the live, seeded stack. Used by the nightly demo workflow (demo-nightly.yml)
// to catch main breaking the README's one-command demo.
//
// It deliberately shares nothing with the qa fixtures (fixtures/db.ts resets
// the DB; the demo smoke must NOT touch the seeded data). Keep it self-contained.

const PORT = 8088;

export default defineConfig({
  testDir: "./tests/demo",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  // The demo stack is shared and seeded once; a retry re-runs the read-only
  // journey, which is safe (it mutates nothing).
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `https://localhost:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // The demo stack's cert is the self-signed localhost cert minted by the
    // compose cert-init service, so the browser must tolerate it (same dev-only
    // relaxation as the main config; the demo README tells humans to click
    // through the same warning).
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
