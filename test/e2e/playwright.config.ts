import { defineConfig, devices } from "@playwright/test";

// Playwright config for the EDR's E2E suite.
//
// `webServer.command` boots the dev server pointed at the local dex
// (started via `task qa:up`) so both break-glass (WebAuthn + virtual
// authenticator) and OIDC tests run against one process. The
// reuseExistingServer flag lets an operator iterate on tests against
// a server they started manually (`task dev:server:qa-oidc`) without
// each `playwright test` invocation racing a port-bind.
//
// Each test resets its own DB state via fixtures/db.ts so tests stay
// independent (Playwright can shuffle them in any order on retries
// or parallel workers).

const PORT = 8088;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false, // tests share one DB; serial keeps the fixtures honest
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // shared DB; one worker
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // Allow Secure cookies on localhost HTTP (the EDR's session +
    // OIDC state cookies set Secure; Chrome treats localhost as a
    // secure origin so this Just Works in practice, but spelling it
    // out keeps the intent obvious).
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    // Boot the dev server with OIDC pointed at the local dex. Both
    // break-glass and OIDC flows route through this one instance.
    // Probe /readyz instead of /livez: the spec + docs/install-server.md
    // + docs/operations.md treat /readyz as the readiness signal
    // (returns 200 when the DB ping succeeds). /livez only proves
    // the process is up; tests that hit DB-backed endpoints need
    // the readiness guarantee.
    command: "cd ../.. && task dev:server:qa-oidc",
    url: `http://localhost:${PORT}/readyz`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    stderr: "pipe",
    stdout: "pipe",
  },
});
