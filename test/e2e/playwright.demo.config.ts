import { defineConfig } from "@playwright/test";
import baseConfig from "./playwright.config";

// Playwright config for the demo smoke test (tests/demo/). It reuses the main
// playwright.config.ts wholesale (same baseURL https://localhost:8088, Chromium
// project, single worker, CI-aware retry/reporter, ignoreHTTPSErrors for the
// self-signed demo cert) and overrides only the two things that differ:
//
//   - testDir points at tests/demo/ instead of the full suite.
//   - webServer is dropped: the demo stack is already running via
//     `docker compose -f docker-compose.demo.yml up`, so this config must NOT
//     auto-start `task dev:server:qa-oidc` (which would race the demo on :8088
//     and point at the qa dex, not the demo dex).
//
// Used by the nightly demo workflow (demo-nightly.yml) to catch main breaking
// the README's one-command demo. Spreading the base config keeps the two in
// lockstep (and avoids duplicating the shared block, Sonar new-code duplication).
export default defineConfig({
  ...baseConfig,
  testDir: "./tests/demo",
  webServer: undefined,
});
