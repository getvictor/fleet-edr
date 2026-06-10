import { test, expect } from "@playwright/test";

// Brute-force protection on /admin/break-glass/challenge: this test
// BURNS the per-IP rate budget (DefaultPerIPRatePerMin = 10) by
// design, and the refill at 6/min plus the per-IP-keyed bucket means
// subsequent break-glass-touching tests from the same IP will 429
// for several minutes afterward. For that reason this spec lives in
// its own file (run LAST) and is excluded from the consolidated
// default-env QA path. The package.json `qa:rate-limit` script
// invokes it in isolation.
//
// Operators running the full QA matrix should:
//   1. npm run test:all       # auth + default-env qa specs
//   2. env-specific suites: qa:allowlist, qa:jit-off, qa:lifecycle
//   3. npm run qa:rate-limit  # last, since it burns the rate bucket
//
// Or just wait ~3 minutes between this spec and the next QA run for
// the per-IP bucket to refill.
test.describe("break-glass challenge rate limit", () => {
  test("repeated /challenge probes hit 429 + Retry-After", async ({ request }) => {
    let observed429 = false;
    let retryAfter: string | undefined;
    for (let i = 0; i < 25 && !observed429; i++) {
      const resp = await request.post("/admin/break-glass/challenge", {
        headers: { "Content-Type": "application/json" },
        data: { email: "admin@fleet-edr.local" },
      });
      if (resp.status() === 429) {
        observed429 = true;
        retryAfter = resp.headers()["retry-after"];
      }
    }
    expect(observed429).toBe(true);
    expect(retryAfter).toBeDefined();
    // Number("abc") returns NaN, and NaN > 0 is false, so the previous
    // single assertion would fail with "expected NaN to be greater than 0"
    // for any non-numeric Retry-After. Split into "is a number" + "is
    // positive" so the failure message names the actual contract.
    const retrySeconds = Number(retryAfter);
    expect(retrySeconds).not.toBeNaN();
    expect(retrySeconds).toBeGreaterThan(0);
  });
});
