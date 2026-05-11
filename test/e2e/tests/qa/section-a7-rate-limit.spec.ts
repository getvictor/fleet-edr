import { test, expect } from "@playwright/test";

// Section A.7: brute-force protection. This test BURNS the per-IP
// rate budget (DefaultPerIPRatePerMin = 10) by design, and the
// refill at 6/min plus the per-IP-keyed bucket means subsequent
// break-glass-touching tests from the same IP will 429 for several
// minutes afterward. For that reason A.7 lives in its own spec
// (run LAST) and is excluded from the consolidated `npm run qa`
// path. The package.json `qa:a7` script invokes this in isolation.
//
// Operators running the full QA matrix should:
//   1. npm run test:all      # auth + qa (default-env sections)
//   2. (env-specific suites: qa:a6, qa:b3, qa:e — see Quick gate doc)
//   3. npm run qa:a7         # last, since it burns the rate bucket
//
// Or just wait ~3 minutes between A.7 and the next QA run for the
// per-IP bucket to refill.
test.describe("qa: Section A.7 — brute-force rate limit", () => {
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
    expect(Number(retryAfter)).toBeGreaterThan(0);
  });
});
