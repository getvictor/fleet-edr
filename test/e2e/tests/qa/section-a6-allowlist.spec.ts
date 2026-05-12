import { test, expect } from "@playwright/test";

// Section A.6: with EDR_BREAKGLASS_IP_ALLOWLIST set to a CIDR the
// test client is NOT in, the break-glass surface returns a generic
// 404 — the path's existence is concealed from off-allowlist
// callers. Run this spec ONLY when the dev server is started with
// EDR_BREAKGLASS_IP_ALLOWLIST=10.99.99.0/24 (or similar off-list
// CIDR). The package.json `qa:a6` script orchestrates the restart.
test.describe("qa: Section A.6 — IP allowlist conceals the surface", () => {
  test("setup URL returns 404 from an off-list IP", async ({ request }) => {
    const resp = await request.get("/admin/break-glass/setup?token=anything");
    expect(resp.status()).toBe(404);
  });

  test("setup challenge POST returns 404 from an off-list IP", async ({ request }) => {
    const resp = await request.post("/admin/break-glass/setup/challenge?token=anything");
    expect(resp.status()).toBe(404);
  });

  test("login challenge POST returns 404 from an off-list IP", async ({ request }) => {
    const resp = await request.post("/admin/break-glass/challenge", {
      headers: { "Content-Type": "application/json" },
      data: { email: "admin@fleet-edr.local" },
    });
    expect(resp.status()).toBe(404);
  });
});
