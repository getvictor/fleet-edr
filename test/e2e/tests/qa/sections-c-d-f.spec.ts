import { test, expect, Page, APIRequestContext } from "@playwright/test";
import { openDB } from "../../fixtures/db";
import { rebuildQAState, dexPassword } from "./_setup";

// Manual QA plan sections C (role matrix), D (reauth window), and
// F.4 (audit-events API filters), folded into one spec so the global
// break-glass setup rate-limit only fires once per `npm run qa`.
// Each section is a separate `test()` inside one describe.serial so
// failures show with their section number.

async function signInViaDex(page: Page, email: string) {
  await page.goto("/ui/login");
  await page.getByRole("button", { name: /continue with single sign-on/i }).click();
  await page.waitForURL(/localhost:5556\/dex/);
  await page.locator('input[name="login"]').fill(email);
  await page.locator('input[name="password"]').fill(dexPassword);
  await page.getByRole("button", { name: /login/i }).click();
  await page.waitForURL(
    (url) =>
      url.host === "localhost:8088" &&
      !url.pathname.includes("login") &&
      !url.pathname.includes("break-glass"),
    { timeout: 30_000 },
  );
}

async function fetchCSRF(req: APIRequestContext): Promise<string> {
  const resp = await req.get("/api/session");
  expect(resp.status()).toBe(200);
  const body = (await resp.json()) as { csrf_token: string };
  return body.csrf_token;
}

async function tryIsolate(req: APIRequestContext, csrf: string) {
  return req.post("/api/commands", {
    headers: { "X-Csrf-Token": csrf, "Content-Type": "application/json" },
    data: { host_id: "qa-host-1", command_type: "isolate" },
  });
}

test.describe.serial("qa: Sections C + D + F.4", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    try {
      await rebuildQAState(page);
    } finally {
      await ctx.close();
    }
  });

  test("C.2 analyst is denied host.isolate", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await signInViaDex(page, "analyst@qa.local");
    const csrf = await fetchCSRF(ctx.request);
    const resp = await tryIsolate(ctx.request, csrf);
    expect(resp.status()).toBe(403);
    expect(resp.headers()["x-edr-authz-reason"]).toBe("no_matching_rule");
    await ctx.close();
  });

  test("C.3 senior_analyst is allowed by the chokepoint on host.isolate", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await signInViaDex(page, "senior@qa.local");
    const csrf = await fetchCSRF(ctx.request);
    const resp = await tryIsolate(ctx.request, csrf);
    expect(resp.status()).not.toBe(403);
    expect(resp.headers()["x-edr-authz-reason"]).not.toBe("no_matching_rule");
    await ctx.close();
  });

  test("C.4 auditor cannot isolate but can read audit", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await signInViaDex(page, "auditor@qa.local");
    const csrf = await fetchCSRF(ctx.request);
    const isolateResp = await tryIsolate(ctx.request, csrf);
    expect(isolateResp.status()).toBe(403);
    expect(isolateResp.headers()["x-edr-authz-reason"]).toBe("no_matching_rule");
    const auditResp = await ctx.request.get(
      "/api/audit-events?action=authz.host.isolate&limit=10",
    );
    expect(auditResp.status()).toBe(200);
    const auditBody = (await auditResp.json()) as { items: unknown[] };
    expect(Array.isArray(auditBody.items)).toBe(true);
    await ctx.close();
  });

  test("C.5 super_admin can do everything", async ({ browser }) => {
    const db = await openDB();
    try {
      await db.query(
        `INSERT IGNORE INTO role_bindings (user_id, role_id, tenant_id, scope_type, scope_id)
         SELECT id, 'super_admin', tenant_id, 'tenant', '*' FROM users WHERE email = 'analyst@qa.local'`,
      );
    } finally {
      await db.end();
    }
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await signInViaDex(page, "analyst@qa.local");
    const csrf = await fetchCSRF(ctx.request);
    const isolateResp = await tryIsolate(ctx.request, csrf);
    expect(isolateResp.status()).not.toBe(403);
    const auditResp = await ctx.request.get("/api/audit-events?limit=5");
    expect(auditResp.status()).toBe(200);
    await ctx.close();
  });

  test("C.6 anonymous request to /api/audit-events is denied", async ({ browser }) => {
    const ctx = await browser.newContext();
    const resp = await ctx.request.get("/api/audit-events");
    expect(resp.status()).toBe(401);
    await ctx.close();
  });

  test("D.1+D.2+D.4 reauth gate switches on staleness, host.read ignores it", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await signInViaDex(page, "senior@qa.local");
    const csrf = await fetchCSRF(ctx.request);

    // D.1: fresh.
    const freshResp = await tryIsolate(ctx.request, csrf);
    expect(freshResp.status()).not.toBe(403);

    // Age the session.
    const db = await openDB();
    try {
      const [updated] = await db.query(
        `UPDATE sessions
            SET last_auth_at = NOW(6) - INTERVAL 1 HOUR
          WHERE user_id = (SELECT id FROM users WHERE email = 'senior@qa.local')`,
      );
      const affected = (updated as { affectedRows?: number }).affectedRows ?? 0;
      expect(affected).toBeGreaterThan(0);
    } finally {
      await db.end();
    }

    // D.2: stale denies destructive.
    const staleResp = await tryIsolate(ctx.request, csrf);
    expect(staleResp.status()).toBe(403);
    expect(staleResp.headers()["x-edr-authz-reason"]).toBe("reauth_required");

    // D.4: stale still serves reads.
    const readResp = await ctx.request.get("/api/hosts");
    expect(readResp.status()).toBe(200);
    await ctx.close();
  });

  test("F.4 /api/audit-events filters (action, limit, bad param)", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await signInViaDex(page, "auditor@qa.local");

    const filtered = await ctx.request.get(
      "/api/audit-events?action=authz.host.isolate&limit=20",
    );
    expect(filtered.status()).toBe(200);
    const filteredBody = (await filtered.json()) as {
      items: Array<{ action: string }>;
    };
    expect(Array.isArray(filteredBody.items)).toBe(true);
    for (const ev of filteredBody.items) {
      expect(ev.action).toBe("authz.host.isolate");
    }

    const bad = await ctx.request.get("/api/audit-events?limit=garbage");
    expect(bad.status()).toBe(400);
    await ctx.close();
  });
});
