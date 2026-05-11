import { test, expect, APIRequestContext } from "@playwright/test";
import { openDB, promote } from "../../fixtures/db";
import { rebuildQAState, signInViaDex } from "./_setup";

// Manual QA plan sections C (role matrix), D (reauth window), and
// F.4 (audit-events API filters), folded into one spec so the global
// break-glass setup rate-limit only fires once per `npm run qa`.
// Each section is a separate `test()` inside one describe.serial so
// failures show with their section number.

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

// Allowed status codes for the "chokepoint allowed; downstream may
// still reject" branch. The role matrix is about RBAC, not the
// command-insert pipeline, so we accept 201 (full success) plus the
// 400 family that the Insert layer emits for unknown host_ids /
// wave-1 unsupported command_types. Any other status — 500, 502,
// 401, 403 — is a regression the test must catch.
const CHOKEPOINT_ALLOWED_STATUSES = new Set([201, 400]);

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
    try {
      const page = await ctx.newPage();
      await signInViaDex(page, "analyst@qa.local");
      const csrf = await fetchCSRF(ctx.request);
      const resp = await tryIsolate(ctx.request, csrf);
      expect(resp.status()).toBe(403);
      expect(resp.headers()["x-edr-authz-reason"]).toBe("no_matching_rule");
    } finally {
      await ctx.close();
    }
  });

  test("C.3 senior_analyst is allowed by the chokepoint on host.isolate", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      await signInViaDex(page, "senior@qa.local");
      const csrf = await fetchCSRF(ctx.request);
      const resp = await tryIsolate(ctx.request, csrf);
      expect(CHOKEPOINT_ALLOWED_STATUSES.has(resp.status())).toBe(true);
      expect(resp.headers()["x-edr-authz-reason"]).not.toBe("no_matching_rule");
    } finally {
      await ctx.close();
    }
  });

  test("C.4 auditor cannot isolate but can read audit", async ({ browser }) => {
    const ctx = await browser.newContext();
    try {
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
    } finally {
      await ctx.close();
    }
  });

  test("C.5 super_admin can do everything", async ({ browser }) => {
    // Promote analyst@qa.local to super_admin for this test, then
    // roll back so subsequent tests see the user with its baseline
    // analyst role only. Without the rollback the leaked binding
    // would mask a regression in the analyst-tier deny path.
    const setupDB = await openDB();
    try {
      await promote(setupDB, "analyst@qa.local", "super_admin");
    } finally {
      await setupDB.end();
    }
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      await signInViaDex(page, "analyst@qa.local");
      const csrf = await fetchCSRF(ctx.request);
      const isolateResp = await tryIsolate(ctx.request, csrf);
      expect(CHOKEPOINT_ALLOWED_STATUSES.has(isolateResp.status())).toBe(true);
      const auditResp = await ctx.request.get("/api/audit-events?limit=5");
      expect(auditResp.status()).toBe(200);
    } finally {
      await ctx.close();
      const cleanupDB = await openDB();
      try {
        await cleanupDB.query(
          `DELETE FROM role_bindings
            WHERE role_id = 'super_admin'
              AND user_id IN (SELECT id FROM users WHERE email = 'analyst@qa.local')`,
        );
      } finally {
        await cleanupDB.end();
      }
    }
  });

  test("C.6 anonymous request to /api/audit-events is denied", async ({ browser }) => {
    const ctx = await browser.newContext();
    try {
      const resp = await ctx.request.get("/api/audit-events");
      expect(resp.status()).toBe(401);
    } finally {
      await ctx.close();
    }
  });

  test("D.1+D.2+D.4 reauth gate switches on staleness, host.read ignores it", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      await signInViaDex(page, "senior@qa.local");
      const csrf = await fetchCSRF(ctx.request);

      // D.1: fresh.
      const freshResp = await tryIsolate(ctx.request, csrf);
      expect(CHOKEPOINT_ALLOWED_STATUSES.has(freshResp.status())).toBe(true);

      // Age the session beyond DefaultReauthWindow (30m per
      // server/identity/internal/sessions/sessions.go:39). 1 hour
      // gives a 2x safety margin so a tuning bump up to 45m still
      // trips the gate; revisit if the window ever grows past 1h.
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
    } finally {
      await ctx.close();
    }
  });

  test("F.4 /api/audit-events filters (action, limit, bad param)", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
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
      // Without rows the for-loop body never runs, which would mask
      // a regression that returns an empty list. Earlier sections
      // (C.2/C.3/C.4) generate authz.host.isolate audit rows, so an
      // empty result here is itself a failure.
      expect(filteredBody.items.length).toBeGreaterThan(0);
      for (const ev of filteredBody.items) {
        expect(ev.action).toBe("authz.host.isolate");
      }

      const bad = await ctx.request.get("/api/audit-events?limit=garbage");
      expect(bad.status()).toBe(400);
    } finally {
      await ctx.close();
    }
  });
});
