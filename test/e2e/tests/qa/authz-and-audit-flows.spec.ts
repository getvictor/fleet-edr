import { test, expect, APIRequestContext } from "@playwright/test";
import { openDB, promote } from "../../fixtures/db";
import { rebuildQAState, signInViaDex } from "./_setup";

// Post-auth chokepoint + audit flows on the default dev server,
// folded into one spec so the dex JIT-provisioning + role promotions
// only run once. Covers: the role matrix (analyst / senior_analyst /
// auditor / super_admin / anonymous against host.isolate +
// audit-events read), the reauth-window gate (fresh allows / stale
// denies destructive / stale still serves reads), an OIDC state-
// cookie tampering wire check, and the /api/audit-events query
// filters.
//
// None of these flows actually exercise the break-glass admin — they
// all run as dex-provisioned users — so rebuildQAState is called
// WITHOUT withBreakglass, conserving the global break-glass setup
// rate limit (DefaultSetupRatePerMin = 5/min, 2 tokens per ceremony)
// for the other default-env specs that DO need it
// (breakglass-login-failure-reason + reauth-modal-retry).

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

test.describe.serial("RBAC, reauth, and audit flows", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    try {
      await rebuildQAState(page);
    } finally {
      await ctx.close();
    }
  });

  test("analyst is denied host.isolate", async ({ browser }) => {
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

  test("senior_analyst is allowed by the chokepoint on host.isolate", async ({
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

  test("auditor cannot isolate but can read audit", async ({ browser }) => {
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

  test("super_admin can do everything", async ({ browser }) => {
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

  test("anonymous request to /api/audit-events is denied", async ({ browser }) => {
    const ctx = await browser.newContext();
    try {
      const resp = await ctx.request.get("/api/audit-events");
      expect(resp.status()).toBe(401);
    } finally {
      await ctx.close();
    }
  });

  test("tampered OIDC state cookie returns 302 invalid_state + audit row", async ({
    browser,
  }) => {
    // Drive the OIDC handler past the state-validation guard with a
    // tampered edr_oidc_state cookie. Wire contract: 302 with
    // Location containing error=invalid_state, X-Edr-Auth-Reason:
    // invalid_state, audit row auth.oidc.callback.error with
    // payload.reason="oidc.invalid_state".
    //
    // We assert on the 302 location header directly (maxRedirects: 0)
    // rather than following the redirect chain to the SPA, because
    // the server's `/` catchall currently redirects `/login` → `/ui/`
    // and drops the ?error= query string — separate UX defect to file
    // (oidc/handler.go:325 should redirect to /ui/login?error=...).
    // The OIDC handler's own behaviour, which is what this test
    // pins, is correct at the 302.
    const ctx = await browser.newContext();
    try {
      // Step 1: initiate OIDC login to seed the state cookie + grab
      // the state param dex would echo back.
      const loginResp = await ctx.request.get("/api/auth/login", {
        maxRedirects: 0,
      });
      expect(loginResp.status()).toBe(302);
      const dexLocation = loginResp.headers()["location"];
      // Defensive assertion: if a future server bug ever returns a 302
      // with no Location header, .match() would throw "Cannot read
      // properties of undefined" — useless. Surface the actual cause.
      expect(dexLocation).toBeTruthy();
      const stateMatch = dexLocation.match(/[?&]state=([^&]+)/);
      expect(stateMatch).not.toBeNull();
      const originalState = stateMatch![1];

      // The state cookie's Path is "/api/auth/" (see oidc handler.go),
      // so ctx.cookies("https://localhost:8088") with bare "/" filters
      // it out. Pass the cookie's actual scope path so the URL-filter
      // matches; omitting the URL would also work but is less specific.
      // Scheme is https since issue #140 made TLS mandatory.
      const cookies = await ctx.cookies("https://localhost:8088/api/auth/");
      const stateCookie = cookies.find((c) => c.name === "edr_oidc_state");
      expect(stateCookie).toBeDefined();

      // Step 2: tamper the cookie. Replacing the last 4 chars breaks
      // the HMAC signature without disturbing the JSON envelope, so
      // the server reads it, fails signature verification, and emits
      // the directed invalid_state reason.
      const tampered = stateCookie!.value.slice(0, -4) + "XXXX";
      await ctx.clearCookies();
      await ctx.addCookies([{ ...stateCookie!, value: tampered }]);

      // Step 3: hit the callback with the ORIGINAL state param dex
      // would have echoed back, plus the tampered cookie.
      const callbackResp = await ctx.request.get(
        `/api/auth/callback?code=fake-code&state=${originalState}`,
        { maxRedirects: 0 },
      );
      expect(callbackResp.status()).toBe(302);
      expect(callbackResp.headers()["location"]).toContain("error=invalid_state");
      expect(callbackResp.headers()["x-edr-auth-reason"]).toBe("invalid_state");

      // Step 4: audit row.
      const db = await openDB();
      try {
        const [rows] = (await db.query(
          `SELECT JSON_UNQUOTE(JSON_EXTRACT(payload, '$.reason')) AS reason
             FROM audit_events
            WHERE action = 'auth.oidc.callback.error'
            ORDER BY id DESC LIMIT 1`,
        )) as [Array<{ reason: string }>, unknown];
        expect(rows).toHaveLength(1);
        expect(rows[0].reason).toBe("oidc.invalid_state");
      } finally {
        await db.end();
      }
    } finally {
      await ctx.close();
    }
  });

  test("reauth gate: fresh allows, stale denies destructive, stale still serves reads", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      await signInViaDex(page, "senior@qa.local");
      const csrf = await fetchCSRF(ctx.request);

      // Fresh session: the chokepoint allows host.isolate.
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

      // Stale session: destructive action denied with reauth_required.
      const staleResp = await tryIsolate(ctx.request, csrf);
      expect(staleResp.status()).toBe(403);
      expect(staleResp.headers()["x-edr-authz-reason"]).toBe("reauth_required");

      // Stale session: non-destructive reads still succeed.
      const readResp = await ctx.request.get("/api/hosts");
      expect(readResp.status()).toBe(200);
    } finally {
      await ctx.close();
    }
  });

  test("/api/audit-events filters (action, limit, bad param)", async ({
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
      // a regression that returns an empty list. The earlier role-
      // matrix tests (analyst/senior_analyst/auditor against
      // host.isolate) generate authz.host.isolate audit rows, so an
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
