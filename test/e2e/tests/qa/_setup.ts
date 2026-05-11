import { Page, expect } from "@playwright/test";
import { openDB, resetDB, mintBootstrapToken, promote } from "../../fixtures/db";
import {
  installVirtualAuthenticator,
  uninstallVirtualAuthenticator,
  VirtualAuthenticator,
} from "../../fixtures/webauthn";

export const dexPassword = "qa-password-123";

// signInViaDex drives the OIDC ceremony through the local dex IdP.
// Shared between rebuildQAState (which JIT-provisions every dex user
// upfront) and the section specs that sign in per-role; centralising
// the selectors here means a dex template tweak only needs one edit.
export async function signInViaDex(page: Page, email: string): Promise<void> {
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

// QA helper: rebuild the user-management state the manual sections
// assume. Drops every operator-side row except the seeded admin,
// re-registers the admin's break-glass credential, JIT-provisions the
// three dex users (analyst/senior/auditor), then promotes them via
// SQL so the role matrix runs as documented.
//
// Operators reading the QA plan can call `npm run qa` and trust this
// helper to set up state from any prior state. Without it, the QA
// specs depend on an exact sequence of prior tests, which is brittle.
export async function rebuildQAState(page: Page): Promise<void> {
  const db = await openDB();
  try {
    await resetDB(db);
  } finally {
    await db.end();
  }

  // Re-register the seeded admin's break-glass credential. The QA
  // pass needs at least one working webauthn credential for the
  // admin so audit + recovery flows have a row to read.
  let va: VirtualAuthenticator | undefined;
  try {
    va = await installVirtualAuthenticator(page);
    const tokenDB = await openDB();
    let plaintext: string;
    try {
      plaintext = await mintBootstrapToken(tokenDB);
    } finally {
      await tokenDB.end();
    }
    await page.goto(`/admin/break-glass/setup?token=${plaintext}`);
    await page.getByLabel(/password/i).fill("qa-redeem-password-12-chars");
    await page.getByRole("button", { name: /register security key/i }).click();
    // Assert the page lands at the signed-in dashboard. A redirect
    // to /ui/ (or /ui/hosts via the router) means the ceremony fully
    // succeeded; checking for absence of /break-glass/setup alone is
    // too weak — an error page might also leave that path while
    // failing the user-visible flow.
    await page.waitForURL(
      (url) =>
        url.host === "localhost:8088" &&
        !url.pathname.includes("break-glass") &&
        !url.pathname.includes("login"),
      { timeout: 15_000 },
    );
    expect(page.url()).toMatch(/\/ui(\/|$|\?)/);
  } finally {
    if (va) await uninstallVirtualAuthenticator(va);
  }

  await page.request.delete("/api/session");

  // JIT-provision the three dex users by signing them in once.
  for (const email of ["analyst@qa.local", "senior@qa.local", "auditor@qa.local"]) {
    await signInViaDex(page, email);
    await page.request.delete("/api/session");
  }

  // Promote senior + auditor.
  const promoteDB = await openDB();
  try {
    await promote(promoteDB, "senior@qa.local", "senior_analyst");
    await promote(promoteDB, "auditor@qa.local", "auditor");
  } finally {
    await promoteDB.end();
  }
}
