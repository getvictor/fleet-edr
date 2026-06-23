import { Page, test, expect } from "@playwright/test";

// Demo smoke test for the README's one-command, Mac-free demo
// (docker-compose.demo.yml). Run by the nightly demo workflow against a stack
// built from the current source so a change on main that breaks the demo is
// caught before a reviewer hits it.
//
// It does NOT reset or seed the database: the compose seeder already replayed
// the curated corpus through the real ingest + detection pipeline before this
// runs. This spec only signs in as the bundled demo SSO user and asserts the
// seeded data surfaces through both the UI and the operator API.
//
// The expected shape is fixed by server/cmd/fleet-edr-demo-seed/hosts.go:
//   - two hosts: alex-mbp.local, ci-builder.local
//   - four detection-source alerts: credential_keychain_dump, dns_c2_beacon,
//     sudoers_tamper, persistence_launchagent
//   - one application_control-source alert (the app-control block)

const DEMO_EMAIL = "demo@fleet-edr.local";
const DEMO_PASSWORD = "demo"; // NOSONAR(typescript:S2068): checked-in demo credential, not a secret
const DEMO_HOSTNAMES = ["alex-mbp.local", "ci-builder.local"];
const DETECTION_RULE_IDS = ["credential_keychain_dump", "dns_c2_beacon", "sudoers_tamper", "persistence_launchagent"];

// signInViaDex runs the dex SSO ceremony for the single demo account. Mirrors
// the qa oidc-login helper but with the demo credentials and the demo issuer
// host (dex.demo.localhost, which the browser resolves to loopback per RFC
// 6761 and reaches via the published :5556 port).
async function signInViaDex(page: Page): Promise<void> {
  await page.goto("/ui/login");
  await page.getByRole("button", { name: /continue with single sign-on/i }).click();
  await page.waitForURL(/:5556\/dex/);

  // Dex's login form labels aren't <label for="...">-associated, so address the
  // inputs by name. On a match dex 302s back to /api/auth/callback?code=...
  await page.locator('input[name="login"]').fill(DEMO_EMAIL);
  await page.locator('input[name="password"]').fill(DEMO_PASSWORD);
  await page.getByRole("button", { name: /login/i }).click();

  // The EDR exchanges the code, mints a session, and redirects to /ui/.
  await page.waitForURL(
    (url) => url.host === "localhost:8088" && !url.pathname.includes("login") && !url.pathname.includes("break-glass"),
    { timeout: 30_000 },
  );
}

test.describe("demo stack smoke", () => {
  test("demo SSO user signs in and sees the seeded hosts + alerts", async ({ page }) => {
    await signInViaDex(page);

    // UI check: the home view (HostList) renders both seeded hosts.
    for (const hostname of DEMO_HOSTNAMES) {
      await expect(page.getByText(hostname, { exact: true })).toBeVisible({ timeout: 15_000 });
    }

    // API check: the authenticated session (page.request shares the cookie jar)
    // returns the seeded hosts.
    const hostsResp = await page.request.get("/api/hosts");
    expect(hostsResp.status()).toBe(200);
    const hosts = (await hostsResp.json()) as Array<{ host_id: string; hostname: string }>;
    expect(hosts).toHaveLength(2);
    const hostnames = hosts.map((h) => h.hostname).sort();
    expect(hostnames).toEqual([...DEMO_HOSTNAMES].sort());

    // API check: alerts carry both a detection-source set (the four woven
    // ATT&CK detections) and the application_control block.
    const alertsResp = await page.request.get("/api/alerts");
    expect(alertsResp.status()).toBe(200);
    const alerts = (await alertsResp.json()) as Array<{ source: string; rule_id: string }>;

    const sources = new Set(alerts.map((a) => a.source));
    expect(sources).toContain("detection");
    expect(sources).toContain("application_control");

    const ruleIDs = new Set(alerts.map((a) => a.rule_id));
    for (const ruleID of DETECTION_RULE_IDS) {
      expect(ruleIDs, `expected a fired alert for rule ${ruleID}`).toContain(ruleID);
    }
  });
});
