import { Page, test, expect } from "@playwright/test";

// Demo smoke test for the README's one-command, Mac-free demo
// (docker-compose.demo.yml). The nightly demo workflow runs it in two modes:
// `source` (images built from the checkout, so a change on main that breaks the
// demo is caught before it ships) and `released` (the published `latest` images
// a reviewer actually pulls, which can lag main by a release).
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
//
// The host list grew a hostname column after v0.2.1, so the released leg may run
// against an image whose /api/hosts omits hostname and whose UI lists hosts by
// host_id. The hostname assertions are therefore capability-detected: required
// for the source build, skipped (with a host_id fallback) when an older released
// image doesn't expose them. The check auto-tightens once `latest` catches up.

const DEMO_EMAIL = "demo@fleet-edr.local";
const DEMO_PASSWORD = "demo"; // NOSONAR(typescript:S2068): checked-in demo credential, not a secret
const DEMO_HOSTNAMES = ["alex-mbp.local", "ci-builder.local"];
const DETECTION_RULE_IDS = ["credential_keychain_dump", "dns_c2_beacon", "sudoers_tamper", "persistence_launchagent"];

// STRICT_BUILD gates assertions that only hold against the current source tree.
// demo-nightly.yml sets MODE per matrix leg; it is unset for local runs, which
// build from source, so the default is strict.
const STRICT_BUILD = process.env.MODE !== "released";

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

    // API check: the authenticated session (page.request shares the cookie jar)
    // returns the two seeded hosts.
    const hostsResp = await page.request.get("/api/hosts");
    expect(hostsResp.status()).toBe(200);
    const hosts = (await hostsResp.json()) as Array<{ host_id: string; hostname?: string }>;
    expect(hosts).toHaveLength(2);
    for (const host of hosts) {
      expect(host.host_id, "every host row carries a host_id").toBeTruthy();
    }

    // Capability-detect the post-v0.2.1 hostname column (see the file header) by
    // field PRESENCE, not by value: /api/hosts emits the key unconditionally once
    // the column exists, so a present-but-empty hostname is a regression to catch,
    // not a reason to fall back (the UI renders host_id when hostname is empty).
    // The source build must expose it; an older released image is allowed to omit it.
    const supportsHostnameField = hosts.every((host) => "hostname" in host);
    if (STRICT_BUILD) {
      expect(supportsHostnameField, "the source build must expose hostnames on /api/hosts").toBe(true);
    }

    if (supportsHostnameField) {
      // API + UI: the hostnames are populated, match the seeded set, and render in
      // the host list. Empty or incorrect values fail here in both legs rather
      // than silently degrading to the host_id fallback below.
      const hostnames = hosts.map((host) => host.hostname ?? "").sort((a, b) => a.localeCompare(b));
      expect(hostnames).toEqual([...DEMO_HOSTNAMES].sort((a, b) => a.localeCompare(b)));
      for (const hostname of DEMO_HOSTNAMES) {
        await expect(page.getByText(hostname, { exact: true })).toBeVisible({ timeout: 15_000 });
      }
    } else {
      // Older released image: the field is absent and the host list renders rows
      // by host_id. Assert both seeded rows surfaced through the authenticated UI.
      for (const host of hosts) {
        await expect(page.getByText(host.host_id, { exact: true })).toBeVisible({ timeout: 15_000 });
      }
    }

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
