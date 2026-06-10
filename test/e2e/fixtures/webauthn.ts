import { Page, CDPSession } from "@playwright/test";

// WebAuthn virtual-authenticator helper for Playwright tests. The
// browser's CDP exposes `WebAuthn.enable` + `WebAuthn.addVirtualAuthenticator`;
// after a virtual authenticator is installed, every
// `navigator.credentials.create()` and `.get()` call on the attached
// page goes through it instead of real hardware (Touch ID, YubiKey).
//
// This is the industry-standard pattern. GitHub, Cloudflare, Twilio,
// Auth0, and every other WebAuthn-aware product test their flows
// this way. The chrome:// WebAuthn DevTools panel does the same
// thing under the hood.
//
// Important: Playwright's CDP session is per-page; if the test
// navigates to a new origin or reloads, the virtual authenticator
// is preserved as long as the browser context (not the page) stays.
// Tests that span multiple page loads share one VirtualAuthenticator
// instance, which is exactly the shape WebAuthn registration -> login
// needs (the credential registered in step 1 must be findable in
// step 2).

export interface VirtualAuthenticator {
  client: CDPSession;
  authenticatorId: string;
}

// Install a virtual authenticator on the given page. Defaults match
// what a macOS Touch ID Passkey reports at the protocol level (ctap2,
// internal transport, resident-key + user-verification both true).
// automaticPresenceSimulation=true means the authenticator answers
// every challenge without simulating a fingerprint prompt, so tests
// stay deterministic.
export async function installVirtualAuthenticator(
  page: Page,
): Promise<VirtualAuthenticator> {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable", { enableUI: false });
  const result = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { client, authenticatorId: result.authenticatorId };
}

// Remove the virtual authenticator. Called in afterEach so a test
// that registers a credential doesn't leak it to the next test (each
// test resets the DB separately, so the WebAuthn-side state has to
// match).
export async function uninstallVirtualAuthenticator(
  va: VirtualAuthenticator,
): Promise<void> {
  await va.client.send("WebAuthn.removeVirtualAuthenticator", {
    authenticatorId: va.authenticatorId,
  });
  await va.client.send("WebAuthn.disable");
  await va.client.detach();
}
