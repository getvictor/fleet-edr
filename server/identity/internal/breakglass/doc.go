// Package breakglass implements the hardened admin-recovery login
// surface introduced in Phase 4b of the user-management work. The
// surface is the only path back into the system when OIDC is broken,
// so it has to be both reachable (no transitive OIDC dependency) and
// defensible (it does not leak its own existence to off-allowlist
// scanners, requires a hardware authenticator, and rate-limits every
// distinguishable bucket).
//
// Three pieces compose the wave-1 surface:
//
//  1. **Bootstrap token redemption** — first-boot prints a one-shot
//     redemption URL (not a plaintext password) to stderr. The
//     operator visits the URL within the configured TTL, sets a
//     password (length-only ≥ 12 — see decision D in the Phase 4
//     plan: WebAuthn carries the cryptographic factor; the password
//     is the shoulder-surf gate), and registers a WebAuthn
//     credential. All three writes (token consume + password set +
//     credential persist) commit in a single transaction so a
//     partial failure leaves the token reusable.
//
//  2. **Login** — `/admin/break-glass` requires both a correct
//     password AND a successful WebAuthn assertion against a
//     registered credential. WebAuthn's challenge round-trips
//     through a signature-protected cookie so the flow survives
//     between the GET (challenge issued) and POST (assertion
//     submitted) without a server-side session table.
//
//  3. **Surface protection** — an optional CIDR allowlist returns
//     a generic 404 to off-list callers (`/admin/break-glass`
//     existence is not acknowledged); per-IP, per-email, and
//     setup-bucket rate limits are stricter than the SSO login
//     limits because brute force attempts here matter more.
//
// What this package deliberately does NOT do:
//
//   - No zxcvbn entropy gate. The 1MB dictionary dependency adds
//     marginal security on an MFA-protected account; CIS guidance
//     for MFA-protected accounts is 8+ chars and we land at 12.
//     Wave-2 polish if operators ask for it.
//   - No TOTP/SMS fallback. Recovery is admin-driven token reissue
//     per the operator runbook; phishing-resistant MFA mandate
//     follows Google Workspace, AWS root, Okta privileged-role
//     patterns.
//   - No multi-credential prompt at bootstrap. Operators may
//     register additional credentials through the wave-2 admin UI.
package breakglass
