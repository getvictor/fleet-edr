# UI redirects to login when a session expires mid-use: tasks

## 1. API layer

- [x] `api.ts`: add `unauthorizedHandler` module state + `setUnauthorizedHandler(handler | null)` setter, mirroring the existing `setForbiddenHandler`.
- [x] `api.ts`: add a `raiseUnauthorized` chokepoint (clear CSRF, fire handler, throw `Unauthorized401Error`) and funnel both 401 throw sites (`fetchJSON`, `appControlMutationEndpoint`) through it.

## 2. App wiring

- [x] `App.tsx`: import `setUnauthorizedHandler`; register a mount-time handler that flips auth `authed -> anon` (functional update, idempotent), with cleanup on unmount.
- [x] `App.tsx`: correct the now-stale mount-probe comment that claimed call sites flip auth on background 401s.
- [x] `App.tsx`: export `AuthedApp` so the redirect behavior can be tested in isolation.
- [x] `api.ts` + `auth.ts`: extend the 401 signal to the session-protected break-glass reauth path (`/api/auth/reauth/*`). `api.ts` exposes a non-throwing `notifyUnauthorized`; `auth.ts`'s `requestJSON` calls it on a reauth-path 401 (a mid-reauth session expiry) so the app redirects to login, while the pre-auth break-glass login/setup 401 (a bad credential) is left untouched. Covered by the existing "Mid-session expiry returns the operator to login" scenario.

## 3. Spec

- [x] `web-ui` spec: MODIFY "Authenticated entry to the application" to cover mid-session expiry, with a new scenario "Mid-session expiry returns the operator to login".
- [x] `ui-authentication-session` spec: REMOVE "Sessions expire 12 hours after issue" (Reason + Migration) and ADD "Sessions expire on idle and absolute timeouts per class" with five scenarios (cookie/absolute/idle/sliding/break-glass) reflecting the shipped `sessions.Timeouts` model.
- [x] Repoint the two existing session-expiry test markers and add markers to the three previously-unmarked tests (idle expiry, sliding extension, break-glass pair) so every new scenario is covered.

## 4. Tests

- [x] `api.test.ts`: the unauthorized handler fires on a 401 from a safe-method fetch and from an unsafe-method (mutation) fetch, and does NOT fire once cleared with null. Scenario marker on the cases.
- [x] `App.test.tsx`: rendering `AuthedApp` with a session probe that succeeds then a background fetch that 401s lands on the login page. Scenario marker on the case.

## 5. Archive follow-up (post-merge)

- [ ] When running `openspec archive ui-redirect-on-session-expiry`, also delete the two transitional `sessions-expire-12-hours-after-issue/*` markers (in `server/identity/internal/sessions/sessions_test.go` and `server/identity/internal/oidc/handler_test.go`). They cover the old canonical scenarios that spectrace gates until archive rewrites the requirement; once the requirement is renamed in canonical, those slugs no longer exist and the lines become invalid references. The new `sessions-expire-on-idle-and-absolute-timeouts-per-class/*` markers already in place cover the replacement scenarios.

## 6. Verification

- [x] `cd ui && npx tsc --noEmit` clean.
- [x] `cd ui && npx vitest run` green (full suite).
- [x] `cd ui && npx eslint` clean on changed files.
- [x] `openspec validate ui-redirect-on-session-expiry --strict`; spectrace; dash + markdown lints.
