// Phase 4c authentication helpers — break-glass redemption + login,
// OIDC redirect URL builder. The existing api.ts handles the
// authenticated /api/* surface; this module covers the pre-auth
// /admin/break-glass/* + /api/auth/* paths the operator hits before
// they have a session.
//
// Wire shape:
//   - GET /admin/break-glass[/setup] redirects to /ui/admin/break-glass[/setup].
//   - POST /admin/break-glass/setup/challenge?token=X → CredentialCreationOptions.
//   - POST /admin/break-glass/setup?token=X            → atomic redemption.
//   - POST /admin/break-glass/challenge                → CredentialAssertionOptions.
//   - POST /admin/break-glass                          → finish login.
//
// The challenge cookie (HttpOnly, signed) round-trips automatically
// because every fetch here uses credentials: 'include' against the
// same origin.

import {
  startRegistration,
  startAuthentication,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

// HTTP status threshold above which the response is an error.
const HTTP_BAD_REQUEST = 400;

// HTTP_NO_CONTENT is the empty-body 2xx that the requestJSON guard
// returns as `undefined` instead of feeding to res.json().
const HTTP_NO_CONTENT = 204;

// Maximum size of a 'next' query parameter we'll forward to the
// IdP-redirect endpoint. The server already sanitises (off-site URLs
// fall through to /ui/), but capping here too prevents an absurdly
// long URL from slipping in via the browser address bar.
const MAX_NEXT_PARAM = 256;

// Allowed shape of the 'next' query parameter: same-origin absolute
// path only. Same restriction the server's safeRedirect enforces;
// duplicating it here means the UI does not produce malformed URLs.
const NEXT_PATH_RE = /^\/(?!\/)[A-Za-z0-9/?=&%:_.@~#-]*$/;

// BreakglassError surfaces the server's reason header so callers can
// render a directed message. The status code rides along so callers
// can distinguish 410 (token gone) from 401 (invalid credentials)
// from 429 (rate-limited).
export class BreakglassError extends Error {
  readonly status: number;
  readonly reason: string;
  constructor(status: number, reason: string) {
    super(`${reason} (status ${String(status)})`);
    this.name = "BreakglassError";
    this.status = status;
    this.reason = reason;
  }
}

// oidcLoginUrl returns the absolute path the "Continue with Okta"
// button navigates to. The optional `next` is a same-origin path the
// IdP returns to after a successful login. Off-shape values are
// dropped: the server's safeRedirect already does this, but the
// client side double-check keeps the URL bar tidy.
export function oidcLoginUrl(next?: string): string {
  if (!next || next.length > MAX_NEXT_PARAM || !NEXT_PATH_RE.test(next)) {
    return "/api/auth/login";
  }
  return `/api/auth/login?next=${encodeURIComponent(next)}`;
}

// requestJSON is the break-glass surface's fetch primitive. Same-
// origin POST with credentials so the challenge cookie rides along;
// JSON request body when one is supplied; throws BreakglassError on
// any non-2xx with the X-Edr-Auth-Reason header (or "http_<status>"
// when the server didn't set one).
async function requestJSON<T>(
  path: string,
  init: RequestInit,
): Promise<T> {
  const target = new URL(path, globalThis.location.origin);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  const res = await fetch(target, {
    ...init,
    headers,
    credentials: "include",
  });
  if (res.status >= HTTP_BAD_REQUEST) {
    const reason = res.headers.get("X-Edr-Auth-Reason") ?? `http_${String(res.status)}`;
    throw new BreakglassError(res.status, reason);
  }
  // Guard against 204 / empty / non-JSON 2xx bodies. Today every
  // break-glass endpoint returns a JSON envelope, but routing this
  // through res.json() unconditionally turns "successful but empty"
  // into a SyntaxError that surfaces as the generic "Sign-in failed"
  // fallback — masking what was actually a successful call. Treat
  // those as `undefined` and let typed call sites decide.
  const noBody = res.status === HTTP_NO_CONTENT
    || res.headers.get("Content-Length") === "0"
    || !(res.headers.get("Content-Type") ?? "").includes("application/json");
  if (noBody) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

// breakglassBeginSetup fetches the WebAuthn registration challenge
// for a redemption token, then runs the browser's
// navigator.credentials.create() ceremony. Returns the attestation
// the caller forwards to breakglassFinishSetup.
//
// The server-side handler sets the signed challenge cookie as part
// of its response; the browser stores it (HttpOnly + Path scope) and
// sends it back automatically on the matching POST.
export async function breakglassBeginSetup(
  token: string,
): Promise<unknown> {
  const body = await requestJSON<{ publicKey: PublicKeyCredentialCreationOptionsJSON }>(
    `/admin/break-glass/setup/challenge?token=${encodeURIComponent(token)}`,
    { method: "POST" },
  );
  return startRegistration({ optionsJSON: body.publicKey });
}

// breakglassFinishSetup submits the password + attestation back to
// the server's atomic redemption endpoint. Caller is responsible for
// having previously called breakglassBeginSetup so the challenge
// cookie is in place. Returns the redirect target on success.
export async function breakglassFinishSetup(
  token: string,
  password: string,
  credentialName: string,
  attestation: unknown,
): Promise<{ redirect: string }> {
  return requestJSON<{ redirect: string }>(
    `/admin/break-glass/setup?token=${encodeURIComponent(token)}`,
    {
      method: "POST",
      body: JSON.stringify({
        password,
        credential_name: credentialName,
        attestation,
      }),
    },
  );
}

// breakglassBeginLogin issues the WebAuthn assertion challenge for
// the given email and runs navigator.credentials.get(). Returns the
// signed assertion the caller forwards to breakglassFinishLogin.
export async function breakglassBeginLogin(email: string): Promise<unknown> {
  const body = await requestJSON<{ publicKey: PublicKeyCredentialRequestOptionsJSON }>(
    `/admin/break-glass/challenge`,
    {
      method: "POST",
      body: JSON.stringify({ email }),
    },
  );
  return startAuthentication({ optionsJSON: body.publicKey });
}

// breakglassFinishLogin posts the email + password + assertion to
// the server's login endpoint. Returns the redirect target on
// success; throws BreakglassError on any non-2xx (caller renders a
// directed message based on .reason).
export async function breakglassFinishLogin(
  email: string,
  password: string,
  assertion: unknown,
): Promise<{ redirect: string }> {
  return requestJSON<{ redirect: string }>(
    `/admin/break-glass`,
    {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
        assertion,
      }),
    },
  );
}

// reauthBreakglass runs the Phase 5 break-glass reauth ceremony
// against the operator's CURRENT session: WebAuthn assertion against
// /api/auth/reauth/challenge → password + assertion submitted to
// /api/auth/reauth → server stamps last_auth_at on the existing row.
// No new session is minted. The challenge cookie is path-scoped to
// /api/auth/reauth so it doesn't collide with an in-flight break-
// glass login flow in another tab.
//
// Throws BreakglassError on the server-side rejection paths (rate
// limit, invalid credentials, no_credentials, reauth_not_supported);
// callers translate .reason into operator-facing copy via the same
// label maps the login flow uses.
export async function reauthBreakglass(password: string): Promise<void> {
  const challenge = await requestJSON<{ publicKey: PublicKeyCredentialRequestOptionsJSON }>(
    `/api/auth/reauth/challenge`,
    { method: "POST" },
  );
  const assertion = await startAuthentication({ optionsJSON: challenge.publicKey });
  await requestJSON<{ ok: boolean }>(
    `/api/auth/reauth`,
    {
      method: "POST",
      body: JSON.stringify({ password, assertion }),
    },
  );
}

// reauthOIDC kicks off the OIDC reauth round-trip. Server appends
// prompt=login on the authorize URL when ?reauth=1 is set, forcing
// the IdP to re-prompt for credentials regardless of its existing
// session. The IdP's callback lands a fresh session whose
// last_auth_at is NOW(); the previous session is orphaned + reaped
// on its absolute expiry. UI returns to the path the operator was
// on (next param) so a button re-click finishes the destructive
// action.
//
// Full-page navigation (not fetch): the React tree unmounts during
// the redirect. Callers should await the returning Promise<never>
// only for type wiring — the function never resolves, browser
// navigation takes over.
export function reauthOIDC(): never {
  const next = `${globalThis.location.pathname}${globalThis.location.search}${globalThis.location.hash}`;
  // Mirror oidcLoginUrl's same-origin path validation so a hostile
  // location (rare — would require a malicious window.history.push or
  // similar) can't steer the redirect at the IdP.
  const safeNext = next.length <= MAX_NEXT_PARAM && NEXT_PATH_RE.test(next) ? next : "";
  const url = safeNext
    ? `/api/auth/login?reauth=1&next=${encodeURIComponent(safeNext)}`
    : `/api/auth/login?reauth=1`;
  globalThis.location.assign(url);
  // The assign() call replaces the current document; everything below
  // is unreachable but TS needs a return path. throw for total clarity.
  throw new Error("redirecting to IdP for reauth");
}
