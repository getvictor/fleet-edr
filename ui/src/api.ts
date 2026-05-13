// The UI authenticates with the server via a HttpOnly session cookie
// (automatic on every fetch when credentials: 'include') + a per-session
// CSRF token that the JS attaches as X-CSRF-Token on unsafe methods.
// Sessions are minted server-side by the OIDC callback (after the
// "Continue with Okta" full-page redirect) or by the break-glass
// FinishLogin/FinishSetup flows; the legacy POST /api/session password
// path was retired in Phase 5b. GET /api/session returns the cookie's
// session JSON shape (including the CSRF token) and is the UI's
// session-probe endpoint.
import type { HostSummary, TreeResponse, ProcessDetail, Alert, AlertDetail, Command } from "./types";
import {
  HTTP_STATUS_FORBIDDEN,
  HTTP_STATUS_NO_CONTENT,
  HTTP_STATUS_UNAUTHORIZED,
  MAX_CSRF_TOKEN_LENGTH,
} from "./constants";

const API_BASE = "/api";

const CSRF_KEY = "edr_csrf_token";

// Unauthorized401Error is thrown whenever the server returns 401. App.tsx catches it
// to decide "show the login page", so callers don't need to know the status code.
export class Unauthorized401Error extends Error {
  constructor() { super("unauthorized"); this.name = "Unauthorized401Error"; }
}

// ReauthAuthMethod enumerates the per-flow recovery shapes the server's
// reauth_required response carries. The wire is open-ended (the server
// could grow new auth methods later); the UI narrows here so the
// ReauthModal's switch is exhaustive at compile time.
export type ReauthAuthMethod = "oidc" | "local_password";

export interface ReauthChallenge {
  authMethod: ReauthAuthMethod;
  reauthURL: string;
}

// ReauthRequiredError is thrown whenever the server returns
// 403 + body { error: "reauth_required", challenge: {...} }. Phase 5
// gates destructive actions on a fresh-auth window; callers don't
// invoke this directly — they wrap their mutation through
// useReauthRetry, which catches the error, runs the per-flow
// challenge, and retries the original call.
export class ReauthRequiredError extends Error {
  readonly challenge: ReauthChallenge;
  constructor(challenge: ReauthChallenge) {
    super("reauth_required");
    this.name = "ReauthRequiredError";
    this.challenge = challenge;
  }
}

// ReauthBodyShape is the minimal JSON shape the fetchJSON wrapper
// looks for when distinguishing a "regular" 403 from the typed reauth
// 403. Kept narrow so the detection is robust against the body
// growing additional sibling fields.
interface ReauthBodyShape {
  error?: string;
  challenge?: {
    auth_method?: string;
    reauth_url?: string;
  };
}

export interface SessionInfo {
  user: { id: number; email: string };
  csrf_token: string;
  // auth_method records the flow that minted the session ("oidc" /
  // "local_password"). The UI surfaces it on the TopNav so an
  // operator who hit the break-glass recovery path knows they're
  // not in a normal SSO session. Optional in the wire shape because
  // wave-1 sessions inserted before the column existed default to
  // an empty string; the server normalises empty → "local_password"
  // before sending, but the field remains optional for forward-
  // compatibility.
  auth_method?: string;
}

export function getCsrfToken(): string {
  return sessionStorage.getItem(CSRF_KEY) || "";
}

// sanitizeCsrfToken restricts stored values to the shape the server actually mints
// (URL-safe base64 of a 32-byte CSRF secret — see server/authn.EncodeSessionID). The
// whitelist blocks any exotic payload that somehow ended up here before hitting
// sessionStorage, which is what the taint analyzer is flagging. Ceiling is generous
// so a future server-side change that widens the token (e.g. 64-byte) doesn't
// silently wedge the client.
function sanitizeCsrfToken(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_CSRF_TOKEN_LENGTH) return "";
  return /^[A-Za-z0-9_-]+$/.test(trimmed) ? trimmed : "";
}

// setCsrfToken stores a freshly-minted token and returns true on success. On
// rejection it wipes any previously-stored token (so the client stops sending a
// stale value) and returns false so callers can surface the failure instead of
// silently half-succeeding.
export function setCsrfToken(token: string): boolean {
  const clean = sanitizeCsrfToken(token);
  if (!clean) {
    clearCsrfToken();
    return false;
  }
  sessionStorage.setItem(CSRF_KEY, clean);
  return true;
}

export function clearCsrfToken(): void {
  sessionStorage.removeItem(CSRF_KEY);
}

function unsafeMethod(method?: string): boolean {
  if (!method) return false;
  const m = method.toUpperCase();
  return m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";
}

// attachCsrfHeader writes the CSRF token onto `headers` when the request
// method is unsafe (POST/PUT/PATCH/DELETE) AND a token is present in
// session storage. Shared with the break-glass + reauth surface in
// auth.ts so both fetch primitives match the server's CSRF middleware
// contract exactly (one canonical header name, one canonical method set).
// Wrapping function returns void rather than the mutated map to make the
// side-effect-only intent visible at the call site.
export function attachCsrfHeader(
  headers: Record<string, string>,
  method?: string,
): void {
  if (!unsafeMethod(method)) return;
  const csrf = getCsrfToken();
  if (csrf) headers["X-CSRF-Token"] = csrf;
}

// assertSafeAPIPath rejects anything that does not look like a same-origin API
// path. fetchJSON concatenates its path argument with API_BASE and hands the
// result to fetch(); without this check a caller that accidentally forwards
// user input (URL from query params, server-returned string, etc.) could steer
// the request to an unintended origin or walk out of /api via "..". The
// whitelist is deliberately narrow: leading slash, then only URL-path +
// query-string characters we actually use.
const API_PATH_RE = /^\/[A-Za-z0-9/?=&%:_.@~-]*$/;

function assertSafeAPIPath(path: string): void {
  if (!API_PATH_RE.test(path) || path.includes("..")) {
    throw new Error("unsafe API path");
  }
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  assertSafeAPIPath(path);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  // Attach CSRF on unsafe methods only — GET/HEAD never need it, and sending an
  // expired token on those is harmless but wasted bytes.
  attachCsrfHeader(headers, init?.method);

  // Build the URL through the URL constructor rather than string concatenation.
  // The constructor parses + normalises the path against our same-origin base,
  // which (a) strips any "//evil.com/..." style protocol-relative escape that
  // slipped past assertSafeAPIPath and (b) gives SonarCloud's taint analyser a
  // recognised sanitisation point so S7044/S8476 don't re-fire.
  const target = new URL(API_BASE + path, globalThis.location.origin);
  const res = await fetch(target, {
    ...init,
    headers,
    credentials: "include",
  });
  if (res.status === HTTP_STATUS_UNAUTHORIZED) {
    // Session expired or never existed. Clear local CSRF so a stale token doesn't
    // linger and trip us up on the next login.
    clearCsrfToken();
    throw new Unauthorized401Error();
  }
  if (res.status === HTTP_STATUS_FORBIDDEN) {
    // Phase 5: the chokepoint denies destructive actions outside the
    // reauth window with 403 + { error: "reauth_required",
    // challenge: { auth_method, reauth_url } }. Disambiguate from a
    // regular forbidden (which is genuinely "your role does not
    // grant this action") before throwing the typed error so
    // useReauthRetry can pick it up. .clone() so the underlying body
    // is still readable if this is NOT a reauth deny — falls through
    // to the !res.ok branch below.
    const reauth = await readReauthChallenge(res);
    if (reauth) throw new ReauthRequiredError(reauth);
  }
  if (!res.ok) {
    throw new Error(`API error: ${String(res.status)} ${res.statusText}`);
  }
  // DELETE /api/session returns 204 with no body; handle the empty-body case.
  if (res.status === HTTP_STATUS_NO_CONTENT) return undefined as T;
  return res.json() as Promise<T>;
}

// readReauthChallenge inspects a 403 response body for the
// reauth_required envelope and returns a typed ReauthChallenge when
// the shape matches, or null otherwise. Kept narrow: any of body
// missing, error mismatch, missing challenge, or unrecognised
// auth_method falls through to null so the caller emits a plain
// "forbidden" error.
async function readReauthChallenge(res: Response): Promise<ReauthChallenge | null> {
  const body = await res.clone().json().catch((): null => null) as ReauthBodyShape | null;
  if (body?.error !== "reauth_required" || !body.challenge) return null;
  const am = body.challenge.auth_method;
  if (am !== "oidc" && am !== "local_password") return null;
  return { authMethod: am, reauthURL: body.challenge.reauth_url ?? "" };
}

// --- Session endpoints ---

export async function currentSession(): Promise<SessionInfo> {
  const info = await fetchJSON<SessionInfo>("/session");
  // The server issues a fresh CSRF per session; on page reload we fetch it here
  // and re-prime sessionStorage so every subsequent unsafe method has a header.
  if (!setCsrfToken(info.csrf_token)) {
    throw new Error("server returned an unexpected CSRF token shape");
  }
  return info;
}

export async function logout(): Promise<void> {
  try {
    await fetchJSON<unknown>("/session", { method: "DELETE" });
  } finally {
    clearCsrfToken();
  }
}

// --- Domain endpoints ---

export async function listHosts(): Promise<HostSummary[]> {
  return fetchJSON<HostSummary[]>("/hosts");
}

export async function getProcessTree(
  hostId: string,
  fromNs: number,
  toNs: number,
  limit = 2000
): Promise<TreeResponse> {
  return fetchJSON<TreeResponse>(
    `/hosts/${encodeURIComponent(hostId)}/tree?from=${String(fromNs)}&to=${String(toNs)}&limit=${String(limit)}`
  );
}

export async function getProcessDetail(
  hostId: string,
  pid: number,
  atNs: number
): Promise<ProcessDetail> {
  return fetchJSON<ProcessDetail>(
    `/hosts/${encodeURIComponent(hostId)}/processes/${String(pid)}?at=${String(atNs)}`
  );
}

export async function listAlerts(params?: {
  host_id?: string;
  status?: string;
  severity?: string;
  process_id?: number;
  limit?: number;
}): Promise<Alert[]> {
  const query = new URLSearchParams();
  if (params?.host_id) query.set("host_id", params.host_id);
  if (params?.status) query.set("status", params.status);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.process_id) query.set("process_id", String(params.process_id));
  if (params?.limit) query.set("limit", String(params.limit));
  const qs = query.toString();
  const suffix = qs ? `?${qs}` : "";
  return fetchJSON<Alert[]>(`/alerts${suffix}`);
}

export async function getAlertDetail(id: number): Promise<AlertDetail> {
  return fetchJSON<AlertDetail>(`/alerts/${String(id)}`);
}

export async function updateAlertStatus(id: number, status: string): Promise<void> {
  await fetchJSON<unknown>(`/alerts/${String(id)}`, {
    method: "PUT",
    body: JSON.stringify({ status }),
  });
}

export async function listAlertsByProcessId(processId: number): Promise<Alert[]> {
  return listAlerts({ process_id: processId });
}

// AttackNavigatorLayer mirrors the layer-4.5 schema the upstream Navigator
// renders. We type it explicitly so future client-side rendering (e.g. an
// in-app heatmap) gets compile-time guarantees against drift in the server's
// admin.handleATTACKCoverage response shape.
export interface AttackNavigatorLayer {
  name: string;
  versions: Record<string, string>;
  domain: string;
  description: string;
  techniques: Array<{
    techniqueID: string;
    score: number;
    color?: string;
    comment?: string;
  }>;
}

// fetchAttackNavigatorLayer pulls the MITRE ATT&CK Navigator layer that
// describes which techniques the registered detection rules cover. Returned
// JSON is dropped directly into https://mitre-attack.github.io/attack-navigator/
// to render as a heatmap. Call site is the "ATT&CK coverage" button in the
// alerts page; the response is also useful for procurement questionnaires.
export async function fetchAttackNavigatorLayer(): Promise<AttackNavigatorLayer> {
  return fetchJSON<AttackNavigatorLayer>("/attack-coverage");
}

// RuleConfig describes one operator-tuning env var. Wire shape matches
// admin.RuleConfig in the server.
export interface RuleConfig {
  env_var: string;
  type: string;
  default: string;
  description: string;
}

// RuleDoc is the structured per-rule documentation surfaced by GET
// /api/rules. Mirrors detection.Documentation on the server, with
// the JSON tag spellings the wire format uses.
export interface RuleDoc {
  title: string;
  summary: string;
  description: string;
  severity: string;
  event_types: string[];
  false_positives?: string[];
  limitations?: string[];
  config?: RuleConfig[];
}

export interface RuleDocEntry {
  id: string;
  techniques: string[];
  doc: RuleDoc;
}

// fetchRuleDocs returns every registered detection rule with its operator-
// facing documentation. Drives the /ui/rules/<id> sub-page and the rule-name
// links on /ui/coverage. Order mirrors the server's registration order, so
// the UI can iterate without resorting.
export async function fetchRuleDocs(): Promise<RuleDocEntry[]> {
  const body = await fetchJSON<{ rules: RuleDocEntry[] }>("/rules");
  return body.rules;
}

export async function createCommand(hostId: string, commandType: string, payload: Record<string, unknown>): Promise<{ id: number }> {
  return fetchJSON<{ id: number }>("/commands", {
    method: "POST",
    body: JSON.stringify({ host_id: hostId, command_type: commandType, payload }),
  });
}

export async function getCommand(id: number): Promise<Command> {
  return fetchJSON<Command>(`/commands/${String(id)}`);
}
