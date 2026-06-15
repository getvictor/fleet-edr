// The UI authenticates with the server via a HttpOnly session cookie
// (automatic on every fetch when credentials: 'include') + a per-session
// CSRF token that the JS attaches as X-CSRF-Token on unsafe methods.
// Sessions are minted server-side by the OIDC callback (after the
// "Continue with Okta" full-page redirect) or by the break-glass
// FinishLogin / FinishSetup flows. GET /api/session returns the cookie's
// session JSON shape (including the CSRF token) and is the UI's
// session-probe endpoint.
import type {
  HostSummary,
  TreeResponse,
  ProcessDetail,
  Alert,
  AlertDetail,
  Command,
  ApplicationControlPolicy,
  ApplicationControlRule,
} from "./types";
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
// 403 + body { error: "reauth_required", challenge: {...} }. The
// server gates destructive actions on a fresh-auth window; callers
// don't invoke this directly: they wrap their mutation through
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
  // permissions is the operator's effective action set, computed server-side from
  // their role bindings (the `*` wildcard expanded to concrete actions). The UI gates
  // navigation and action affordances on it via the capability seam (see
  // permissions.tsx). Optional for forward-compatibility: an older server that
  // predates this field leaves it undefined, which the seam treats as "render
  // optimistically and rely on the server's 403". Advisory only; the server's
  // authorization chokepoint remains authoritative.
  permissions?: string[];
}

export function getCsrfToken(): string {
  return sessionStorage.getItem(CSRF_KEY) || "";
}

// sanitizeCsrfToken restricts stored values to the shape the server actually mints
// (URL-safe base64 of a 32-byte CSRF secret: see server/authn.EncodeSessionID). The
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

// AUTHZ_REASON_HEADER is the response header the authorization chokepoint sets on a policy
// denial (server/identity/api: AuthzReasonHeader). Its presence distinguishes a genuine
// authz "your role does not grant this action" 403 from other 403s (CSRF failures, etc.),
// which the forbidden-handler signal gates on so only authz denials trigger a refetch.
const AUTHZ_REASON_HEADER = "X-Edr-Authz-Reason";

// forbiddenHandler is an optional callback invoked when the server returns an authorization
// 403 (one carrying AUTHZ_REASON_HEADER). The UI registers one so it can refresh a
// possibly-stale permission set (e.g. the operator's role changed after the session probe).
// Deduping/throttling is the handler's responsibility (see createDedupedRunner); api.ts just
// fires the signal. Reauth 403s, CSRF 403s, and 401s do NOT trigger it: they have their own
// handling or are not authz denials.
let forbiddenHandler: (() => void) | null = null;

// setForbiddenHandler registers (or clears, with null) the authz-403 callback.
export function setForbiddenHandler(handler: (() => void) | null): void {
  forbiddenHandler = handler;
}

// unauthorizedHandler is an optional callback invoked when the server returns 401 on ANY /api/* fetch: the session expired (idle or
// absolute timeout) or was revoked mid-use. The app registers one (see App.tsx) so a background 401 flips global auth state to anon
// and routes to the login page, instead of each call site rendering a stale inline "API error: 401" and leaving the operator stranded
// on a dead page. The mount-time session probe and explicit logout already drive that same anon transition; this closes the gap for a
// session that lapses while the app is open. The handler MUST be idempotent: a burst of in-flight fetches can all 401 at once.
let unauthorizedHandler: (() => void) | null = null;

// setUnauthorizedHandler registers (or clears, with null) the 401 callback.
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

// raiseUnauthorized is the single 401 chokepoint both fetch helpers funnel through. It clears the now-stale CSRF token so it cannot
// linger into the next login, fires the global 401 signal so the app can redirect to login, then throws the typed error so the calling
// site still rejects (callers that already catch Unauthorized401Error keep working unchanged).
function raiseUnauthorized(): never {
  clearCsrfToken();
  unauthorizedHandler?.();
  throw new Unauthorized401Error();
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  assertSafeAPIPath(path);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  // Attach CSRF on unsafe methods only. GET/HEAD never need it, and sending an
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
    // Session expired or never existed: clear stale CSRF, signal the app to redirect to login, and throw so the caller still rejects.
    raiseUnauthorized();
  }
  if (res.status === HTTP_STATUS_FORBIDDEN) {
    // The chokepoint denies destructive actions outside the
    // reauth window with 403 + { error: "reauth_required",
    // challenge: { auth_method, reauth_url } }. Disambiguate from a
    // regular forbidden (which is genuinely "your role does not
    // grant this action") before throwing the typed error so
    // useReauthRetry can pick it up. .clone() so the underlying body
    // is still readable if this is NOT a reauth deny, which falls through
    // to the !res.ok branch below.
    const reauth = await readReauthChallenge(res);
    if (reauth) throw new ReauthRequiredError(reauth);
    // Signal the UI to refresh a possibly-stale permission set ONLY when this 403 came
    // from the authorization chokepoint, identified by its reason header. CSRF failures
    // (csrf_missing / csrf_mismatch) and other non-authz 403s are also 403 but do NOT
    // carry the header, so they must not trigger a spurious /api/session refetch. The
    // error still propagates below so the caller surfaces it.
    if (res.headers.get(AUTHZ_REASON_HEADER)) {
      forbiddenHandler?.();
    }
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
  source?: string;
  process_id?: number;
  limit?: number;
}): Promise<Alert[]> {
  const query = new URLSearchParams();
  if (params?.host_id) query.set("host_id", params.host_id);
  if (params?.status) query.set("status", params.status);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.source) query.set("source", params.source);
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

// --- Application Control endpoints ---
//
// Mirrors the demo-cut REST surface mounted at /api/v1/app-control/* by
// server/rules/internal/operator/appcontrol_handler.go. The server emits
// typed error codes (application_control.invalid_rule, etc.); the UI
// surfaces those via AppControlApiError so callers can switch on the
// code rather than match a free-form message.

// AppControlApiError carries the typed `error` code the handler writes
// on its 4xx responses. Callers use `.code` to switch on the failure
// (e.g. invalid_rule -> highlight the identifier field;
// duplicate_rule -> show "this rule already exists" inline).
export class AppControlApiError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "AppControlApiError";
    this.code = code;
    this.status = status;
  }
}

// AppControlErrorBody is the wire shape every typed 4xx response from
// the app-control handler carries. Narrow on purpose so unrelated 4xxs
// (a stray HTML error page from a misconfigured proxy, e.g.) fall
// through to the plain `API error` path.
interface AppControlErrorBody {
  error?: string;
  message?: string;
}

// AppControlListResponse is the GET /policies wire shape. The
// underlying handler returns `{policies: [...]}` rather than a bare
// array so future pagination + filter metadata can land alongside the
// rows without a wire-shape break.
interface AppControlListResponse {
  policies: ApplicationControlPolicy[];
}

// The read-side endpoints (list + get) route through fetchJSON because
// they never produce typed application_control.* error codes on the
// happy paths the UI exercises (4xx on read would be a 404 with the
// typed code, which the call site already handles via the standard
// "API error" path mapped to a user-visible error message). Only the
// state-changing POST goes through the explicit AppControlApiError
// path below; the typed-error surface only earns its complexity on
// the write side.
export async function listAppControlPolicies(): Promise<ApplicationControlPolicy[]> {
  const body = await fetchJSON<AppControlListResponse>("/v1/app-control/policies");
  return body.policies;
}

export async function getAppControlPolicy(id: number): Promise<ApplicationControlPolicy> {
  return fetchJSON<ApplicationControlPolicy>(`/v1/app-control/policies/${String(id)}`);
}

// CreateAppControlRuleRequest is the JSON body the POST endpoint
// accepts. Mirrors createRuleRequest in
// server/rules/internal/operator/appcontrol_handler.go. The demo cut
// only honours rule_type=BINARY; the form locks the type selector to
// that value, but the type is on the wire so post-demo additions
// don't break the contract.
export interface CreateAppControlRuleRequest {
  rule_type: string;
  identifier: string;
  custom_msg?: string;
  custom_url?: string;
  comment?: string;
  severity?: string;
  reason: string;
}

export async function createAppControlRule(
  policyID: number,
  req: CreateAppControlRuleRequest,
): Promise<ApplicationControlRule> {
  return appControlMutationEndpoint(
    "POST",
    `/v1/app-control/policies/${String(policyID)}/rules`,
    req,
    (res) => res.json() as Promise<ApplicationControlRule>,
  );
}

// UpdateAppControlRuleRequest is the JSON body the PATCH endpoint accepts. Mirrors updateRuleRequest in
// server/rules/internal/operator/appcontrol_handler.go. Every mutable field is optional so a body that flips only `enabled`
// still validates; `reason` is required for the audit trail. Phase B's Detect-mode change will layer an `enforcement` field
// on top of this shape.
export interface UpdateAppControlRuleRequest {
  enabled?: boolean;
  severity?: string;
  custom_msg?: string;
  custom_url?: string;
  comment?: string;
  expires_at?: string;
  reason: string;
}

// DeleteAppControlRuleRequest carries the audit reason for DELETE /rules/{id}.
export interface DeleteAppControlRuleRequest {
  reason: string;
}

// appControlMutationEndpoint is the shared body of every state-changing app-control endpoint (POST + PATCH + DELETE). All
// four endpoints have the same auth + reauth + typed-error handling; centralising here keeps the per-verb wrappers thin and
// avoids the duplicate-function-body trap Sonar's S4144 fires on parallel implementations. Method-widening from
// "PATCH" | "DELETE" to include "POST" is the only change versus the prior signature.
async function appControlMutationEndpoint<T>(
  method: "POST" | "PATCH" | "DELETE",
  path: string,
  body: unknown,
  parseResponse: (res: Response) => Promise<T>,
): Promise<T> {
  assertSafeAPIPath(path);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  attachCsrfHeader(headers, method);
  const target = new URL(API_BASE + path, globalThis.location.origin);
  const res = await fetch(target, {
    method,
    credentials: "include",
    headers,
    body: JSON.stringify(body),
  });
  if (res.status === HTTP_STATUS_UNAUTHORIZED) {
    raiseUnauthorized();
  }
  if (res.status === HTTP_STATUS_FORBIDDEN) {
    const reauth = await readReauthChallenge(res);
    if (reauth) throw new ReauthRequiredError(reauth);
  }
  if (!res.ok) {
    const errBody = (await res.clone().json().catch((): null => null)) as AppControlErrorBody | null;
    if (errBody?.error) {
      throw new AppControlApiError(errBody.error, errBody.message ?? errBody.error, res.status);
    }
    throw new Error(`API error: ${String(res.status)} ${res.statusText}`);
  }
  return parseResponse(res);
}

export async function updateAppControlRule(
  ruleID: number,
  req: UpdateAppControlRuleRequest,
): Promise<ApplicationControlRule> {
  return appControlMutationEndpoint(
    "PATCH",
    `/v1/app-control/rules/${String(ruleID)}`,
    req,
    (res) => res.json() as Promise<ApplicationControlRule>,
  );
}

export async function deleteAppControlRule(
  ruleID: number,
  req: DeleteAppControlRuleRequest,
): Promise<void> {
  await appControlMutationEndpoint(
    "DELETE",
    `/v1/app-control/rules/${String(ruleID)}`,
    req,
    // DELETE returns 204 No Content; resolve to undefined without parsing.
    () => Promise.resolve(undefined),
  );
}

// BulkUpsertAppControlRuleItem is one row in the bulk-upsert request body. Mirrors bulkUpsertItem in
// server/rules/internal/operator/appcontrol_handler.go. custom_msg + custom_url are optional pointer-shape fields server-side
// so the empty-string vs. missing distinction round-trips; UI senders can always include them.
export interface BulkUpsertAppControlRuleItem {
  rule_type: string;
  identifier: string;
  severity?: string;
  custom_msg?: string;
  custom_url?: string;
  comment?: string;
}

// BulkUpsertAppControlRulesRequest is the wire envelope. PolicyID rides in the URL path; the body carries the items + the
// shared audit reason that lands on the single audit row regardless of how many items were in the batch.
export interface BulkUpsertAppControlRulesRequest {
  rules: BulkUpsertAppControlRuleItem[];
  reason: string;
}

// BulkUpsertAppControlResult mirrors server/rules/api.BulkUpsertResult. inserted + updated are the per-row outcome counts,
// rules is the post-upsert row set in request order so the UI can render the result without an extra round trip.
export interface BulkUpsertAppControlResult {
  inserted: number;
  updated: number;
  rules: ApplicationControlRule[];
}

// MAX_BULK_UPSERT_ITEMS mirrors server/rules/api.MaxBulkUpsertItems. The server returns a typed 400 above this; the modal
// pre-validates so a 500-item paste fails locally before traversing the network round trip.
export const MAX_BULK_UPSERT_ITEMS = 500;

export async function bulkUpsertAppControlRules(
  policyID: number,
  req: BulkUpsertAppControlRulesRequest,
): Promise<BulkUpsertAppControlResult> {
  return appControlMutationEndpoint(
    "POST",
    `/v1/app-control/policies/${String(policyID)}/rules:bulkUpsert`,
    req,
    (res) => res.json() as Promise<BulkUpsertAppControlResult>,
  );
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
