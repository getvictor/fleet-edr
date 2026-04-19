// Phase 3: the UI authenticates with the server via a HttpOnly session cookie
// (automatic on every fetch when credentials: 'include') + a per-session CSRF token
// that the JS attaches as X-CSRF-Token on unsafe methods. The old sessionStorage
// "edr_api_key" bearer is gone; see POST /api/v1/session for the login round-trip
// that issues both the cookie and the CSRF token.
import type { HostSummary, TreeResponse, ProcessDetail, Alert, AlertDetail, Command } from "./types";

const API_BASE = "/api/v1";

const CSRF_KEY = "edr_csrf_token";

// Unauthorized401Error is thrown whenever the server returns 401. App.tsx catches it
// to decide "show the login page", so callers don't need to know the status code.
export class Unauthorized401Error extends Error {
  constructor() { super("unauthorized"); this.name = "Unauthorized401Error"; }
}

export interface SessionInfo {
  user: { id: number; email: string };
  csrf_token: string;
}

export function getCsrfToken(): string {
  return sessionStorage.getItem(CSRF_KEY) || "";
}

// sanitizeCsrfToken restricts stored values to the shape the server actually mints
// (URL-safe base64 of a 32-byte CSRF secret — see server/authn.EncodeSessionID). The
// whitelist blocks any exotic payload that somehow ended up here before hitting
// sessionStorage, which is what the taint analyzer is flagging.
function sanitizeCsrfToken(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > 128) return "";
  return /^[A-Za-z0-9_-]+$/.test(trimmed) ? trimmed : "";
}

export function setCsrfToken(token: string): void {
  const clean = sanitizeCsrfToken(token);
  if (!clean) {
    console.warn("rejected malformed CSRF token");
    return;
  }
  sessionStorage.setItem(CSRF_KEY, clean);
}

export function clearCsrfToken(): void {
  sessionStorage.removeItem(CSRF_KEY);
}

function unsafeMethod(method?: string): boolean {
  if (!method) return false;
  const m = method.toUpperCase();
  return m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  // Attach CSRF on unsafe methods only — GET/HEAD never need it, and sending an
  // expired token on those is harmless but wasted bytes.
  if (unsafeMethod(init?.method)) {
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });
  if (res.status === 401) {
    // Session expired or never existed. Clear local CSRF so a stale token doesn't
    // linger and trip us up on the next login.
    clearCsrfToken();
    throw new Unauthorized401Error();
  }
  if (!res.ok) {
    throw new Error(`API error: ${String(res.status)} ${res.statusText}`);
  }
  // DELETE /api/v1/session returns 204 with no body; handle the empty-body case.
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// --- Session endpoints ---

export async function login(email: string, password: string): Promise<SessionInfo> {
  const info = await fetchJSON<SessionInfo>("/session", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setCsrfToken(info.csrf_token);
  return info;
}

export async function currentSession(): Promise<SessionInfo> {
  const info = await fetchJSON<SessionInfo>("/session");
  // The server issues a fresh CSRF per session; on page reload we fetch it here
  // and re-prime sessionStorage so every subsequent unsafe method has a header.
  setCsrfToken(info.csrf_token);
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

export async function createCommand(hostId: string, commandType: string, payload: Record<string, unknown>): Promise<{ id: number }> {
  return fetchJSON<{ id: number }>("/commands", {
    method: "POST",
    body: JSON.stringify({ host_id: hostId, command_type: commandType, payload }),
  });
}

export async function getCommand(id: number): Promise<Command> {
  return fetchJSON<Command>(`/commands/${String(id)}`);
}
