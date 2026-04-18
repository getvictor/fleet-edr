import type { HostSummary, TreeResponse, ProcessDetail, Alert, AlertDetail, Command } from "./types";

const API_BASE = "/api/v1";

function getApiKey(): string {
  return sessionStorage.getItem("edr_api_key") || "";
}

export function setApiKey(key: string) {
  sessionStorage.setItem("edr_api_key", key);
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const apiKey = getApiKey();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    throw new Error(`API error: ${String(res.status)} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

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
  return fetchJSON<Alert[]>(`/alerts${qs ? `?${qs}` : ""}`);
}

export async function getAlertDetail(id: number): Promise<AlertDetail> {
  return fetchJSON<AlertDetail>(`/alerts/${String(id)}`);
}

export async function updateAlertStatus(id: number, status: string): Promise<void> {
  const apiKey = getApiKey();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  const res = await fetch(`${API_BASE}/alerts/${String(id)}`, {
    method: "PUT",
    headers,
    body: JSON.stringify({ status }),
  });
  if (!res.ok) {
    throw new Error(`API error: ${String(res.status)} ${res.statusText}`);
  }
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
