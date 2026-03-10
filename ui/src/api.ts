import type { HostSummary, TreeResponse, ProcessDetail } from "./types";

const API_BASE = "/api/v1";

function getApiKey(): string {
  return sessionStorage.getItem("edr_api_key") || "";
}

export function setApiKey(key: string) {
  sessionStorage.setItem("edr_api_key", key);
}

async function fetchJSON<T>(path: string): Promise<T> {
  const apiKey = getApiKey();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  const res = await fetch(`${API_BASE}${path}`, { headers });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function listHosts(): Promise<HostSummary[]> {
  return fetchJSON<HostSummary[]>("/hosts");
}

export async function getProcessTree(
  hostId: string,
  fromNs: number,
  toNs: number,
  limit = 500
): Promise<TreeResponse> {
  return fetchJSON<TreeResponse>(
    `/hosts/${encodeURIComponent(hostId)}/tree?from=${fromNs}&to=${toNs}&limit=${limit}`
  );
}

export async function getProcessDetail(
  hostId: string,
  pid: number,
  atNs: number
): Promise<ProcessDetail> {
  return fetchJSON<ProcessDetail>(
    `/hosts/${encodeURIComponent(hostId)}/processes/${pid}?at=${atNs}`
  );
}
