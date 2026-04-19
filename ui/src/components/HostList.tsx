import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listHosts } from "../api";
import type { HostSummary } from "../types";
import { Table, EmptyState } from "./ui/Table";
import { PageHeader } from "./ui/PageHeader";

export function HostList() {
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    listHosts()
      .then(setHosts)
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  return (
    <>
      <PageHeader title="Hosts" subtitle="Endpoints reporting events" />
      {loading && <EmptyState>Loading hosts...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {!loading && !error && hosts.length === 0 && (
        <EmptyState>No hosts reporting yet.</EmptyState>
      )}
      {!loading && !error && hosts.length > 0 && (
        <Table className="table--clickable">
          <thead>
            <tr>
              <th>Host ID</th>
              <th>Status</th>
              <th>Events</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h) => (
              <tr
                key={h.host_id}
                onClick={() => {
                  void navigate(`/hosts/${encodeURIComponent(h.host_id)}`);
                }}
              >
                <td>{h.host_id}</td>
                <td>
                  <span className={statusPillClass(h.last_seen_ns)}>
                    {isOnline(h.last_seen_ns) ? "online" : "offline"}
                  </span>
                </td>
                <td>{h.event_count.toLocaleString()}</td>
                <td>{formatRelative(h.last_seen_ns)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}

// offlineThresholdMs: Phase 4 defines "offline" as last_seen > 5 min old. The agent
// polls every 5 s, so 5 min is 60× the polling interval — well past any transient
// network blip but fast enough that a crashed agent shows up quickly in the UI.
const offlineThresholdMs = 5 * 60 * 1000;

function isOnline(lastSeenNs: number): boolean {
  if (lastSeenNs === 0) return false;
  return Date.now() - lastSeenNs / 1_000_000 < offlineThresholdMs;
}

function statusPillClass(lastSeenNs: number): string {
  return isOnline(lastSeenNs) ? "status-pill status-pill--online" : "status-pill status-pill--offline";
}

function formatRelative(ns: number): string {
  if (ns === 0) return "never";
  const diff = Date.now() - ns / 1_000_000;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${String(Math.floor(diff / 60_000))}m ago`;
  if (diff < 86_400_000) return `${String(Math.floor(diff / 3_600_000))}h ago`;
  return `${String(Math.floor(diff / 86_400_000))}d ago`;
}
