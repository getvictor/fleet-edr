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

function formatRelative(ns: number): string {
  const diff = Date.now() - ns / 1_000_000;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${String(Math.floor(diff / 60_000))}m ago`;
  if (diff < 86_400_000) return `${String(Math.floor(diff / 3_600_000))}h ago`;
  return `${String(Math.floor(diff / 86_400_000))}d ago`;
}
