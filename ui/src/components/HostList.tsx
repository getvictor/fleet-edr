import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listHosts } from "../api";
import type { HostSummary } from "../types";

export function HostList() {
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    listHosts()
      .then(setHosts)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p>Loading hosts...</p>;
  if (error) return <p style={{ color: "red" }}>Error: {error}</p>;
  if (hosts.length === 0) return <p>No hosts reporting yet.</p>;

  return (
    <table style={{ borderCollapse: "collapse", width: "100%" }}>
      <thead>
        <tr>
          <th style={thStyle}>Host ID</th>
          <th style={thStyle}>Events</th>
          <th style={thStyle}>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {hosts.map((h) => (
          <tr
            key={h.host_id}
            onClick={() => navigate(`/hosts/${encodeURIComponent(h.host_id)}`)}
            style={{ cursor: "pointer" }}
          >
            <td style={tdStyle}>{h.host_id}</td>
            <td style={tdStyle}>{h.event_count.toLocaleString()}</td>
            <td style={tdStyle}>{formatRelative(h.last_seen_ns)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function formatRelative(ns: number): string {
  const diff = Date.now() - ns / 1_000_000;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  borderBottom: "2px solid #ccc",
  padding: "0.5rem",
};

const tdStyle: React.CSSProperties = {
  borderBottom: "1px solid #eee",
  padding: "0.5rem",
};
