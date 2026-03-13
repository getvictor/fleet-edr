import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listAlerts, updateAlertStatus } from "../api";
import type { Alert } from "../types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#d32f2f",
  high: "#e65100",
  medium: "#f9a825",
  low: "#1976d2",
};

const STATUS_OPTIONS = ["", "open", "acknowledged", "resolved"];
const SEVERITY_OPTIONS = ["", "low", "medium", "high", "critical"];

export function AlertList() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    listAlerts({
      status: statusFilter || undefined,
      severity: severityFilter || undefined,
    })
      .then((result) => {
        if (!cancelled) setAlerts(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [statusFilter, severityFilter]);

  const handleStatusChange = (alertId: number, newStatus: string) => {
    updateAlertStatus(alertId, newStatus)
      .then(() => {
        setAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
        );
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to update status");
      });
  };

  if (loading) return <p>Loading alerts...</p>;
  if (error) return <p style={{ color: "red" }}>Error: {error}</p>;

  return (
    <div>
      <div style={{ marginBottom: "1rem", display: "flex", gap: "1rem", alignItems: "center" }}>
        <label>
          Status:{" "}
          <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); }}>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{s || "All"}</option>
            ))}
          </select>
        </label>
        <label>
          Severity:{" "}
          <select value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value); }}>
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>{s || "All"}</option>
            ))}
          </select>
        </label>
      </div>

      {alerts.length === 0 ? (
        <p>No alerts found.</p>
      ) : (
        <table style={{ borderCollapse: "collapse", width: "100%" }}>
          <thead>
            <tr>
              <th style={thStyle}>Severity</th>
              <th style={thStyle}>Title</th>
              <th style={thStyle}>Host</th>
              <th style={thStyle}>Time</th>
              <th style={thStyle}>Status</th>
              <th style={thStyle}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td style={tdStyle}>
                  <span style={{
                    display: "inline-block",
                    padding: "0.15rem 0.5rem",
                    borderRadius: 3,
                    color: "#fff",
                    fontSize: "0.75rem",
                    fontWeight: "bold",
                    backgroundColor: SEVERITY_COLORS[a.severity] || "#999",
                  }}>
                    {a.severity}
                  </span>
                </td>
                <td style={{ ...tdStyle, cursor: "pointer", color: "#1976d2" }}
                    onClick={() => { void navigate(`/hosts/${encodeURIComponent(a.host_id)}?alert=${String(a.id)}&process=${String(a.process_id)}`); }}>
                  {a.title}
                </td>
                <td style={tdStyle}>{a.host_id}</td>
                <td style={tdStyle}>{formatTime(a.created_at)}</td>
                <td style={tdStyle}>
                  <span style={{
                    fontSize: "0.8rem",
                    color: a.status === "open" ? "#d32f2f" : a.status === "acknowledged" ? "#e65100" : "#388e3c",
                  }}>
                    {a.status}
                  </span>
                </td>
                <td style={tdStyle}>
                  {a.status === "open" && (
                    <button style={btnStyle} onClick={() => { handleStatusChange(a.id, "acknowledged"); }}>
                      Acknowledge
                    </button>
                  )}
                  {a.status !== "resolved" && (
                    <button style={btnStyle} onClick={() => { handleStatusChange(a.id, "resolved"); }}>
                      Resolve
                    </button>
                  )}
                  {a.status === "resolved" && (
                    <button style={btnStyle} onClick={() => { handleStatusChange(a.id, "open"); }}>
                      Reopen
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  borderBottom: "2px solid #ccc",
  padding: "0.5rem",
};

const tdStyle: React.CSSProperties = {
  borderBottom: "1px solid #eee",
  padding: "0.5rem",
  fontSize: "0.85rem",
};

const btnStyle: React.CSSProperties = {
  marginRight: "0.25rem",
  padding: "0.2rem 0.5rem",
  fontSize: "0.75rem",
  cursor: "pointer",
};
