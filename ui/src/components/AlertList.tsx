import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listAlerts, updateAlertStatus } from "../api";
import type { Alert } from "../types";
import { Table, EmptyState } from "./ui/Table";
import { Badge, type BadgeVariant } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Select } from "./ui/Input";
import { PageHeader } from "./ui/PageHeader";
import "./AlertList.scss";

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const STATUS_OPTIONS = ["", "open", "acknowledged", "resolved"];
const SEVERITY_OPTIONS = ["", "low", "medium", "high", "critical"];

export function AlertList() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Default to showing only open alerts, matching the landing-page default on every
  // mature EDR (Defender, CrowdStrike, Elastic, etc). Resolved/acknowledged alerts are
  // one click away via the Status dropdown but don't clutter the default view.
  const [statusFilter, setStatusFilter] = useState("open");
  const [severityFilter, setSeverityFilter] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    setError(null);
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

  const applyStatus = (prev: Alert[], alertId: number, newStatus: string): Alert[] => {
    // If the current filter no longer matches, remove the row instead of just patching it.
    if (statusFilter && newStatus !== statusFilter) {
      return prev.filter((a) => a.id !== alertId);
    }
    return prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a));
  };

  const handleStatusChange = (alertId: number, newStatus: string) => {
    updateAlertStatus(alertId, newStatus)
      .then(() => { setAlerts((prev) => applyStatus(prev, alertId, newStatus)); })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to update status");
      });
  };

  const filters = (
    <div className="alert-filters">
      <Select
        id="status-filter"
        label="Status:"
        value={statusFilter}
        onChange={(e) => { setStatusFilter(e.target.value); }}
      >
        {STATUS_OPTIONS.map((s) => (
          <option key={s} value={s}>{s || "All"}</option>
        ))}
      </Select>
      <Select
        id="severity-filter"
        label="Severity:"
        value={severityFilter}
        onChange={(e) => { setSeverityFilter(e.target.value); }}
      >
        {SEVERITY_OPTIONS.map((s) => (
          <option key={s} value={s}>{s || "All"}</option>
        ))}
      </Select>
    </div>
  );

  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle="Detection findings across all hosts"
        actions={filters}
      />
      {loading && <EmptyState>Loading alerts...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {!loading && !error && alerts.length === 0 && (
        <EmptyState>No alerts found.</EmptyState>
      )}
      {!loading && !error && alerts.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>Host</th>
              <th>Time</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td>
                  <Badge variant={SEVERITY_VARIANTS[a.severity] ?? "neutral"}>
                    {a.severity}
                  </Badge>
                </td>
                <td>
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => {
                      const atMs = new Date(a.created_at).getTime();
                      const result = navigate(
                        `/hosts/${encodeURIComponent(a.host_id)}?alert=${String(a.id)}&process=${String(a.process_id)}&at=${String(atMs)}`,
                      );
                      // navigate() may return void or Promise<void> in react-router v7.
                      // Swallow the promise path; the router already handles cancellation.
                      if (result instanceof Promise) result.catch(() => { /* ignored */ });
                    }}
                  >
                    {a.title}
                  </button>
                </td>
                <td>{a.host_id}</td>
                <td>{formatTime(a.created_at)}</td>
                <td>
                  <span className={`status-text status-text--${a.status}`}>
                    {a.status}
                  </span>
                </td>
                <td>
                  <div className="alert-actions">
                    {a.status === "open" && (
                      <Button
                        size="small"
                        variant="inverse"
                        onClick={() => { handleStatusChange(a.id, "acknowledged"); }}
                      >
                        Acknowledge
                      </Button>
                    )}
                    {a.status !== "resolved" && (
                      <Button
                        size="small"
                        variant="inverse"
                        onClick={() => { handleStatusChange(a.id, "resolved"); }}
                      >
                        Resolve
                      </Button>
                    )}
                    {a.status === "resolved" && (
                      <Button
                        size="small"
                        variant="inverse"
                        onClick={() => { handleStatusChange(a.id, "open"); }}
                      >
                        Reopen
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}
