import { useEffect, useState, useCallback } from "react";
import { getProcessDetail, listAlertsByProcessId, updateAlertStatus, createCommand, getCommand } from "../api";
import type { ProcessNode, ProcessDetail as ProcessDetailType, Alert, Command } from "../types";
import { NetworkConnections } from "./NetworkConnections";

interface Props {
  hostId: string;
  node: ProcessNode;
  onClose: () => void;
}

export function ProcessDetail({ hostId, node, onClose }: Props) {
  const [detail, setDetail] = useState<ProcessDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [killCommand, setKillCommand] = useState<Command | null>(null);
  const [killSending, setKillSending] = useState(false);

  const atTime = node.exec_time_ns || node.fork_time_ns;

  useEffect(() => {
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    getProcessDetail(hostId, node.pid, atTime)
      .then((result) => {
        if (!cancelled) setDetail(result);
      })
      .catch(() => {
        if (!cancelled) setDetail(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [hostId, node.pid, atTime]);

  useEffect(() => {
    let cancelled = false;
    listAlertsByProcessId(node.id)
      .then((result) => {
        if (!cancelled) setAlerts(result);
      })
      .catch(() => { /* alerts are best-effort */ });
    return () => { cancelled = true; };
  }, [node.id]);

  // Poll for command status updates when a kill command is pending/acked.
  useEffect(() => {
    if (!killCommand || killCommand.id === 0 || killCommand.status === "completed" || killCommand.status === "failed") return;
    const timer = setInterval(() => {
      getCommand(killCommand.id)
        .then((found) => {
          if (found.status !== killCommand.status) {
            setKillCommand(found);
          }
        })
        .catch(() => { /* polling is best-effort */ });
    }, 2000);
    return () => { clearInterval(timer); };
  }, [killCommand]);

  const handleKillProcess = useCallback(() => {
    if (killSending) return;
    setKillSending(true);
    createCommand(hostId, "kill_process", { pid: node.pid })
      .then((res) => {
        setKillCommand({
          id: res.id,
          host_id: hostId,
          command_type: "kill_process",
          payload: { pid: node.pid },
          status: "pending",
          created_at: new Date().toISOString(),
        });
      })
      .catch(() => {
        setKillCommand({
          id: 0,
          host_id: hostId,
          command_type: "kill_process",
          payload: { pid: node.pid },
          status: "failed",
          created_at: new Date().toISOString(),
          result: { error: "Failed to send command" },
        });
      })
      .finally(() => { setKillSending(false); });
  }, [hostId, node.pid, killSending]);

  const handleAlertStatusChange = (alertId: number, newStatus: string) => {
    updateAlertStatus(alertId, newStatus)
      .then(() => {
        setAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
        );
      })
      .catch(() => { /* ignore */ });
  };

  return (
    <div style={{ border: "1px solid #ddd", borderRadius: 4, padding: "1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
        <strong>Process detail</strong>
        <button onClick={onClose} aria-label="Close" style={{ cursor: "pointer" }}>
          &times;
        </button>
      </div>

      <dl style={dlStyle}>
        <dt>PID</dt>
        <dd>{node.pid}</dd>
        <dt>PPID</dt>
        <dd>{node.ppid}</dd>
        <dt>Path</dt>
        <dd style={{ wordBreak: "break-all" }}>{node.path || "(unknown)"}</dd>
        {node.args && (
          <>
            <dt>Args</dt>
            <dd style={{ wordBreak: "break-all" }}>{node.args.join(" ")}</dd>
          </>
        )}
        {node.uid !== undefined && (
          <>
            <dt>UID</dt>
            <dd>{node.uid}</dd>
          </>
        )}
        {node.gid !== undefined && (
          <>
            <dt>GID</dt>
            <dd>{node.gid}</dd>
          </>
        )}
        {node.sha256 && (
          <>
            <dt>SHA256</dt>
            <dd style={{ wordBreak: "break-all", fontSize: "0.75rem" }}>{node.sha256}</dd>
          </>
        )}
        {node.code_signing && (
          <>
            <dt>Signing</dt>
            <dd>
              {node.code_signing.signing_id}
              {node.code_signing.is_platform_binary ? " (platform)" : ""}
            </dd>
          </>
        )}
        <dt>Fork</dt>
        <dd>{formatTimestamp(node.fork_time_ns)}</dd>
        {node.exec_time_ns && (
          <>
            <dt>Exec</dt>
            <dd>{formatTimestamp(node.exec_time_ns)}</dd>
          </>
        )}
        {node.exit_time_ns && (
          <>
            <dt>Exit</dt>
            <dd>
              {formatTimestamp(node.exit_time_ns)}
              {node.exit_code !== undefined ? ` (code ${String(node.exit_code)})` : ""}
            </dd>
          </>
        )}
      </dl>

      <div style={{ marginTop: "0.75rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <button
          onClick={handleKillProcess}
          disabled={killSending || (killCommand !== null && killCommand.status !== "completed" && killCommand.status !== "failed")}
          style={{
            ...killBtnStyle,
            opacity: killSending || (killCommand !== null && killCommand.status !== "completed" && killCommand.status !== "failed") ? 0.5 : 1,
          }}
        >
          Kill process
        </button>
        {killCommand && (
          <span style={{ fontSize: "0.8rem", color: commandStatusColor(killCommand.status) }}>
            {killCommand.status}
            {killCommand.status === "failed" && typeof killCommand.result?.error === "string"
              ? `: ${killCommand.result.error}`
              : ""}
            {killCommand.status === "completed" ? " — process killed" : ""}
          </span>
        )}
      </div>

      {loading && <p>Loading network data...</p>}

      {detail && (
        <NetworkConnections
          connections={detail.network_connections}
          dnsQueries={detail.dns_queries}
        />
      )}

      {alerts.length > 0 && (
        <div style={{ marginTop: "1rem" }}>
          <strong style={{ fontSize: "0.85rem" }}>Alerts</strong>
          {alerts.map((a) => (
            <div key={a.id} style={alertCardStyle}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{
                  display: "inline-block",
                  padding: "0.1rem 0.4rem",
                  borderRadius: 3,
                  color: "#fff",
                  fontSize: "0.7rem",
                  fontWeight: "bold",
                  backgroundColor: severityColor(a.severity),
                }}>
                  {a.severity}
                </span>
                <span style={{ fontSize: "0.75rem", color: statusColor(a.status) }}>{a.status}</span>
              </div>
              <div style={{ fontSize: "0.8rem", fontWeight: "bold", marginTop: "0.25rem" }}>{a.title}</div>
              <div style={{ fontSize: "0.75rem", color: "#666", marginTop: "0.15rem" }}>{a.description}</div>
              <div style={{ marginTop: "0.4rem", display: "flex", gap: "0.25rem" }}>
                {a.status === "open" && (
                  <button style={alertBtnStyle} onClick={() => { handleAlertStatusChange(a.id, "acknowledged"); }}>
                    Acknowledge
                  </button>
                )}
                {a.status !== "resolved" && (
                  <button style={alertBtnStyle} onClick={() => { handleAlertStatusChange(a.id, "resolved"); }}>
                    Resolve
                  </button>
                )}
                {a.status === "resolved" && (
                  <button style={alertBtnStyle} onClick={() => { handleAlertStatusChange(a.id, "open"); }}>
                    Reopen
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function severityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: "#d32f2f", high: "#e65100", medium: "#f9a825", low: "#1976d2",
  };
  return colors[severity] || "#999";
}

function statusColor(status: string): string {
  if (status === "open") return "#d32f2f";
  if (status === "acknowledged") return "#e65100";
  return "#388e3c";
}

function formatTimestamp(ns: number): string {
  return new Date(ns / 1_000_000).toLocaleTimeString();
}

const dlStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "auto 1fr",
  gap: "0.25rem 0.75rem",
  fontSize: "0.85rem",
  margin: 0,
};

const alertCardStyle: React.CSSProperties = {
  border: "1px solid #ffcdd2",
  borderRadius: 4,
  padding: "0.5rem",
  marginTop: "0.5rem",
  backgroundColor: "#fff5f5",
};

const alertBtnStyle: React.CSSProperties = {
  padding: "0.15rem 0.4rem",
  fontSize: "0.7rem",
  cursor: "pointer",
};

const killBtnStyle: React.CSSProperties = {
  padding: "0.3rem 0.75rem",
  fontSize: "0.8rem",
  cursor: "pointer",
  backgroundColor: "#d32f2f",
  color: "#fff",
  border: "none",
  borderRadius: 3,
  fontWeight: "bold",
};

function commandStatusColor(status: string): string {
  if (status === "pending") return "#f9a825";
  if (status === "acked") return "#e65100";
  if (status === "completed") return "#388e3c";
  return "#d32f2f";
}
