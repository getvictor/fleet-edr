import { useEffect, useState, useCallback } from "react";
import {
  getProcessDetail,
  listAlertsByProcessId,
  updateAlertStatus,
  createCommand,
  getCommand,
  ReauthRequiredError,
} from "../api";
import type {
  ProcessNode,
  ProcessDetail as ProcessDetailType,
  Alert,
  Command,
} from "../types";
import { useReauthRetry } from "../hooks/useReauthRetry";
import { NetworkConnections } from "./NetworkConnections";
import { ReauthModal } from "./ReauthModal";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import { Badge, type BadgeVariant } from "./ui/Badge";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";
import "./ProcessDetail.scss";

// killCommandPollIntervalMs is the cadence we re-fetch the kill command's
// status while it's still pending/acked. 2s mirrors the agent's command-poll
// interval so the UI sees a state transition within one round-trip.
const KILL_COMMAND_POLL_INTERVAL_MS = 2000;

interface Props {
  readonly hostId: string;
  readonly node: ProcessNode;
  readonly onClose: () => void;
}

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

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
    if (
      !killCommand
      || killCommand.id === 0
      || killCommand.status === "completed"
      || killCommand.status === "failed"
    ) return;
    const timer = setInterval(() => {
      getCommand(killCommand.id)
        .then((found) => {
          if (found.status !== killCommand.status) {
            setKillCommand(found);
          }
        })
        .catch(() => { /* polling is best-effort */ });
    }, KILL_COMMAND_POLL_INTERVAL_MS);
    return () => { clearInterval(timer); };
  }, [killCommand]);

  // Phase 5: kill_process is reauth-gated by the chokepoint when the
  // session is stale. Same pattern for alert.resolve on critical
  // alerts. Wrap both mutations through useReauthRetry so the
  // operator gets an inline reauth modal + the action retries on
  // success. Non-gated mutations (e.g. alert.acknowledge or kill on
  // a fresh session) pass through unchanged — useReauthRetry is a
  // no-op until the chokepoint throws ReauthRequiredError.
  const sendKillCommand = useCallback(
    async (): Promise<{ id: number }> => createCommand(hostId, "kill_process", { pid: node.pid }),
    [hostId, node.pid],
  );
  const { call: callKill, modal: killReauthModal } = useReauthRetry(sendKillCommand);

  const updateStatus = useCallback(
    async (alertId: number, newStatus: string) => updateAlertStatus(alertId, newStatus),
    [],
  );
  const { call: callUpdateStatus, modal: alertReauthModal } = useReauthRetry(updateStatus);

  const handleKillProcess = useCallback(() => {
    if (killSending) return;
    setKillSending(true);
    callKill()
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
      .catch((err: unknown) => {
        // Cancelled reauth surfaces as ReauthRequiredError (the hook
        // rethrows the original gate-deny when the operator dismisses
        // the modal). That isn't a send failure — no command was
        // ever dispatched. Leave killCommand untouched so the UI
        // returns to its pre-click state instead of showing a
        // misleading "Failed to send command" row.
        if (err instanceof ReauthRequiredError) return;
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
  }, [callKill, hostId, node.pid, killSending]);

  const applyAlertStatus = (prev: Alert[], alertId: number, newStatus: string): Alert[] => {
    return prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a));
  };

  const handleAlertStatusChange = (alertId: number, newStatus: string) => {
    callUpdateStatus(alertId, newStatus)
      .then(() => { setAlerts((prev) => applyAlertStatus(prev, alertId, newStatus)); })
      .catch(() => { /* ignore */ });
  };

  const killDisabled = killSending
    || (killCommand !== null
      && killCommand.status !== "completed"
      && killCommand.status !== "failed");

  return (
    <Card padding="medium" className="process-detail">
      <div className="process-detail__header">
        <h3 className="process-detail__title">Process detail</h3>
        <button
          type="button"
          className="process-detail__close"
          onClick={onClose}
          aria-label="Close"
        >
          &times;
        </button>
      </div>

      <dl className="process-detail__list">
        <dt>PID</dt>
        <dd>{node.pid}</dd>
        <dt>PPID</dt>
        <dd>{node.ppid}</dd>
        <dt>Path</dt>
        <dd className="process-detail__break">{node.path || "(unknown)"}</dd>
        {node.args && (
          <>
            <dt>Args</dt>
            <dd className="process-detail__break">{node.args.join(" ")}</dd>
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
            <dd className="process-detail__hash">{node.sha256}</dd>
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
              {node.exit_code === undefined ? "" : ` (code ${String(node.exit_code)})`}
            </dd>
          </>
        )}
      </dl>

      <div className="process-detail__kill">
        <Button
          variant="alert"
          size="small"
          onClick={handleKillProcess}
          disabled={killDisabled}
        >
          Kill process
        </Button>
        {killCommand && (
          <span className={`process-detail__cmd-status process-detail__cmd-status--${killCommand.status}`}>
            {killCommand.status}
            {killCommand.status === "failed"
              && typeof killCommand.result?.error === "string"
              ? `: ${killCommand.result.error}`
              : ""}
            {killCommand.status === "completed" ? " — process killed" : ""}
          </span>
        )}
      </div>

      {loading && <p className="process-detail__loading">Loading network data...</p>}

      {detail?.re_exec_chain && detail.re_exec_chain.length > 0 && (
        <div className="process-detail__reexec">
          <h4 className="process-detail__reexec-title">
            Re-exec chain{" "}
            <span className="process-detail__reexec-count">
              ({detail.re_exec_chain.length} prior
              {detail.re_exec_chain.length === 1 ? " generation" : " generations"})
            </span>
          </h4>
          <ol className="process-detail__reexec-list">
            {detail.re_exec_chain.map((gen) => (
              <li key={gen.id} className="process-detail__reexec-item">
                <code className="process-detail__break">{gen.path || "(unknown)"}</code>
                {gen.exec_time_ns !== undefined && (
                  <span className="process-detail__reexec-time">
                    {" — exec @ "}
                    {formatTimestamp(gen.exec_time_ns)}
                  </span>
                )}
              </li>
            ))}
            <li className="process-detail__reexec-item process-detail__reexec-item--current">
              <code className="process-detail__break">{node.path || "(unknown)"}</code>
              <span className="process-detail__reexec-time"> — current</span>
            </li>
          </ol>
        </div>
      )}

      {detail && (
        <NetworkConnections
          connections={detail.network_connections}
          dnsQueries={detail.dns_queries}
        />
      )}

      {alerts.length > 0 && (
        <div className="process-detail__alerts">
          <h4 className="process-detail__alerts-title">Alerts</h4>
          {alerts.map((a) => (
            <div key={a.id} className="process-detail__alert">
              <div className="process-detail__alert-header">
                <Badge variant={SEVERITY_VARIANTS[a.severity] ?? "neutral"}>
                  {a.severity}
                </Badge>
                <span className={`status-text status-text--${a.status}`}>{a.status}</span>
              </div>
              <div className="process-detail__alert-title">{a.title}</div>
              <div className="process-detail__alert-desc">{a.description}</div>
              <div className="process-detail__alert-actions">
                {a.status === "open" && (
                  <Button
                    size="small"
                    variant="inverse"
                    onClick={() => { handleAlertStatusChange(a.id, "acknowledged"); }}
                  >
                    Acknowledge
                  </Button>
                )}
                {a.status !== "resolved" && (
                  <Button
                    size="small"
                    variant="inverse"
                    onClick={() => { handleAlertStatusChange(a.id, "resolved"); }}
                  >
                    Resolve
                  </Button>
                )}
                {a.status === "resolved" && (
                  <Button
                    size="small"
                    variant="inverse"
                    onClick={() => { handleAlertStatusChange(a.id, "open"); }}
                  >
                    Reopen
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      <ReauthModal {...killReauthModal} />
      <ReauthModal {...alertReauthModal} />
    </Card>
  );
}

function formatTimestamp(ns: number): string {
  return new Date(ns / NANOSECONDS_PER_MILLISECOND).toLocaleTimeString();
}
