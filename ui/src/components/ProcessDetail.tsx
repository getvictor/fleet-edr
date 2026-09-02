import { useEffect, useState, useCallback, useMemo, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import {
  getProcessDetail,
  listAlertsByProcessId,
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
import { CopyButton } from "./ui/CopyButton";
import { Button } from "./ui/Button";
import { TechniqueTags } from "./TechniqueTags";
import { Badge, type BadgeVariant } from "./ui/Badge";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";
import { deriveSigningVerdict, type SigningVerdictKind } from "../signing";
import { formatCommandLine } from "../cmdline";
import { Can } from "../permissions";
import { PermissionAction } from "../permissions-core";
import "./ProcessDetail.scss";

// killCommandPollIntervalMs is the cadence we re-fetch the kill command's
// status while it's still pending/acked. 2s mirrors the agent's command-poll
// interval so the UI sees a state transition within one round-trip.
const KILL_COMMAND_POLL_INTERVAL_MS = 2000;

interface Props {
  readonly hostId: string;
  readonly node: ProcessNode;
  readonly onClose: () => void;
  // currentAlertId is the alert whose page is open (when entered from an alert). Its own row is dropped from "Related alerts" so the
  // panel never links back to the page you are already on; other alerts on the process still show.
  readonly currentAlertId?: number;
}

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

// VERDICT_BADGE maps the signer category to the panel badge's tone: the two identity-less categories read as attention (high for no
// signature at all, medium for ad-hoc), a verifiable Developer ID reads informational, and platform/signed are neutral facts.
// SearchPivot is the "search all hosts for this artifact" affordance next to an evidence row (issue #582): an icon button (a magnifying
// glass, boxed to match the copy button so the two line up in the row's trailing action column) linking to the fleet-wide search
// pre-filtered by one param. Rendered only for artifacts the search endpoint can filter (path, hash, uid, signing verdict).
function SearchPivot({ param, value, label }: { readonly param: string; readonly value: string; readonly label: string }) {
  const qs = new URLSearchParams({ [param]: value }).toString();
  return (
    <Link className="process-detail__pivot" to={`/search?${qs}`} aria-label={label} title={label}>
      <svg
        viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"
        fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"
      >
        <circle cx="7" cy="7" r="4.5" />
        <path d="m10.5 10.5 4 4" />
      </svg>
    </Link>
  );
}

interface EvidenceRowProps {
  readonly label: string;
  readonly children: ReactNode;
  // valueClassName carries per-row value treatments (break-all for paths, the smaller mono size for hashes).
  readonly valueClassName?: string;
  readonly copy?: { readonly value: string; readonly label: string };
  readonly pivot?: { readonly param: string; readonly value: string; readonly label: string };
}

// EvidenceRow is one label/value pair in the process-detail grid. The value takes the row's width and any copy / fleet-search
// affordances sit in a fixed trailing cluster, so the icons form one aligned column down the panel instead of scattering inline
// after each value (issue: the copy + "search all hosts" controls looked unaligned and oversized).
function EvidenceRow({ label, children, valueClassName, copy, pivot }: EvidenceRowProps) {
  const valueClass = valueClassName ? `process-detail__value ${valueClassName}` : "process-detail__value";
  return (
    <>
      <dt>{label}</dt>
      <dd className="process-detail__row">
        <span className={valueClass}>{children}</span>
        {(copy || pivot) && (
          <span className="process-detail__row-actions">
            {copy && <CopyButton value={copy.value} label={copy.label} />}
            {pivot && <SearchPivot param={pivot.param} value={pivot.value} label={pivot.label} />}
          </span>
        )}
      </dd>
    </>
  );
}

const VERDICT_BADGE: Record<SigningVerdictKind, BadgeVariant> = {
  unsigned: "high",
  invalid: "high",
  "ad-hoc": "medium",
  "developer-id": "info",
  platform: "neutral",
  signed: "neutral",
};

export function ProcessDetail({ hostId, node, onClose, currentAlertId }: Props) {
  const [searchParams] = useSearchParams();
  // Show-in-timeline preserves the host page's other params (notably ?at= / ?alert=, which anchor the shared time window) so the
  // graph->timeline pivot keeps the window; it only swaps the graph's ?process= selection for the timeline's view + pid emphasis.
  const timelineParams = new URLSearchParams(searchParams);
  timelineParams.set("view", "timeline");
  timelineParams.set("pid", String(node.pid));
  timelineParams.delete("process");
  const timelineHref = `/hosts/${encodeURIComponent(hostId)}?${timelineParams.toString()}`;

  const [detail, setDetail] = useState<ProcessDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [killCommand, setKillCommand] = useState<Command | null>(null);
  const [killSending, setKillSending] = useState(false);

  const atTime = node.exec_time_ns || node.fork_time_ns;

  useEffect(() => {
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    getProcessDetail(hostId, node.pid, atTime, node.pidversion)
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
  }, [hostId, node.pid, atTime, node.pidversion]);

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

  // kill_process is reauth-gated by the chokepoint when the session is stale. Wrap it through useReauthRetry so the operator gets an
  // inline reauth modal + the action retries on success. Kill on a fresh session passes through unchanged: useReauthRetry is a no-op
  // until the chokepoint throws ReauthRequiredError. Alert triage (acknowledge / resolve / reopen) lives on the alert header now, not
  // here: the node inspector references the process's alerts as links rather than owning their lifecycle.
  // Pin the kill to the exact process generation the operator is looking at: include pidversion so the agent refuses the kill if this PID
  // has since been reused or re-exec'd (issue #627). Omitted for pre-migration / boot-snapshot nodes that carry no pidversion, where the
  // agent falls back to a pid-only kill.
  const killPayload = useMemo<Record<string, unknown>>(
    // node.pidversion is number | undefined (ProcessNode in types.ts); the API contract never yields null, so an absent generation is exactly
    // undefined. Omit the field entirely in that case (pid-only kill) rather than send pidversion: null.
    () => (node.pidversion === undefined ? { pid: node.pid } : { pid: node.pid, pidversion: node.pidversion }),
    [node.pid, node.pidversion],
  );
  const sendKillCommand = useCallback(
    async (): Promise<{ id: number }> => createCommand(hostId, "kill_process", killPayload),
    [hostId, killPayload],
  );
  const { call: callKill, modal: killReauthModal } = useReauthRetry(sendKillCommand);

  const handleKillProcess = useCallback(() => {
    if (killSending) return;
    setKillSending(true);
    callKill()
      .then((res) => {
        setKillCommand({
          id: res.id,
          host_id: hostId,
          command_type: "kill_process",
          payload: killPayload,
          status: "pending",
          created_at: new Date().toISOString(),
        });
      })
      .catch((err: unknown) => {
        // Cancelled reauth surfaces as ReauthRequiredError (the hook
        // rethrows the original gate-deny when the operator dismisses
        // the modal). That isn't a send failure: no command was
        // ever dispatched. Leave killCommand untouched so the UI
        // returns to its pre-click state instead of showing a
        // misleading "Failed to send command" row.
        if (err instanceof ReauthRequiredError) return;
        setKillCommand({
          id: 0,
          host_id: hostId,
          command_type: "kill_process",
          payload: killPayload,
          status: "failed",
          created_at: new Date().toISOString(),
          result: { error: "Failed to send command" },
        });
      })
      .finally(() => { setKillSending(false); });
  }, [callKill, hostId, killPayload, killSending]);

  const verdict = deriveSigningVerdict(node.code_signing);

  // Drop the alert whose page is already open so "Related alerts" never links back to itself; other alerts on this process remain.
  const relatedAlerts = currentAlertId === undefined ? alerts : alerts.filter((a) => a.id !== currentAlertId);

  // A process that has already exited cannot be killed: kill targets a live PID, and once the process is gone that PID is either free or
  // reused by an unrelated process (the exit_reason pid_reuse / reexec cases), so a kill-by-pid could hit the wrong process. Grey the
  // control out and say why, matching how EDR consoles disable a response action once its target is no longer running.
  const processExited = node.exit_time_ns !== undefined && node.exit_time_ns > 0;
  const killDisabled = processExited
    || killSending
    || (killCommand !== null
      && killCommand.status !== "completed"
      && killCommand.status !== "failed");
  const killTitle = processExited ? "This process has already exited, so it can no longer be killed" : undefined;

  return (
    <Card padding="medium" className="process-detail">
      <div className="process-detail__header">
        <h3 className="process-detail__title">Process detail</h3>
        {/* Show in timeline (issue #583): switch to the host's flat event stream with this process's rows emphasized, the reverse of
            a timeline row's "open in graph" pivot. */}
        <Link
          className="process-detail__timeline-link"
          to={timelineHref}
          title="Show this process's events in the timeline"
        >
          Show in timeline
        </Link>
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
        <EvidenceRow label="PID">{node.pid}</EvidenceRow>
        <EvidenceRow label="PPID">{node.ppid}</EvidenceRow>
        <EvidenceRow
          label="Path"
          valueClassName="process-detail__break"
          copy={node.path ? { value: node.path, label: "Copy path" } : undefined}
          pivot={node.path ? { param: "path", value: node.path, label: "Search all hosts for this path" } : undefined}
        >
          {node.path || "(unknown)"}
        </EvidenceRow>
        {node.args && (
          <EvidenceRow
            label="Args"
            valueClassName="process-detail__break"
            copy={{ value: formatCommandLine(node.args, node.path), label: "Copy command line" }}
          >
            {formatCommandLine(node.args, node.path)}
          </EvidenceRow>
        )}
        {node.uid !== undefined && (
          <EvidenceRow label="UID" pivot={{ param: "uid", value: String(node.uid), label: "Search all hosts for this UID" }}>
            {node.uid}
          </EvidenceRow>
        )}
        {node.gid !== undefined && <EvidenceRow label="GID">{node.gid}</EvidenceRow>}
        {node.sha256 && (
          <EvidenceRow
            label="SHA256"
            valueClassName="process-detail__hash"
            copy={{ value: node.sha256, label: "Copy SHA256" }}
            pivot={{ param: "hash", value: node.sha256, label: "Search all hosts for this hash" }}
          >
            {node.sha256}
          </EvidenceRow>
        )}
        {node.cdhash && (
          <EvidenceRow label="CDHash" valueClassName="process-detail__hash" copy={{ value: node.cdhash, label: "Copy cdhash" }}>
            {node.cdhash}
          </EvidenceRow>
        )}
        {/* Fork-only nodes (no exec yet) run the parent's inherited image and carry no signature of their own; a verdict there
            would be a false conviction, matching the tree tooltip's rule. */}
        {node.exec_time_ns && (
          <EvidenceRow label="Signing" pivot={{ param: "signing", value: verdict.kind, label: "Search all hosts for this signing verdict" }}>
            <Badge variant={VERDICT_BADGE[verdict.kind]}>{verdict.label}</Badge>
          </EvidenceRow>
        )}
        {node.code_signing?.signing_id && (
          <EvidenceRow
            label="Signing ID"
            valueClassName="process-detail__break"
            copy={{ value: node.code_signing.signing_id, label: "Copy signing id" }}
          >
            {node.code_signing.signing_id}
          </EvidenceRow>
        )}
        {node.code_signing?.team_id && (
          <EvidenceRow label="Team ID" copy={{ value: node.code_signing.team_id, label: "Copy team id" }}>
            {node.code_signing.team_id}
          </EvidenceRow>
        )}
        <EvidenceRow label="Fork">{formatTimestamp(node.fork_time_ns)}</EvidenceRow>
        {node.exec_time_ns && <EvidenceRow label="Exec">{formatTimestamp(node.exec_time_ns)}</EvidenceRow>}
        {node.exit_time_ns && (
          <EvidenceRow label="Exit">
            {formatTimestamp(node.exit_time_ns)}
            {node.exit_code === undefined ? "" : ` (code ${String(node.exit_code)})`}
          </EvidenceRow>
        )}
      </dl>

      <Can action={PermissionAction.HostKillProcess}>
        <div className="process-detail__kill">
          <Button
            variant="alert"
            size="small"
            onClick={handleKillProcess}
            disabled={killDisabled}
            title={killTitle}
          >
            Kill process
          </Button>
          {processExited && !killCommand && (
            <span className="process-detail__cmd-status process-detail__cmd-status--exited">process exited</span>
          )}
          {killCommand && (
            <span className={`process-detail__cmd-status process-detail__cmd-status--${killCommand.status}`}>
              {killCommand.status}
              {killCommand.status === "failed"
                && typeof killCommand.result?.error === "string"
                ? `: ${killCommand.result.error}`
                : ""}
              {killCommand.status === "completed" ? " - process killed" : ""}
            </span>
          )}
        </div>
      </Can>

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
                    {" - exec @ "}
                    {formatTimestamp(gen.exec_time_ns)}
                  </span>
                )}
              </li>
            ))}
            <li className="process-detail__reexec-item process-detail__reexec-item--current">
              <code className="process-detail__break">{node.path || "(unknown)"}</code>
              <span className="process-detail__reexec-time"> - current</span>
            </li>
          </ol>
        </div>
      )}

      {detail?.flows_truncated && (
        /* The server caps this read, so say when the cap bound. Without it a partial list is indistinguishable from a complete one,
           and an analyst would read absence as evidence the process made no further connections (issue #423's rule, applied to the
           flow lists). */
        <p className="process-detail__truncated">
          Showing the first {detail.network_connections.length + detail.dns_queries.length} network events for this
          process. Narrow the time range or use search to see the rest.
        </p>
      )}

      {detail && (
        <NetworkConnections
          connections={detail.network_connections}
          dnsQueries={detail.dns_queries}
        />
      )}

      {/* Related alerts are references, not a second copy of the alert. Each row links to the alert page, which owns the alert's
          severity/description and its triage (acknowledge / resolve) actions. Restating the full alert card here duplicated what the
          alert breadcrumb + detail already show one panel over. The technique tags stay because they link to the rule doc page (the
          only linked technique surface reachable from the graph, issue #585); everything else collapses to the link. The alert whose
          page is currently open is dropped: linking back to the page you are already on is noise, not a reference. */}
      {relatedAlerts.length > 0 && (
        <div className="process-detail__alerts">
          <h4 className="process-detail__alerts-title">Related alerts</h4>
          <ul className="process-detail__alert-list">
            {relatedAlerts.map((a) => (
              <li key={a.id} className="process-detail__alert-ref">
                <Link className="process-detail__alert-link" to={`/alerts/${String(a.id)}`}>
                  <Badge variant={SEVERITY_VARIANTS[a.severity] ?? "neutral"}>{a.severity}</Badge>
                  <span className="process-detail__alert-name">{a.title}</span>
                  <span className={`status-text status-text--${a.status}`}>{a.status}</span>
                </Link>
                <TechniqueTags techniques={a.techniques} ruleId={a.rule_id} className="process-detail__alert-techniques" />
                {/* Attribution rides even this reference list (issue #765). The list is deliberately minimal, but "minimal" is a
                    presentation choice and the Detection Rule License obligation is not: the row shows a vendored rule's title,
                    which is that rule's output, so it is a surface displaying a match and owes the credit. Absent on alerts
                    raised before the column existed, which render without it. */}
                {a.origin && <div className="process-detail__alert-origin">{a.origin}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}
      <ReauthModal {...killReauthModal} />
    </Card>
  );
}

function formatTimestamp(ns: number): string {
  return new Date(ns / NANOSECONDS_PER_MILLISECOND).toLocaleTimeString();
}
