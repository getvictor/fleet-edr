import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import "./HostHeader.scss";
import { getHostDetail } from "../api";
import type { HostDetail } from "../types";
import { PageHeader } from "./ui/PageHeader";
import { CopyButton } from "./ui/CopyButton";
import { formatRelativeNs, isOnline } from "../time";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";

interface HostHeaderProps {
  readonly hostId: string;
  readonly actions?: ReactNode;
}

// HostHeader is the host page's identity header (issue #579): the enrollment hostname as the title (falling back to the raw host id),
// an online/offline pill on the host list's shared 5-minute predicate, and a meta row with the OS identity the inventory check-in
// keeps fresh, the agent version, liveness, source IP, event count, and enrollment date. Best-effort by design: the detail fetch
// failing (or not yet resolved) degrades to the raw-id title and never blocks the process tree below it. The title links to the bare
// host page so an operator in an alert-context view can drop the ?alert=...&process=...&at=... params without the host list.
export function HostHeader({ hostId, actions }: HostHeaderProps) {
  const [detail, setDetail] = useState<HostDetail | null>(null);

  useEffect(() => {
    // Reset on hostId change so a stale header never shows over another host (React Router re-renders without unmounting). Disable
    // set-state-in-effect for the synchronous reset, matching HostHealthPanel and ProcessTree.
    /* eslint-disable react-hooks/set-state-in-effect */
    setDetail(null);
    /* eslint-enable react-hooks/set-state-in-effect */
    let cancelled = false;
    getHostDetail(hostId)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch(() => {
        // Best-effort: the header degrades to the raw id; errors surface via the tree's own fetch if the server is really down.
      });
    return () => {
      cancelled = true;
    };
  }, [hostId]);

  // Compute once per render so the pill's class and label cannot straddle the threshold between two Date.now() reads.
  const online = detail ? isOnline(detail.last_seen_ns) : false;

  const title = (
    <span className="host-header__title">
      <Link to={`/hosts/${encodeURIComponent(hostId)}`} className="process-tree__host-link">
        {detail?.hostname ? detail.hostname : hostId}
      </Link>
      <CopyButton value={hostId} label="Copy host id" />
      {detail && (
        <span className={online ? "status-pill status-pill--online" : "status-pill status-pill--offline"}>
          {online ? "online" : "offline"}
        </span>
      )}
    </span>
  );

  return <PageHeader title={title} subtitle={detail ? metaRow(detail) : undefined} actions={actions} />;
}

// metaRow renders the identity/liveness facts as dot-separated segments. Empty fields (never enrolled, degraded collector) drop their
// segment rather than rendering a dash, so the row only states what the server actually knows.
function metaRow(detail: HostDetail) {
  const os = [detail.os_name, detail.os_version].filter(Boolean).join(" ");
  const segments: ReactNode[] = [];
  if (os) segments.push(<span key="os">{detail.os_build ? `${os} (${detail.os_build})` : os}</span>);
  if (detail.agent_version) segments.push(<span key="agent">agent {detail.agent_version}</span>);
  segments.push(<span key="seen">last seen {formatRelativeNs(detail.last_seen_ns)}</span>);
  if (detail.source_ip) segments.push(<span key="ip">{detail.source_ip}</span>);
  segments.push(<span key="events">{detail.event_count.toLocaleString()} events</span>);
  if (detail.enrolled_at_ns > 0) {
    segments.push(
      <span key="enrolled">enrolled {new Date(detail.enrolled_at_ns / NANOSECONDS_PER_MILLISECOND).toLocaleDateString()}</span>,
    );
  }
  // The raw id stays visible for log correlation even when the hostname takes the title slot.
  if (detail.hostname) segments.push(<span key="id" className="host-header__host-id">{detail.host_id}</span>);
  return <span className="host-header__meta">{segments}</span>;
}
