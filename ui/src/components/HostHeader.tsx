import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router";
import "./HostHeader.scss";
import { getHostDetail, getHostHealth } from "../api";
import type { HostDetail, HostHealth, HostHealthEpisode } from "../types";
import { PageHeader } from "./ui/PageHeader";
import { CopyButton } from "./ui/CopyButton";
import { HealthBadge } from "./ui/HealthBadge";
import { useDismiss } from "./ui/useDismiss";
import { formatElapsedNs, formatRelativeNs, isOnline } from "../time";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";

interface HostHeaderProps {
  readonly hostId: string;
  readonly actions?: ReactNode;
}

// Friendly labels for the component types shipped today. An unrecognized type (a future signal) falls back to its raw identifier.
const COMPONENT_LABELS: Record<string, string> = {
  endpoint_security_extension: "Security extension",
  network_extension: "Network extension",
  // Agent-reported capture providers (issue #702). The network extension reports each one separately, so a wedged provider is
  // distinguishable from a healthy host rather than hidden inside the extension's single rollup above.
  content_filter: "Content filter",
  dns_proxy: "DNS proxy",
  // Server-derived conditions (issue #677). Labelled by what stopped arriving rather than by the provider's internal name, since
  // that is what the operator is being told: the extension says it is fine, but this capture is not reaching us.
  content_filter_delivery: "Connection capture",
  dns_proxy_delivery: "DNS capture",
};

// healthDotClass maps the rollup to the attention dot on the Details trigger: none when healthy (green is "no news") or unknown (no
// snapshot yet, nothing actionable), amber when degraded, red when unhealthy. So the operator only sees a marker when something needs
// their attention, and the full conditions live one click away in the popover.
function healthDotClass(status: string | undefined): string | null {
  if (status === "degraded") return "host-header__health-dot--warn";
  if (status === "unhealthy") return "host-header__health-dot--crit";
  return null;
}

// HostHeader is the host page's identity header (issue #579). It leads with the enrollment hostname (falling back to the raw host id),
// an online/offline pill on the host list's shared 5-minute predicate, and a "Details" popover holding the reference facts (raw id +
// copy, agent version, source IP, event count, enrollment date, exact last-seen). The always-visible meta row stays to the essentials:
// the OS identity, plus "last seen" only when offline (when online the pill already conveys liveness). Best-effort by design: the detail
// fetch failing (or not yet resolved) degrades to the raw-id title and never blocks the process tree below it. The title links to the
// bare host page so an operator in an alert-context view can drop the ?alert=...&process=...&at=... params.
export function HostHeader({ hostId, actions }: HostHeaderProps) {
  const [detail, setDetail] = useState<HostDetail | null>(null);

  useEffect(() => {
    // Reset on hostId change so a stale header never shows over another host (React Router re-renders without unmounting). Disable
    // set-state-in-effect for the synchronous reset, matching ProcessTree.
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
      {detail && (
        <span className={online ? "status-pill status-pill--online" : "status-pill status-pill--offline"}>
          {online ? "online" : "offline"}
        </span>
      )}
      {detail && <HostDetailsPopover detail={detail} />}
    </span>
  );

  return <PageHeader title={title} subtitle={detail ? metaRow(detail, online) : undefined} actions={actions} />;
}

// metaRow renders only the at-a-glance identity facts as dot-separated segments: the OS, and "last seen" only when the host is offline
// (when online the pill already says so). Everything else moved into the Details popover. Returns undefined when nothing is known so the
// PageHeader renders no subtitle rather than an empty row.
function metaRow(detail: HostDetail, online: boolean): ReactNode {
  const os = [detail.os_name, detail.os_version].filter(Boolean).join(" ");
  const segments: ReactNode[] = [];
  if (os) segments.push(<span key="os">{detail.os_build ? `${os} (${detail.os_build})` : os}</span>);
  if (!online) segments.push(<span key="seen">last seen {formatRelativeNs(detail.last_seen_ns)}</span>);
  if (segments.length === 0) return undefined;
  return <span className="host-header__meta">{segments}</span>;
}

// labelFor looks up an open-vocabulary wire value in a label table, returning undefined for anything the table does not itself define.
//
// The own-property check is the point. A plain object also answers for its inherited keys, and these values come from the agent: a
// subject of "__proto__" indexed straight into COMPONENT_LABELS yields Object.prototype, which React refuses to render, so a malformed or
// compromised sensor report would throw the moment an operator opened the host's Details. An outcome of "toString" would likewise return
// a function instead of falling back. Only a key the table was written with is a label.
function labelFor(table: Readonly<Record<string, string>>, key: string): string | undefined {
  // eslint-disable-next-line security/detect-object-injection -- guarded by the own-property check on the line itself
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

// OUTCOME_LABELS phrase a self_heal_failed episode's outcome for an operator. The two shapes point at different fixes, so they are
// spelled out rather than shown as their wire names. An outcome this build does not recognise renders nothing rather than the raw
// value, since the title and description already say the repair gave up.
const OUTCOME_LABELS: Record<string, string> = {
  enable_failed: "the repair command kept failing",
  enable_ineffective: "repairs reported success but it stayed stopped",
};

// episodeDetailString reads one string field from an episode's per-kind detail, or "" when it is absent or not a string. The detail's
// shape belongs to the episode kind, so nothing here assumes a field exists.
function episodeDetailString(episode: HostHealthEpisode, field: string): string {
  // eslint-disable-next-line security/detect-object-injection -- a fixed field name from this file, not user input
  const value = episode.detail?.[field];
  return typeof value === "string" ? value : "";
}

// HostHealthEpisodes lists the host's recorded sensor faults (issue #778): the ones still open, then recent resolved ones with how
// long each lasted. It renders nothing for a host with no recorded faults, keeping to the popover's rule that a clean host shows no
// health chrome.
//
// Kept apart from the component list above it on purpose. Those rows say what is true NOW and are overwritten as it changes; these are
// the durable record, and a resolved fault still belongs here after its component has long since recovered.
function HostHealthEpisodes({ episodes }: { readonly episodes: readonly HostHealthEpisode[] }) {
  if (episodes.length === 0) return null;
  return (
    <div className="host-header__episodes">
      <span className="host-header__details-label">Sensor faults</span>
      <ul className="host-header__health-list">
        {episodes.map((e) => {
          const open = e.resolved_at_ns === undefined;
          // `||`, not `??`: an empty subject means "the component as a whole", the same as an absent one, and must fall back too.
          const partKey = e.subject || e.component;
          const part = labelFor(COMPONENT_LABELS, partKey) ?? partKey;
          const outcome = labelFor(OUTCOME_LABELS, episodeDetailString(e, "outcome")) ?? "";
          return (
            <li key={e.id} className="host-header__health-item">
              <div className="host-header__health-item-head">
                <HealthBadge status={open ? "unhealthy" : "healthy"} />
                <span className="host-header__health-component">{part}</span>
              </div>
              {/* The message and the timing are separate lines, not one row as the component conditions use. A component's age is a
                  short "46m ago", but a resolved fault's timing ("lasted 2h 14m, ended 46m ago") is long and does not wrap, so on one
                  row it squeezed the message into a column a word or two wide, and faults with different timings rendered in
                  different shapes at the same width. */}
              <span className="host-header__health-message">{outcome ? `${e.title}: ${outcome}` : e.title}</span>
              <span className="host-header__episode-when">
                {e.resolved_at_ns === undefined
                  ? `opened ${formatRelativeNs(e.opened_at_ns)}`
                  : `lasted ${formatElapsedNs(e.resolved_at_ns - e.opened_at_ns)}, ended ${formatRelativeNs(e.resolved_at_ns)}`}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// HostDetailsPopover is the click-open reference panel for the host's secondary facts (issue #579 simplification). It keeps the raw id,
// its copy control, agent version, source IP, event count, exact last-seen, enrollment date, and the agent-health conditions out of the
// always-visible header. The trigger carries an attention dot only when agent health needs attention, so a clean host shows no health
// chrome at all. Closes on outside-click and Escape, mirroring AccountMenu's disclosure pattern.
function HostDetailsPopover({ detail }: { readonly detail: HostDetail }) {
  const { open, setOpen, ref } = useDismiss<HTMLDivElement>();
  const [health, setHealth] = useState<HostHealth | null>(null);

  useEffect(() => {
    // Reset on host_id change (and clear on a failed fetch) so the attention dot and health section never show the previous host's
    // agent health, matching the header's own detail reset. Disable set-state-in-effect for the synchronous reset.
    /* eslint-disable react-hooks/set-state-in-effect */
    setHealth(null);
    /* eslint-enable react-hooks/set-state-in-effect */
    let cancelled = false;
    getHostHealth(detail.host_id)
      .then((h) => {
        if (!cancelled) setHealth(h);
      })
      .catch(() => {
        if (!cancelled) setHealth(null);
      });
    return () => {
      cancelled = true;
    };
  }, [detail.host_id]);

  const dotClass = healthDotClass(health?.overall_status);
  // Agent-reported conditions first, then the server's own. One list, because an operator diagnosing a host wants every condition in
  // one place; the derived ones read as distinct through their labels and their "reports healthy, but..." message.
  const components = [...(health?.components ?? []), ...(health?.derived_components ?? [])];

  return (
    <div className="host-header__details" ref={ref}>
      <button
        type="button"
        className="host-header__details-trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        title={dotClass ? "Agent needs attention" : undefined}
        onClick={() => {
          setOpen((v) => !v);
        }}
      >
        Details
        {dotClass && <span className={`host-header__health-dot ${dotClass}`} aria-hidden="true" />}
        {dotClass && <span className="host-header__sr-only">agent needs attention</span>}
      </button>
      {open && (
        <div className="host-header__details-popover" role="dialog" aria-label="Host details">
          {health && (
            <div className="host-header__health">
              <div className="host-header__health-head">
                <span className="host-header__details-label">Agent health</span>
                <HealthBadge status={health.overall_status} prefix="Agent" />
              </div>
              {components.length > 0 && (
                <ul className="host-header__health-list">
                  {components.map((c) => (
                    <li key={c.type} className="host-header__health-item">
                      {/* Two explicit rows rather than one wrapping row. As a single flex line that wraps on overflow, where the
                          message landed depended on how long the component's NAME was: "DNS proxy" is short enough that its
                          message fitted beside it while the three longer names pushed theirs onto the next line, so four
                          components in one panel rendered in two different shapes at the same width. */}
                      <div className="host-header__health-item-head">
                        <HealthBadge status={c.status} />
                        <span className="host-header__health-component">{labelFor(COMPONENT_LABELS, c.type) ?? c.type}</span>
                      </div>
                      {/* Server-derived conditions carry no transition instant (see HostHealth.derived_components); rendering one
                          would date a possibly days-old fault to the moment the page loaded. */}
                      {(c.message || c.last_transition_ns > 0) && (
                        <div className="host-header__health-detail">
                          {c.message ? <span className="host-header__health-message">{c.message}</span> : null}
                          {c.last_transition_ns > 0 && (
                            <span className="host-header__health-since">{formatRelativeNs(c.last_transition_ns)}</span>
                          )}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
              <HostHealthEpisodes episodes={health.episodes} />
            </div>
          )}
          <dl className="host-header__details-list">
            <div className="host-header__details-row">
              <dt>Host ID</dt>
              <dd className="host-header__details-id">
                <span>{detail.host_id}</span>
                <CopyButton value={detail.host_id} label="Copy host id" />
              </dd>
            </div>
            {detail.agent_version && (
              <div className="host-header__details-row">
                <dt>Agent</dt>
                <dd>{detail.agent_version}</dd>
              </div>
            )}
            {detail.source_ip && (
              <div className="host-header__details-row">
                <dt>IP</dt>
                <dd>{detail.source_ip}</dd>
              </div>
            )}
            <div className="host-header__details-row">
              <dt>Events</dt>
              <dd>{detail.event_count.toLocaleString()}</dd>
            </div>
            <div className="host-header__details-row">
              <dt>Last seen</dt>
              <dd>{formatRelativeNs(detail.last_seen_ns)}</dd>
            </div>
            {detail.enrolled_at_ns > 0 && (
              <div className="host-header__details-row">
                <dt>Enrolled</dt>
                <dd>{new Date(detail.enrolled_at_ns / NANOSECONDS_PER_MILLISECOND).toLocaleDateString()}</dd>
              </div>
            )}
          </dl>
        </div>
      )}
    </div>
  );
}
