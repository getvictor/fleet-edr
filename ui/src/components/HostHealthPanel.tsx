import { useEffect, useState } from "react";
import { getHostHealth } from "../api";
import type { HostHealth } from "../types";
import { formatRelativeNs } from "../time";
import { Card } from "./ui/Card";
import { HealthBadge } from "./ui/HealthBadge";
import "./HostHealthPanel.scss";

// Friendly labels for the component types shipped today. An unrecognized type (a future signal) falls back to its raw identifier, so the
// panel keeps rendering without a UI change.
const COMPONENT_LABELS: Record<string, string> = {
  endpoint_security_extension: "Security extension",
  network_extension: "Network extension",
};

// HostHealthPanel shows a host's agent-health conditions on the host detail page: the overall rollup plus one row per component
// (status, message, time-in-state). It fetches on mount and is best-effort: a load failure or the pre-first-fetch state renders nothing
// rather than blocking the process-tree page it sits above.
export function HostHealthPanel({ hostId }: { readonly hostId: string }) {
  const [health, setHealth] = useState<HostHealth | null>(null);
  const [failed, setFailed] = useState(false);
  // When the rollup is healthy the per-component rows just repeat "all good", so they collapse behind this toggle. Only ever set by the
  // user; not-healthy states ignore it and always show the rows so the failing component is visible without a click.
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    // Reset per-host state on hostId change so a prior host's data, a latched failure, or a left-open expander does not persist (React
    // Router re-renders without unmounting). Disable set-state-in-effect for the synchronous reset, matching ProcessTree.tsx.
    /* eslint-disable react-hooks/set-state-in-effect */
    setHealth(null);
    setFailed(false);
    setExpanded(false);
    /* eslint-enable react-hooks/set-state-in-effect */
    getHostHealth(hostId)
      .then((h) => {
        if (!cancelled) setHealth(h);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [hostId]);

  if (failed || !health) return null;

  const components = health.components ?? [];
  const healthy = health.overall_status === "healthy";
  // Show the component rows when something needs attention (always, so the failing one is visible) or when a healthy host's panel has
  // been expanded on demand. A healthy, collapsed panel is just the one-line rollup.
  const showComponents = components.length > 0 && (!healthy || expanded);
  return (
    <Card className="host-health" padding="medium">
      <div className="host-health__header">
        {/* One self-describing pill ("Agent healthy" / "Agent needs attention") instead of a separate label plus a bare status badge. */}
        <HealthBadge status={health.overall_status} prefix="Agent" />
        {healthy && components.length > 0 && (
          <button
            type="button"
            className="host-health__toggle"
            aria-expanded={expanded}
            onClick={() => { setExpanded((v) => !v); }}
          >
            {expanded ? "Hide details" : "Details"}
          </button>
        )}
      </div>
      {components.length === 0 && <p className="host-health__empty">No component health reported yet.</p>}
      {showComponents && (
        <ul className="host-health__list">
          {components.map((c) => (
            <li key={c.type} className="host-health__item">
              <HealthBadge status={c.status} />
              <span className="host-health__component">{COMPONENT_LABELS[c.type] ?? c.type}</span>
              {c.message ? <span className="host-health__message">{c.message}</span> : null}
              <span className="host-health__since">{formatRelativeNs(c.last_transition_ns)}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
