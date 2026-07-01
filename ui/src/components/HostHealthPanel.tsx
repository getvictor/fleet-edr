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

  useEffect(() => {
    let cancelled = false;
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
  return (
    <Card className="host-health" padding="medium">
      <div className="host-health__header">
        <span className="host-health__title">Agent health</span>
        <HealthBadge status={health.overall_status} />
      </div>
      {components.length === 0 ? (
        <p className="host-health__empty">No component health reported yet.</p>
      ) : (
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
