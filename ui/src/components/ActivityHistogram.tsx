import { useEffect, useState } from "react";
import "./ActivityHistogram.scss";
import { getActivityHistogram } from "../api";
import type { ActivityHistogram as Histogram } from "../types";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";

// MIN_VISIBLE_BAR_PERCENT keeps a tiny-but-nonzero bucket visible: a 1-count bucket next to a 400-count spike must still read as a
// clickable mark, not vanish into the baseline.
const MIN_VISIBLE_BAR_PERCENT = 6;

interface ActivityHistogramProps {
  readonly hostId: string;
  readonly fromNs: number;
  readonly toNs: number;
  // onSelectBucket narrows the page's active window to one bucket's span (the scrubber, issue #581).
  readonly onSelectBucket: (fromNs: number, toNs: number) => void;
}

// ActivityHistogram is the host page's activity strip: one bar per server-derived bucket of process starts over the active window.
// A single series wears a single hue; bars are real buttons (keyboard-usable, per-mark hover via the accessible label) whose click
// narrows the window. Server-aggregated, so it stays correct even when the rendered tree is truncated. Best-effort like the other
// page decorations: a fetch failure or an empty window renders nothing rather than blocking the tree.
export function ActivityHistogram({ hostId, fromNs, toNs, onSelectBucket }: ActivityHistogramProps) {
  const [hist, setHist] = useState<Histogram | null>(null);

  useEffect(() => {
    // Reset so a stale strip never shows over another window while the new fetch is in flight. Disable set-state-in-effect for the
    // synchronous reset, matching HostHealthPanel.
    /* eslint-disable react-hooks/set-state-in-effect */
    setHist(null);
    /* eslint-enable react-hooks/set-state-in-effect */
    let cancelled = false;
    getActivityHistogram(hostId, fromNs, toNs)
      .then((h) => {
        if (!cancelled) setHist(h);
      })
      .catch(() => {
        // Best-effort decoration; the tree's own fetch surfaces real trouble.
      });
    return () => {
      cancelled = true;
    };
  }, [hostId, fromNs, toNs]);

  if (!hist || hist.total === 0) return null;

  const counts = new Map<number, number>();
  for (const b of hist.buckets ?? []) counts.set(b.start_ns, b.count);
  const slots: { startNs: number; count: number }[] = [];
  let max = 0;
  for (let startNs = fromNs; startNs < toNs; startNs += hist.bucket_ns) {
    const count = counts.get(startNs) ?? 0;
    if (count > max) max = count;
    slots.push({ startNs, count });
  }

  return (
    <div className="activity-histogram" aria-label="Process starts over the selected window">
      {slots.map((slot) => {
        const label = `${formatBucketTime(slot.startNs)} to ${formatBucketTime(slot.startNs + hist.bucket_ns)}: ${String(slot.count)} process starts`;
        return (
          <button
            key={slot.startNs}
            type="button"
            className="activity-histogram__bar"
            disabled={slot.count === 0}
            aria-label={`${label}. Narrow the window to this bucket.`}
            title={label}
            onClick={() => { onSelectBucket(slot.startNs, slot.startNs + hist.bucket_ns); }}
          >
            <span
              className="activity-histogram__fill"
              style={{ height: `${String(slot.count === 0 ? 0 : Math.max(MIN_VISIBLE_BAR_PERCENT, (slot.count / max) * 100))}%` }}
            />
          </button>
        );
      })}
    </div>
  );
}

function formatBucketTime(ns: number): string {
  return new Date(ns / NANOSECONDS_PER_MILLISECOND).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
