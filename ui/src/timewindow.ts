import {
  HOURS_PER_DAY,
  MILLISECONDS_PER_HOUR,
  MILLISECONDS_PER_MINUTE,
  NANOSECONDS_PER_MILLISECOND,
} from "./constants";

// TimeWindow is the host page's single source of time truth (issue #581): every view (tree, histogram, control label) derives its
// bounds from one value, so a preset pick, an absolute selection, a shift, or a histogram-bucket click cannot desynchronize them.
// A relative window ends at `now` (or at its anchor: the alert-entry default anchors to the alert time, preserving the alert-pivot
// requirement's wide window). An absolute window is a fixed span.
export type TimeWindow =
  | { kind: "relative"; ms: number; anchorNs?: number }
  | { kind: "absolute"; fromNs: number; toNs: number };

export interface WindowBounds {
  fromNs: number;
  toNs: number;
}

const RANGE_15_MINUTES_IN_MINUTES = 15;
const RANGE_6_HOURS_IN_HOURS = 6;
const DAYS_PER_WEEK = 7;

// RELATIVE_PRESETS are the quick-picks the time control offers. Labels are authoritative; ms derives from named constants so the
// lint catches a mismatched label/duration edit.
export const RELATIVE_PRESETS: { label: string; ms: number }[] = [
  { label: "Last 15 min", ms: RANGE_15_MINUTES_IN_MINUTES * MILLISECONDS_PER_MINUTE },
  { label: "Last 1 hour", ms: MILLISECONDS_PER_HOUR },
  { label: "Last 6 hours", ms: RANGE_6_HOURS_IN_HOURS * MILLISECONDS_PER_HOUR },
  { label: "Last 24 hours", ms: HOURS_PER_DAY * MILLISECONDS_PER_HOUR },
  { label: "Last 7 days", ms: DAYS_PER_WEEK * HOURS_PER_DAY * MILLISECONDS_PER_HOUR },
];

export const DEFAULT_LIVE_WINDOW_MS = MILLISECONDS_PER_HOUR;
export const DEFAULT_ALERT_WINDOW_MS = HOURS_PER_DAY * MILLISECONDS_PER_HOUR;

// windowBounds resolves a window to concrete nanosecond bounds. nowMs is a parameter (not Date.now()) so consumers decide when
// "now" advances (the Refresh action) and tests stay deterministic.
export function windowBounds(window: TimeWindow, nowMs: number): WindowBounds {
  if (window.kind === "absolute") {
    return { fromNs: window.fromNs, toNs: window.toNs };
  }
  const toNs = window.anchorNs ?? nowMs * NANOSECONDS_PER_MILLISECOND;
  return { fromNs: toNs - window.ms * NANOSECONDS_PER_MILLISECOND, toNs };
}

// windowLabel is the time control's at-rest text: the preset wording for an un-anchored relative window, a compact date-time span
// otherwise (an anchored window is a fixed span in disguise, so labeling it "Last 24 hours" would misread). Pure by construction:
// the un-anchored branch labels the width without resolving bounds, and anchored/absolute bounds are independent of "now", so no
// clock read happens during render.
export function windowLabel(window: TimeWindow): string {
  if (window.kind === "relative" && window.anchorNs === undefined) {
    const preset = RELATIVE_PRESETS.find((p) => p.ms === window.ms);
    return preset ? preset.label : `Last ${String(Math.round(window.ms / MILLISECONDS_PER_MINUTE))} min`;
  }
  const { fromNs, toNs } = windowBounds(window, 0);
  return `${formatStamp(fromNs)} to ${formatStamp(toNs)}`;
}

// shiftWindow moves the active window backward or forward by its own width. The result is always absolute: a shifted window is a
// statement about a specific span, not about "now".
export function shiftWindow(window: TimeWindow, direction: -1 | 1, nowMs: number): TimeWindow {
  const { fromNs, toNs } = windowBounds(window, nowMs);
  const width = toNs - fromNs;
  return { kind: "absolute", fromNs: fromNs + direction * width, toNs: toNs + direction * width };
}

function formatStamp(ns: number): string {
  return new Date(ns / NANOSECONDS_PER_MILLISECOND).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
