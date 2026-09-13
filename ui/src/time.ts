import {
  MILLISECONDS_PER_DAY,
  MILLISECONDS_PER_HOUR,
  MILLISECONDS_PER_MINUTE,
  NANOSECONDS_PER_MILLISECOND,
  OFFLINE_THRESHOLD_MINUTES,
} from "./constants";

// formatRelativeNs renders a nanosecond epoch timestamp as a compact age relative to now ("never", "just now", "5m ago", "2h ago",
// "3d ago"). Shared by the Hosts list (last-seen) and the host-health panel (a component's time-in-state), so the two surfaces phrase
// relative time identically.
export function formatRelativeNs(ns: number): string {
  if (ns === 0) return "never";
  const diff = Date.now() - ns / NANOSECONDS_PER_MILLISECOND;
  if (diff < MILLISECONDS_PER_MINUTE) return "just now";
  if (diff < MILLISECONDS_PER_HOUR) return `${String(Math.floor(diff / MILLISECONDS_PER_MINUTE))}m ago`;
  if (diff < MILLISECONDS_PER_DAY) return `${String(Math.floor(diff / MILLISECONDS_PER_HOUR))}h ago`;
  return `${String(Math.floor(diff / MILLISECONDS_PER_DAY))}d ago`;
}

// formatElapsedNs renders how long something LASTED ("36s", "5m", "2h 14m", "1d 13h"), from a nanosecond span rather than an epoch
// instant. It is the counterpart to formatRelativeNs, which says how long AGO something happened: a resolved sensor fault needs both,
// when it ended and how long the host went uncaptured, and they must not be confused on the page.
//
// Two units at most, and the smaller one is dropped when it is zero, because the question an operator is answering is "was this a
// blip or a day", not the exact figure. A negative or zero span renders "0s" rather than a nonsensical negative duration; the server
// already refuses to record an episode that ends before it began, so this only guards a clock the page itself is reading.
//
// The span is ROUNDED to the nearest second, not floored, and that is load-bearing. A caller computes it by subtracting two epoch
// nanosecond instants, and those exceed Number.MAX_SAFE_INTEGER, so the difference can land a few hundred nanoseconds short of the
// true value. Flooring would then turn an exact 2h 14m into "2h 13m", on real data and not only in tests.
export function formatElapsedNs(spanNs: number): string {
  const totalSeconds = Math.max(0, Math.round(spanNs / NANOSECONDS_PER_MILLISECOND / 1000));
  const secondsPerMinute = MILLISECONDS_PER_MINUTE / 1000;
  const secondsPerHour = MILLISECONDS_PER_HOUR / 1000;
  const secondsPerDay = MILLISECONDS_PER_DAY / 1000;
  const pair = (major: number, majorUnit: string, minor: number, minorUnit: string): string =>
    minor > 0 ? `${String(major)}${majorUnit} ${String(minor)}${minorUnit}` : `${String(major)}${majorUnit}`;
  if (totalSeconds < secondsPerMinute) return `${String(totalSeconds)}s`;
  if (totalSeconds < secondsPerHour) return `${String(Math.floor(totalSeconds / secondsPerMinute))}m`;
  if (totalSeconds < secondsPerDay) {
    return pair(Math.floor(totalSeconds / secondsPerHour), "h", Math.floor((totalSeconds % secondsPerHour) / secondsPerMinute), "m");
  }
  return pair(Math.floor(totalSeconds / secondsPerDay), "d", Math.floor((totalSeconds % secondsPerDay) / secondsPerHour), "h");
}

// formatRelativeISO renders an RFC 3339 timestamp as the same compact age formatRelativeNs produces, for the surfaces whose API
// returns a formatted timestamp rather than a nanosecond epoch (the detection-tuning match counts). It delegates rather than
// re-buckets so the two can never drift in how they phrase recency.
//
// An unparseable value renders as the empty string rather than "Invalid Date", leaving the caller to omit the element instead of
// showing a broken one.
export function formatRelativeISO(iso: string): string {
  const ms = new Date(iso).getTime();
  if (Number.isNaN(ms)) return "";
  return formatRelativeNs(ms * NANOSECONDS_PER_MILLISECOND);
}

// isOnline classifies a host by its last-seen timestamp against the shared offline threshold. One predicate for the Hosts list pill,
// the fleet summary cards, and the host detail header, so every surface agrees on what "online" means.
export function isOnline(lastSeenNs: number): boolean {
  if (lastSeenNs === 0) return false;
  return Date.now() - lastSeenNs / NANOSECONDS_PER_MILLISECOND < OFFLINE_THRESHOLD_MINUTES * MILLISECONDS_PER_MINUTE;
}
