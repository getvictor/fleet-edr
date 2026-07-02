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

// isOnline classifies a host by its last-seen timestamp against the shared offline threshold. One predicate for the Hosts list pill,
// the fleet summary cards, and the host detail header, so every surface agrees on what "online" means.
export function isOnline(lastSeenNs: number): boolean {
  if (lastSeenNs === 0) return false;
  return Date.now() - lastSeenNs / NANOSECONDS_PER_MILLISECOND < OFFLINE_THRESHOLD_MINUTES * MILLISECONDS_PER_MINUTE;
}
