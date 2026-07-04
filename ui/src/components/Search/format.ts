import { NANOSECONDS_PER_MILLISECOND } from "../../constants";

// Shared row formatters for the search modes (issue #582). Kept in one module so the process and event tables render times and paths
// identically and neither re-implements them.

// formatNs renders an ns-since-epoch timestamp as a locale date-time string.
export function formatNs(ns: number): string {
  return new Date(ns / NANOSECONDS_PER_MILLISECOND).toLocaleString();
}

// basename returns the last path segment (handling both / and \ separators), or the whole string when it has no separator.
export function basename(path: string): string {
  const idx = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return idx >= 0 ? path.slice(idx + 1) : path;
}
