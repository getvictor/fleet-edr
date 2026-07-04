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

// hostPort renders an address + port unambiguously. An IPv6 literal contains colons, so "2606::1:443" is ambiguous; bracket the
// address (`[2606::1]:443`) as the URI authority form does. IPv4 and hostnames pass through as `addr:port`.
export function hostPort(address: string, port: number): string {
  const addr = address.includes(":") ? `[${address}]` : address;
  return `${addr}:${String(port)}`;
}
