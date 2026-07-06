import { Link, useSearchParams } from "react-router-dom";
import "./SearchPage.scss";
import { ProcessSearch } from "./ProcessSearch";
import { EventSearch } from "./EventSearch";
import { useHostNames } from "./useHostNames";
import type { EventSearchMode } from "../../api";

// The three search modes. Process is the default (no ?mode= param) so PR 3's pivots (`/search?path=...`) still land on it; the two
// event modes carry ?mode=. Switching mode drops the previous mode's artifact/process filters (a remote address is meaningless as a
// process filter and vice versa) but preserves host_id, the one filter every mode shares.
const MODES: { key: "process" | EventSearchMode; label: string }[] = [
  { key: "process", label: "Processes" },
  { key: "connections", label: "Connections" },
  { key: "dns", label: "DNS" },
];

// SearchPage is the fleet-wide hunting console (issue #582): a mode selector (processes / connections / DNS) over the shared page
// shell. The mode lives in the URL so each mode is bookmarkable and a pivot is a link; the active mode's component owns its own
// filters, fetch, and result table. The host_id -> hostname map is resolved once here and passed to whichever mode renders, so a mode
// switch does not refetch the host list.
export function SearchPage() {
  const [searchParams] = useSearchParams();
  const raw = searchParams.get("mode");
  const mode: "process" | EventSearchMode = raw === "connections" || raw === "dns" ? raw : "process";
  const hostId = searchParams.get("host_id");
  const hostNames = useHostNames();

  // A mode link carries only ?mode= (omitted for process) plus the shared host_id, dropping the other mode's filters.
  const modeHref = (key: "process" | EventSearchMode): string => {
    const next = new URLSearchParams();
    if (key !== "process") next.set("mode", key);
    if (hostId) next.set("host_id", hostId);
    const qs = next.toString();
    const suffix = qs ? `?${qs}` : "";
    return `/search${suffix}`;
  };

  return (
    <div className="search-page">
      <nav className="search-page__modes" aria-label="Search mode">
        {MODES.map((m) => (
          <Link
            key={m.key}
            to={modeHref(m.key)}
            className="search-page__mode"
            aria-current={m.key === mode ? "page" : undefined}
          >
            {m.label}
          </Link>
        ))}
      </nav>

      {/* key={mode} remounts EventSearch on a connections<->dns switch so the FilterChips add-filter state (which is keyed to one
          mode's field set) cannot leak an irrelevant param across modes. */}
      {mode === "process" ? (
        <ProcessSearch hostNames={hostNames} />
      ) : (
        <EventSearch key={mode} mode={mode} hostNames={hostNames} />
      )}
    </div>
  );
}
