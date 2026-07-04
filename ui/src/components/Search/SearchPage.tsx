import { Link, useSearchParams } from "react-router-dom";
import "./SearchPage.scss";
import { PageHeader } from "../ui/PageHeader";
import { ProcessSearch } from "./ProcessSearch";
import { EventSearch } from "./EventSearch";
import type { EventSearchMode } from "../../api";

// The three search modes. Process is the default (no ?mode= param) so PR 3's pivots (`/search?path=...`) still land on it; the two
// event modes carry ?mode= and target the connection/DNS endpoints. Switching mode navigates with only ?mode= set, dropping the
// previous mode's filter params (a remote address is meaningless as a process filter and vice versa).
const MODES: { key: "process" | EventSearchMode; label: string; to: string }[] = [
  { key: "process", label: "Processes", to: "/search" },
  { key: "connections", label: "Connections", to: "/search?mode=connections" },
  { key: "dns", label: "DNS", to: "/search?mode=dns" },
];

// SearchPage is the fleet-wide hunting console (issue #582): a mode selector (processes / connections / DNS) over the shared page
// shell. The mode lives in the URL so each mode is bookmarkable and a pivot is a link; the active mode's component owns its own
// filters, fetch, and result table.
export function SearchPage() {
  const [searchParams] = useSearchParams();
  const raw = searchParams.get("mode");
  const mode: "process" | EventSearchMode = raw === "connections" || raw === "dns" ? raw : "process";

  return (
    <div className="search-page">
      <PageHeader title="Search" subtitle="Hunt processes, connections, and DNS across every host." />

      <nav className="search-page__modes" aria-label="Search mode">
        {MODES.map((m) => (
          <Link
            key={m.key}
            to={m.to}
            className="search-page__mode"
            aria-current={m.key === mode ? "page" : undefined}
          >
            {m.label}
          </Link>
        ))}
      </nav>

      {mode === "process" ? <ProcessSearch /> : <EventSearch mode={mode} />}
    </div>
  );
}
