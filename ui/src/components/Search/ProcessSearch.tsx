import { useCallback, useMemo } from "react";
import { Link, useSearchParams } from "react-router";
import { searchProcesses, type ProcessSearchFilter } from "../../api";
import type { Process } from "../../types";
import { Table } from "../ui/Table";
import { Badge } from "../ui/Badge";
import { FilterChips, type FilterField } from "./FilterChips";
import { useCursorList, type CursorPage } from "./useCursorList";
import { SearchResultsFrame } from "./SearchResultsFrame";
import { formatNs, basename } from "./format";
import { deriveSigningVerdict } from "../../signing";
import { NANOSECONDS_PER_MILLISECOND } from "../../constants";

// The filter dimensions the process search exposes, in chip order. Signing carries the verdict vocabulary as a fixed option set so
// the chip offers a dropdown rather than free text.
const FILTER_FIELDS: FilterField[] = [
  { key: "host_id", label: "Host" },
  { key: "path", label: "Path" },
  { key: "hash", label: "SHA256" },
  { key: "uid", label: "UID" },
  {
    key: "signing",
    label: "Signing",
    options: [
      { value: "unsigned", label: "Unsigned" },
      { value: "invalid", label: "Invalid" },
      { value: "ad-hoc", label: "Ad-hoc" },
      { value: "developer-id", label: "Developer ID" },
      { value: "platform", label: "Apple platform" },
      { value: "signed", label: "Signed" },
    ],
  },
];

const FILTER_KEYS = FILTER_FIELDS.map((f) => f.key);

// ProcessSearch is the process mode of the fleet-wide search page (issue #582): filter chips over GET /api/search/processes, a
// keyset-paginated result table, and rows that pivot into the host's process tree. Its filter state lives in the URL so a pivot is a
// link and the page is bookmarkable. hostNames (resolved once by the parent) decorates rows with a name over the bare host id.
export function ProcessSearch({ hostNames }: { readonly hostNames: Map<string, string> }) {
  const [searchParams, setSearchParams] = useSearchParams();

  // The active filter is exactly the whitelisted params present in the URL, as a plain key->value record (built with
  // Object.fromEntries to avoid a computed-index write). Serialized as the cursor-list key so any filter change resets and refetches;
  // it doubles as the ProcessSearchFilter passed to the endpoint (every field is an optional string).
  const activeFilter = useMemo<Record<string, string>>(() => {
    const entries = FILTER_KEYS.map((key): [string, string] => [key, searchParams.get(key) ?? ""]).filter(([, v]) => v !== "");
    return Object.fromEntries(entries);
  }, [searchParams]);
  const filter = activeFilter as ProcessSearchFilter;
  const filterKey = useMemo(() => JSON.stringify(activeFilter), [activeFilter]);

  const fetchPage = useCallback(
    async (cursor: string): Promise<CursorPage<Process>> => {
      const res = await searchProcesses(filter, cursor || undefined);
      return { rows: res.rows, nextCursor: res.next_cursor, total: res.total_matched };
    },
    [filterKey], // eslint-disable-line react-hooks/exhaustive-deps -- filter is captured; filterKey is its stable identity
  );
  const { rows, total, loading, error, hasMore, loadMore } = useCursorList(filterKey, fetchPage);

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    setSearchParams(next);
  };

  return (
    <>
      <FilterChips fields={FILTER_FIELDS} active={activeFilter} onChange={setFilter} />
      <SearchResultsFrame
        loading={loading}
        error={error}
        count={rows.length}
        total={total}
        hasMore={hasMore}
        onLoadMore={loadMore}
        emptyLabel="No matching processes."
      >
        <Table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Host</th>
              <th>Process</th>
              <th>Parent</th>
              <th>Command line</th>
              <th>User</th>
              <th>Signing</th>
              <th>Exit</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.id}>
                <td>{formatNs(p.fork_time_ns)}</td>
                <td>{hostNames.get(p.host_id) ?? p.host_id}</td>
                <td className="search-page__mono">
                  <Link to={rowPivot(p)}>{basename(p.path) || String(p.pid)}</Link>
                </td>
                <td>{p.ppid}</td>
                <td className="search-page__mono search-page__cmdline">{p.args ? p.args.join(" ") : p.path}</td>
                <td>{p.uid ?? ""}</td>
                <td>
                  {/* A fork-only process (no exec) inherited its parent's image and has no signature of its own; show no verdict
                      rather than a misleading "unsigned", matching the tree tooltip and detail panel. */}
                  {p.exec_time_ns ? <Badge variant="neutral">{deriveSigningVerdict(p.code_signing).label}</Badge> : null}
                </td>
                <td>{p.exit_reason ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </SearchResultsFrame>
    </>
  );
}

// rowPivot links a result row to its host's process tree anchored at the process's fork time. The tree's ?process= selects by the
// process DB row id (findNodeByDbId), NOT the OS pid, so pass p.id; the same convention the alert->tree deep link uses.
function rowPivot(p: Process): string {
  const atMs = Math.floor(p.fork_time_ns / NANOSECONDS_PER_MILLISECOND);
  return `/hosts/${encodeURIComponent(p.host_id)}?process=${String(p.id)}&at=${String(atMs)}`;
}
