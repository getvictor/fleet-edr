import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import "./SearchPage.scss";
import { listHosts, searchProcesses, type ProcessSearchFilter } from "../../api";
import type { HostSummary, Process } from "../../types";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";
import { Badge } from "../ui/Badge";
import { FilterChips, type FilterField } from "./FilterChips";
import { useCursorList, type CursorPage } from "./useCursorList";
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

// SearchPage is the fleet-wide hunting console (issue #582): its filters live in the URL (so a pivot is a link and the page is
// bookmarkable), results are keyset-paginated with "load more", and rows pivot into the host's process tree.
export function SearchPage() {
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

  // Resolve host_id -> hostname once so rows show a name, not a bare id (the host set is small; same treatment as the Hosts list).
  const [hostNames, setHostNames] = useState<Map<string, string>>(new Map());
  useEffect(() => {
    let cancelled = false;
    listHosts()
      .then((hosts: HostSummary[]) => {
        if (cancelled) return;
        setHostNames(new Map(hosts.filter((h) => h.hostname).map((h) => [h.host_id, h.hostname])));
      })
      .catch(() => {
        // Best-effort decoration; rows fall back to the host id.
      });
    return () => { cancelled = true; };
  }, []);

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
    <div className="search-page">
      <PageHeader title="Search" subtitle="Hunt processes across every host." />
      <FilterChips fields={FILTER_FIELDS} active={activeFilter} onChange={setFilter} />

      {error && <EmptyState>Error: {error}</EmptyState>}
      {!error && loading && rows.length === 0 && <EmptyState>Searching...</EmptyState>}
      {!error && !loading && rows.length === 0 && <EmptyState>No matching processes.</EmptyState>}

      {rows.length > 0 && (
        <>
          <p className="search-page__count">
            Showing {rows.length.toLocaleString()} of {total.toLocaleString()} matches
          </p>
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
                    <Badge variant="neutral">{deriveSigningVerdict(p.code_signing).label}</Badge>
                  </td>
                  <td>{p.exit_reason ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </Table>
          {hasMore && (
            <div className="search-page__more">
              <Button size="small" variant="inverse" onClick={loadMore} disabled={loading}>
                {loading ? "Loading..." : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// rowPivot links a result row to its host's process tree anchored at the process's fork time (the standard `?at=` tree entry).
function rowPivot(p: Process): string {
  const atMs = Math.floor(p.fork_time_ns / NANOSECONDS_PER_MILLISECOND);
  return `/hosts/${encodeURIComponent(p.host_id)}?process=${String(p.pid)}&at=${String(atMs)}`;
}

function formatNs(ns: number): string {
  return new Date(ns / NANOSECONDS_PER_MILLISECOND).toLocaleString();
}

function basename(path: string): string {
  const idx = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return idx >= 0 ? path.slice(idx + 1) : path;
}
