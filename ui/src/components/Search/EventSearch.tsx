import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { searchEvents, eventArtifactParam, type EventSearchMode } from "../../api";
import type { EventRecord, NetworkConnectPayload, DNSQueryPayload } from "../../types";
import { Table } from "../ui/Table";
import { FilterChips, type FilterField } from "./FilterChips";
import { useCursorList, type CursorPage } from "./useCursorList";
import { SearchResultsFrame } from "./SearchResultsFrame";
import { useHostNames } from "./useHostNames";
import { formatNs, basename } from "./format";

// Per-mode labels and prompt: connections match a remote address, DNS matches a domain. The artifact URL param name comes from
// eventArtifactParam so the page and the API layer agree on remote_address / query_name.
const MODE_COPY: Record<EventSearchMode, { artifactLabel: string; prompt: string; emptyLabel: string }> = {
  connections: {
    artifactLabel: "Remote address",
    prompt: "Enter a remote address to search connections across every host.",
    emptyLabel: "No matching connections.",
  },
  dns: {
    artifactLabel: "Domain",
    prompt: "Enter a domain to search DNS lookups across every host.",
    emptyLabel: "No matching DNS queries.",
  },
};

function modeCopy(mode: EventSearchMode) {
  return mode === "connections" ? MODE_COPY.connections : MODE_COPY.dns;
}

// EventSearch is the connection and DNS mode of the fleet-wide search page (issue #582). The artifact value (a remote address or a
// domain) and an optional host live in the URL as chips; because the endpoint 400s on an empty artifact, the page prompts for one and
// issues no request until it is supplied. Results are keyset-paginated on the shared frame.
export function EventSearch({ mode }: { readonly mode: EventSearchMode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const copy = modeCopy(mode);
  const artifactParam = eventArtifactParam(mode);
  const value = searchParams.get(artifactParam) ?? "";
  const hostId = searchParams.get("host_id") ?? "";
  const hasValue = value !== "";

  const fields: FilterField[] = [
    { key: artifactParam, label: copy.artifactLabel },
    { key: "host_id", label: "Host" },
  ];
  const activeFilter = useMemo<Record<string, string>>(() => {
    const entries: [string, string][] = [];
    if (value) entries.push([artifactParam, value]);
    if (hostId) entries.push(["host_id", hostId]);
    return Object.fromEntries(entries);
  }, [artifactParam, value, hostId]);

  // The cursor-list key folds in the mode so switching modes resets the list; JSON.stringify gives it a stable identity.
  const filterKey = useMemo(() => JSON.stringify({ mode, value, hostId }), [mode, value, hostId]);

  const fetchPage = useCallback(
    async (cursor: string): Promise<CursorPage<EventRecord>> => {
      // No artifact value: the endpoint requires one, so return an empty page without issuing a request. The frame shows the prompt.
      if (!value) return { rows: [], total: 0 };
      const res = await searchEvents(mode, { value, host_id: hostId || undefined }, cursor || undefined);
      return { rows: res.events, nextCursor: res.next_cursor, total: res.total_matched };
    },
    [filterKey], // eslint-disable-line react-hooks/exhaustive-deps -- mode/value/hostId are captured; filterKey is their stable identity
  );
  const { rows, total, loading, error, hasMore, loadMore } = useCursorList(filterKey, fetchPage);
  const hostNames = useHostNames();

  const setFilter = (key: string, val: string) => {
    const next = new URLSearchParams(searchParams);
    if (val) {
      next.set(key, val);
    } else {
      next.delete(key);
    }
    setSearchParams(next);
  };

  return (
    <>
      <FilterChips fields={fields} active={activeFilter} onChange={setFilter} />
      <SearchResultsFrame
        loading={loading}
        error={error}
        count={rows.length}
        total={total}
        hasMore={hasMore}
        onLoadMore={loadMore}
        emptyLabel={copy.emptyLabel}
        prompt={hasValue ? undefined : copy.prompt}
      >
        <Table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Host</th>
              <th>Process</th>
              {mode === "connections" ? <ConnectionHeaders /> : <DNSHeaders />}
            </tr>
          </thead>
          <tbody>
            {rows.map((evt) => (
              <tr key={evt.event_id}>
                <td>{formatNs(evt.timestamp_ns)}</td>
                <td>{hostNames.get(evt.host_id) ?? evt.host_id}</td>
                <td className="search-page__mono">{processCell(evt)}</td>
                {mode === "connections" ? <ConnectionCells evt={evt} /> : <DNSCells evt={evt} />}
              </tr>
            ))}
          </tbody>
        </Table>
      </SearchResultsFrame>
    </>
  );
}

// processCell renders the originating process as "name (pid)", the same shorthand the tree uses; falls back to the raw pid when the
// event carried no path (a legacy or redacted flow).
function processCell(evt: EventRecord): string {
  const p = evt.payload as { path?: string; pid: number };
  const name = p.path ? basename(p.path) : "";
  return name ? `${name} (${String(p.pid)})` : String(p.pid);
}

function ConnectionHeaders() {
  return (
    <>
      <th>Direction</th>
      <th>Proto</th>
      <th>Remote</th>
    </>
  );
}

function ConnectionCells({ evt }: { readonly evt: EventRecord }) {
  const p = evt.payload as NetworkConnectPayload;
  return (
    <>
      <td>{p.direction}</td>
      <td>{p.protocol}</td>
      <td className="search-page__mono">{p.remote_address}:{p.remote_port}</td>
    </>
  );
}

function DNSHeaders() {
  return (
    <>
      <th>Type</th>
      <th>Response</th>
    </>
  );
}

function DNSCells({ evt }: { readonly evt: EventRecord }) {
  const p = evt.payload as DNSQueryPayload;
  return (
    <>
      <td>{p.query_type}</td>
      <td className="search-page__mono">{p.response_addresses?.join(", ") || "-"}</td>
    </>
  );
}
