import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import "./HostTimeline.scss";
import { getHostTimeline, eventArtifactParam, listAlerts, getAlertDetail, encodeChainGeneration, type ChainGeneration } from "../api";
import type { EventRecord, NetworkConnectPayload, DNSQueryPayload, ExecPayload } from "../types";
import { Table } from "./ui/Table";
import { Badge } from "./ui/Badge";
import { TechniqueTags } from "./TechniqueTags";
import { useCursorList, type CursorPage } from "./Search/useCursorList";
import { SearchResultsFrame } from "./Search/SearchResultsFrame";
import { formatNs, basename, hostPort } from "./Search/format";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";

// EventTechniques maps a triggering event id to the alerting rules' technique ids, so a timeline row for that event shows the MITRE
// tags (issue #585). Keyed by event id because a timeline event carries the OS pid, not the alert's process DB id. The value is a
// list because one event can trigger more than one alert (one entry per rule, each linking to its own rule page).
type EventTechniques = Map<string, { ruleId: string; techniques: string[] }[]>;

// Cap how many alerts we fetch details for, so a host in an alert storm cannot fan out into hundreds of concurrent getAlertDetail
// requests. Tagging the most recent alerts' events is enough for the overlay; the cap is best-effort, not a correctness bound.
const MAX_ALERT_DETAIL_FETCHES = 50;

// buildEventTechniques resolves a host's triggering-event -> technique-tags map: its open + acknowledged alerts (each list fetched
// resiliently so one failing status still yields the other), the alerting rules' event ids via getAlertDetail, grouped by event id.
// Extracted to module scope so the effect stays shallow (avoids deep function nesting).
async function buildEventTechniques(hostID: string): Promise<EventTechniques> {
  const [open, acked] = await Promise.all([
    listAlerts({ host_id: hostID, status: "open", limit: 1000 }).catch(() => []),
    listAlerts({ host_id: hostID, status: "acknowledged", limit: 1000 }).catch(() => []),
  ]);
  const withTechniques = [...open, ...acked].filter((a) => (a.techniques ?? []).length > 0).slice(0, MAX_ALERT_DETAIL_FETCHES);
  const detailed = await Promise.all(
    withTechniques.map(async (a) => ({ alert: a, detail: await getAlertDetail(a.id).catch(() => null) })),
  );
  const map: EventTechniques = new Map();
  for (const { alert, detail } of detailed) {
    if (!detail) continue;
    for (const eid of detail.event_ids) {
      const entry = map.get(eid) ?? [];
      entry.push({ ruleId: alert.rule_id, techniques: alert.techniques ?? [] });
      map.set(eid, entry);
    }
  }
  return map;
}

interface Props {
  readonly hostId: string;
  // The active event-time window, shared with the graph so both views reflect one window.
  readonly bounds: { fromNs: number; toNs: number };
  // When set, timeline rows whose originating process is this pid are emphasized (the graph node -> timeline pivot).
  readonly emphasizePid?: number;
  // When set, scopes the timeline to the alert chain: only events belonging to one of these process generations (the alerted process
  // plus its ancestors and descendants), matched by the (pid, pidversion) pair, mirroring the graph's "Alert chain" focus. Undefined
  // shows the full host stream.
  readonly chainGenerations?: ChainGeneration[];
}

// How long after the last keystroke the text filter commits to the URL (and thus the query). Keeps a fast typist to one fetch.
const TEXT_DEBOUNCE_MS = 300;

// The event classes the timeline surfaces, in chip order. An empty selection means all of them (the endpoint's default).
const EVENT_TYPES: { key: string; label: string }[] = [
  { key: "exec", label: "Exec" },
  { key: "network_connect", label: "Network" },
  { key: "dns_query", label: "DNS" },
];

// HostTimeline is the flat, filterable event stream beside the process graph (issue #583): the host's exec/network/DNS events for the
// active window, newest-first, filterable by type chips and a text box (both in the URL), keyset-paginated via the shared list hook.
// A row links to its process node in the graph; connection/DNS rows carry the fleet-wide "search" pivot.
export function HostTimeline({ hostId, bounds, emphasizePid, chainGenerations }: Props) {
  const [searchParams, setSearchParams] = useSearchParams();
  // Sorted so a semantically-equal selection (e.g. a type toggled off then back on) yields one canonical order; otherwise the
  // Set-insertion order would churn filterKey and reset the cursor list on a no-op change.
  const activeTypes = (searchParams.get("type") ?? "").split(",").filter(Boolean).sort((a, b) => a.localeCompare(b));
  const text = searchParams.get("text") ?? "";
  // scopeChain is undefined (not []) when unscoped so it is omitted from the query entirely. The filter key includes a canonical,
  // order-independent encoding of the generations so toggling the scope on or off reloads the list without churning on walk order.
  const scopeChain = chainGenerations && chainGenerations.length > 0 ? chainGenerations : undefined;
  const scopeKey = scopeChain
    ? scopeChain.map(encodeChainGeneration).sort((a, b) => a.localeCompare(b))
    : [];
  const filterKey = JSON.stringify({ h: hostId, from: bounds.fromNs, to: bounds.toNs, types: activeTypes, text, chain: scopeKey });

  // The text box is driven by local state, not the URL, so fast typing is never reset by a re-render; the draft is debounced into the
  // URL (which drives the query) so a burst of keystrokes issues one fetch, not one per character.
  const [textDraft, setTextDraft] = useState(text);
  // Re-sync the draft when the URL text changes from outside this input (back/forward navigation, a link that sets/clears ?text=), so
  // the input never shows a stale value the debounce would then write back over the navigation.
  // eslint-disable-next-line react-hooks/set-state-in-effect -- mirror external URL state into the local input draft
  useEffect(() => { setTextDraft(text); }, [text]);
  useEffect(() => {
    const id = setTimeout(() => {
      if (textDraft === (searchParams.get("text") ?? "")) return;
      const next = new URLSearchParams(searchParams);
      if (textDraft) {
        next.set("text", textDraft);
      } else {
        next.delete("text");
      }
      setSearchParams(next);
    }, TEXT_DEBOUNCE_MS);
    return () => { clearTimeout(id); };
  }, [textDraft, searchParams, setSearchParams]);

  const fetchPage = useCallback(
    async (cursor: string): Promise<CursorPage<EventRecord>> => {
      const res = await getHostTimeline(
        hostId,
        { from: String(bounds.fromNs), to: String(bounds.toNs), types: activeTypes, text: text || undefined, chain: scopeChain },
        cursor || undefined,
      );
      return { rows: res.events, nextCursor: res.next_cursor, total: res.total_matched };
    },
    [filterKey], // eslint-disable-line react-hooks/exhaustive-deps -- inputs are captured; filterKey is their stable identity
  );
  const { rows, total, loading, error, hasMore, loadMore } = useCursorList(filterKey, fetchPage);

  // Build event-id -> technique tags for this host: its open + acknowledged alerts, each alerting rule's triggering event ids
  // (getAlertDetail) mapped to its technique ids. A row whose event triggered an alert then shows the tags (issue #585). Best-effort:
  // a failed fetch just leaves rows untagged.
  const [eventTechniques, setEventTechniques] = useState<EventTechniques>(new Map());
  useEffect(() => {
    const live = { current: true }; // object ref (not a bare let) so the guard read is a boolean, not a TS-narrowed literal
    // Clear on host change so a slow/failed fetch cannot leave the previous host's tags on this host's rows.
    setEventTechniques(new Map()); // eslint-disable-line react-hooks/set-state-in-effect -- reset request-scoped state on host change
    buildEventTechniques(hostId)
      .then((map) => { if (live.current) setEventTechniques(map); })
      .catch(() => { /* technique tags are best-effort */ });
    return () => { live.current = false; };
  }, [hostId]);

  const toggleType = (key: string) => {
    const next = new URLSearchParams(searchParams);
    const set = new Set(activeTypes);
    if (set.has(key)) {
      set.delete(key);
    } else {
      set.add(key);
    }
    if (set.size > 0) {
      next.set("type", [...set].sort((a, b) => a.localeCompare(b)).join(",")); // canonical order so the same selection never churns the URL/filterKey
    } else {
      next.delete("type");
    }
    setSearchParams(next);
  };

  return (
    <div className="host-timeline">
      <div className="host-timeline__filters">
        <fieldset className="host-timeline__types" aria-label="Event type filter">
          {EVENT_TYPES.map((t) => {
            const on = activeTypes.length === 0 || activeTypes.includes(t.key);
            return (
              <button
                key={t.key}
                type="button"
                className={`host-timeline__type${on ? " host-timeline__type--on" : ""}`}
                aria-pressed={on}
                onClick={() => { toggleType(t.key); }}
              >
                {t.label}
              </button>
            );
          })}
        </fieldset>
        <input
          className="host-timeline__text"
          type="search"
          placeholder="Filter by path, address, or domain"
          aria-label="Filter timeline by text"
          value={textDraft}
          onChange={(e) => { setTextDraft(e.target.value); }}
        />
        {/* Reflect the shared alert-scope so the analyst knows why fewer events show; the "Alert chain / Full tree" toggle in the
            breadcrumb drives both this and the graph. */}
        {scopeChain && <span className="host-timeline__scope-note">Scoped to the alert chain</span>}
      </div>

      <SearchResultsFrame
        loading={loading}
        error={error}
        count={rows.length}
        total={total}
        hasMore={hasMore}
        onLoadMore={loadMore}
        emptyLabel="No events in this time range."
      >
        <Table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Process</th>
              <th>Detail</th>
              <th>MITRE</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((evt) => {
              const pid = evt.payload.pid; // every timeline payload has pid
              const emphasized = emphasizePid !== undefined && pid === emphasizePid;
              const techEntries = eventTechniques.get(evt.event_id) ?? [];
              return (
                <tr key={evt.event_id} className={emphasized ? "host-timeline__row--emphasis" : undefined}>
                  <td>{formatNs(evt.timestamp_ns)}</td>
                  <td><Badge variant="neutral">{TYPE_LABEL(evt.event_type)}</Badge></td>
                  <td className="host-timeline__mono">
                    <Link to={nodePivot(hostId, pid, evt.timestamp_ns)}>{processLabel(evt)}</Link>
                  </td>
                  <td className="host-timeline__mono host-timeline__detail">{detailCell(evt)}</td>
                  {/* Technique tags on a row whose event triggered one or more alerts (issue #585), each linked to its rule doc page. */}
                  <td>{techEntries.map((t) => <TechniqueTags key={t.ruleId} techniques={t.techniques} ruleId={t.ruleId} />)}</td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      </SearchResultsFrame>
    </div>
  );
}

// nodePivot links a timeline row to its process in the graph view, anchored at the event time. The graph resolves (pid, at) to the
// node whose lifetime brackets the anchor (findNodeByPidAtTime), the pid analogue of the ?process=<dbId> deep link.
function nodePivot(hostId: string, pid: number, timestampNs: number): string {
  const atMs = Math.floor(timestampNs / NANOSECONDS_PER_MILLISECOND);
  return `/hosts/${encodeURIComponent(hostId)}?view=graph&pid=${String(pid)}&at=${String(atMs)}`;
}

function TYPE_LABEL(eventType: string): string {
  return EVENT_TYPES.find((t) => t.key === eventType)?.label ?? eventType;
}

// processLabel renders the originating process as "name (pid)"; falls back to the raw pid when the event carried no path. pid and the
// optional path are common to every timeline payload, so no narrowing is needed.
function processLabel(evt: EventRecord): string {
  const p = evt.payload;
  const name = p.path ? basename(p.path) : "";
  return name ? `${name} (${String(p.pid)})` : String(p.pid);
}

// detailCell renders the type-specific column: the command line for an exec, the remote endpoint (with a fleet pivot) for a
// connection, and the query name + resolved addresses (with a fleet pivot) for a DNS query.
function detailCell(evt: EventRecord) {
  if (evt.event_type === "network_connect") {
    const p = evt.payload as NetworkConnectPayload;
    return (
      <>
        {p.direction} {p.protocol} {hostPort(p.remote_address, p.remote_port)}
        <SearchFleetLink mode="connections" value={p.remote_address} artifact="address" />
      </>
    );
  }
  if (evt.event_type === "dns_query") {
    const p = evt.payload as DNSQueryPayload;
    return (
      <>
        {p.query_name} {p.query_type}
        {p.response_addresses && p.response_addresses.length > 0 ? ` -> ${p.response_addresses.join(", ")}` : ""}
        <SearchFleetLink mode="dns" value={p.query_name} artifact="domain" />
      </>
    );
  }
  const p = evt.payload as ExecPayload;
  return p.args && p.args.length > 0 ? p.args.join(" ") : (p.path ?? "");
}

// SearchFleetLink is the "search all hosts for this artifact" pivot on a connection/DNS row, the timeline analogue of the network
// panel's pivot: it targets the fleet-wide search in the matching mode, with the artifact query param from eventArtifactParam so the
// pivot and the API layer share one mapping.
function SearchFleetLink({ mode, value, artifact }: { readonly mode: "connections" | "dns"; readonly value: string; readonly artifact: string }) {
  const qs = new URLSearchParams();
  qs.set("mode", mode);
  qs.set(eventArtifactParam(mode), value);
  const label = `Search all hosts for this ${artifact}`;
  return (
    <Link className="host-timeline__pivot" to={`/search?${qs.toString()}`} aria-label={label} title={label}>
      search fleet
    </Link>
  );
}
