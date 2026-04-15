import { useMemo } from "react";
import type {
  EventRecord,
  NetworkConnectPayload,
  DNSQueryPayload,
} from "../types";
import "./NetworkConnections.scss";

interface Props {
  connections: EventRecord[] | null;
  dnsQueries: EventRecord[] | null;
}

// Collapsed connection row: identical remote+port+proto+direction grouped into a single row
// with a hit count and the most-recent timestamp. Avoids the common case where Safari (or
// any network-chatty process) produces dozens of identical entries to the local DNS resolver.
interface GroupedConnection {
  key: string;
  remote_address: string;
  remote_port: number;
  remote_hostname?: string;
  protocol: string;
  direction: string;
  count: number;
  latest_ts_ns: number;
}

export function NetworkConnections({
  connections: rawConnections,
  dnsQueries: rawDNS,
}: Props) {
  const grouped = useMemo(() => groupConnections(rawConnections ?? []), [rawConnections]);
  const dnsQueries = rawDNS ?? [];
  const hasConnections = grouped.length > 0;
  const hasDNS = dnsQueries.length > 0;
  const totalConnections = (rawConnections ?? []).length;

  if (!hasConnections && !hasDNS) {
    return <p className="net-empty">No network activity.</p>;
  }

  return (
    <div className="net-section">
      {hasConnections && (
        <>
          <h4 className="net-section__title">
            Network connections ({totalConnections}
            {totalConnections !== grouped.length ? `, ${String(grouped.length)} unique` : ""})
          </h4>
          <table className="net-table">
            <thead>
              <tr>
                <th>Remote</th>
                <th>Hostname</th>
                <th>Proto</th>
                <th>Count</th>
                <th>Latest</th>
              </tr>
            </thead>
            <tbody>
              {grouped.map((g) => (
                <tr key={g.key}>
                  <td>{g.remote_address}:{g.remote_port}</td>
                  <td>{g.remote_hostname || "-"}</td>
                  <td>{g.protocol}{g.direction === "inbound" ? " in" : ""}</td>
                  <td className="net-table__count">{g.count > 1 ? `×${String(g.count)}` : ""}</td>
                  <td>{formatTime(g.latest_ts_ns)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {hasDNS && (
        <>
          <h4 className="net-section__title net-section__title--dns">DNS queries ({dnsQueries.length})</h4>
          <table className="net-table">
            <thead>
              <tr>
                <th>Query</th>
                <th>Type</th>
                <th>Response</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {dnsQueries.map((evt) => {
                const p = evt.payload as DNSQueryPayload;
                return (
                  <tr key={evt.event_id}>
                    <td>{p.query_name}</td>
                    <td>{p.query_type}</td>
                    <td>{p.response_addresses?.join(", ") || "-"}</td>
                    <td>{formatTime(evt.timestamp_ns)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function groupConnections(events: EventRecord[]): GroupedConnection[] {
  const map = new Map<string, GroupedConnection>();
  for (const evt of events) {
    const p = evt.payload as NetworkConnectPayload;
    const key = `${p.remote_address}|${String(p.remote_port)}|${p.protocol}|${p.direction}`;
    const existing = map.get(key);
    if (existing) {
      existing.count += 1;
      if (evt.timestamp_ns > existing.latest_ts_ns) existing.latest_ts_ns = evt.timestamp_ns;
    } else {
      map.set(key, {
        key,
        remote_address: p.remote_address,
        remote_port: p.remote_port,
        remote_hostname: p.remote_hostname,
        protocol: p.protocol,
        direction: p.direction,
        count: 1,
        latest_ts_ns: evt.timestamp_ns,
      });
    }
  }
  // Sort: highest count first (noisy endpoints float up), then latest timestamp.
  return [...map.values()].sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return b.latest_ts_ns - a.latest_ts_ns;
  });
}

function formatTime(ns: number): string {
  return new Date(ns / 1_000_000).toLocaleTimeString();
}
