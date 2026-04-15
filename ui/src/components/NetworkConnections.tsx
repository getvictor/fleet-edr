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

export function NetworkConnections({
  connections: rawConnections,
  dnsQueries: rawDNS,
}: Props) {
  const connections = rawConnections ?? [];
  const dnsQueries = rawDNS ?? [];
  const hasConnections = connections.length > 0;
  const hasDNS = dnsQueries.length > 0;

  if (!hasConnections && !hasDNS) {
    return <p className="net-empty">No network activity.</p>;
  }

  return (
    <div className="net-section">
      {hasConnections && (
        <>
          <h4 className="net-section__title">Network connections ({connections.length})</h4>
          <table className="net-table">
            <thead>
              <tr>
                <th>Remote</th>
                <th>Hostname</th>
                <th>Proto</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((evt) => {
                const p = evt.payload as NetworkConnectPayload;
                return (
                  <tr key={evt.event_id}>
                    <td>{p.remote_address}:{p.remote_port}</td>
                    <td>{p.remote_hostname || "-"}</td>
                    <td>{p.protocol}</td>
                    <td>{formatTime(evt.timestamp_ns)}</td>
                  </tr>
                );
              })}
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

function formatTime(ns: number): string {
  return new Date(ns / 1_000_000).toLocaleTimeString();
}
