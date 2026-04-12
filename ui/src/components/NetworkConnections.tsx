import type {
  EventRecord,
  NetworkConnectPayload,
  DNSQueryPayload,
} from "../types";

interface Props {
  connections: EventRecord[] | null;
  dnsQueries: EventRecord[] | null;
}

export function NetworkConnections({ connections: rawConnections, dnsQueries: rawDNS }: Props) {
  const connections = rawConnections ?? [];
  const dnsQueries = rawDNS ?? [];
  const hasConnections = connections.length > 0;
  const hasDNS = dnsQueries.length > 0;

  if (!hasConnections && !hasDNS) {
    return <p style={{ fontSize: "0.85rem", color: "#666" }}>No network activity.</p>;
  }

  return (
    <div style={{ marginTop: "1rem" }}>
      {hasConnections && (
        <>
          <h4 style={{ fontSize: "0.85rem", marginBottom: "0.25rem" }}>
            Network connections ({connections.length})
          </h4>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Remote</th>
                <th style={thStyle}>Hostname</th>
                <th style={thStyle}>Proto</th>
                <th style={thStyle}>Time</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((evt) => {
                const p = evt.payload as NetworkConnectPayload;
                return (
                  <tr key={evt.event_id}>
                    <td style={tdStyle}>
                      {p.remote_address}:{p.remote_port}
                    </td>
                    <td style={tdStyle}>{p.remote_hostname || "-"}</td>
                    <td style={tdStyle}>{p.protocol}</td>
                    <td style={tdStyle}>{formatTime(evt.timestamp_ns)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}

      {hasDNS && (
        <>
          <h4 style={{ fontSize: "0.85rem", marginTop: "0.75rem", marginBottom: "0.25rem" }}>
            DNS queries ({dnsQueries.length})
          </h4>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Query</th>
                <th style={thStyle}>Type</th>
                <th style={thStyle}>Response</th>
                <th style={thStyle}>Time</th>
              </tr>
            </thead>
            <tbody>
              {dnsQueries.map((evt) => {
                const p = evt.payload as DNSQueryPayload;
                return (
                  <tr key={evt.event_id}>
                    <td style={tdStyle}>{p.query_name}</td>
                    <td style={tdStyle}>{p.query_type}</td>
                    <td style={tdStyle}>{p.response_addresses?.join(", ") || "-"}</td>
                    <td style={tdStyle}>{formatTime(evt.timestamp_ns)}</td>
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

const tableStyle: React.CSSProperties = {
  borderCollapse: "collapse",
  width: "100%",
  fontSize: "0.8rem",
};

const thStyle: React.CSSProperties = {
  textAlign: "left",
  borderBottom: "1px solid #ccc",
  padding: "0.25rem 0.5rem",
};

const tdStyle: React.CSSProperties = {
  borderBottom: "1px solid #eee",
  padding: "0.25rem 0.5rem",
};
