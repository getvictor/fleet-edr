import { useEffect, useState } from "react";
import { getProcessDetail } from "../api";
import type { ProcessNode, ProcessDetail as ProcessDetailType } from "../types";
import { NetworkConnections } from "./NetworkConnections";

interface Props {
  hostId: string;
  node: ProcessNode;
  onClose: () => void;
}

export function ProcessDetail({ hostId, node, onClose }: Props) {
  const [detail, setDetail] = useState<ProcessDetailType | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const atTime = node.exec_time_ns || node.fork_time_ns;
    getProcessDetail(hostId, node.pid, atTime)
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  }, [hostId, node.pid, node.fork_time_ns, node.exec_time_ns]);

  return (
    <div style={{ border: "1px solid #ddd", borderRadius: 4, padding: "1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
        <strong>Process detail</strong>
        <button onClick={onClose} aria-label="Close" style={{ cursor: "pointer" }}>
          &times;
        </button>
      </div>

      <dl style={dlStyle}>
        <dt>PID</dt>
        <dd>{node.pid}</dd>
        <dt>PPID</dt>
        <dd>{node.ppid}</dd>
        <dt>Path</dt>
        <dd style={{ wordBreak: "break-all" }}>{node.path || "(unknown)"}</dd>
        {node.args && (
          <>
            <dt>Args</dt>
            <dd style={{ wordBreak: "break-all" }}>{node.args.join(" ")}</dd>
          </>
        )}
        {node.uid !== undefined && (
          <>
            <dt>UID</dt>
            <dd>{node.uid}</dd>
          </>
        )}
        {node.gid !== undefined && (
          <>
            <dt>GID</dt>
            <dd>{node.gid}</dd>
          </>
        )}
        {node.sha256 && (
          <>
            <dt>SHA256</dt>
            <dd style={{ wordBreak: "break-all", fontSize: "0.75rem" }}>{node.sha256}</dd>
          </>
        )}
        {node.code_signing && (
          <>
            <dt>Signing</dt>
            <dd>
              {node.code_signing.signing_id}
              {node.code_signing.is_platform_binary ? " (platform)" : ""}
            </dd>
          </>
        )}
        <dt>Fork</dt>
        <dd>{formatTimestamp(node.fork_time_ns)}</dd>
        {node.exec_time_ns && (
          <>
            <dt>Exec</dt>
            <dd>{formatTimestamp(node.exec_time_ns)}</dd>
          </>
        )}
        {node.exit_time_ns && (
          <>
            <dt>Exit</dt>
            <dd>
              {formatTimestamp(node.exit_time_ns)}
              {node.exit_code !== undefined ? ` (code ${node.exit_code})` : ""}
            </dd>
          </>
        )}
      </dl>

      {loading && <p>Loading network data...</p>}

      {detail && (
        <NetworkConnections
          connections={detail.network_connections}
          dnsQueries={detail.dns_queries}
        />
      )}
    </div>
  );
}

function formatTimestamp(ns: number): string {
  return new Date(ns / 1_000_000).toLocaleTimeString();
}

const dlStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "auto 1fr",
  gap: "0.25rem 0.75rem",
  fontSize: "0.85rem",
  margin: 0,
};
