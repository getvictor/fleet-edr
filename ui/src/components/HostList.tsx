import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listHosts } from "../api";
import type { HostSummary } from "../types";
import {
  MILLISECONDS_PER_DAY,
  MILLISECONDS_PER_HOUR,
  MILLISECONDS_PER_MINUTE,
  NANOSECONDS_PER_MILLISECOND,
} from "../constants";
import { Table, EmptyState } from "./ui/Table";
import { StatCard, SummaryStrip } from "./ui/StatCard";
import "./HostList.scss";

// "offline" is last_seen > 5 min old. The agent polls every 5 s, so 5 min
// is 60× the polling interval: well past any transient network blip but
// fast enough that a crashed agent shows up quickly in the UI.
const OFFLINE_THRESHOLD_MINUTES = 5;
const offlineThresholdMs = OFFLINE_THRESHOLD_MINUTES * MILLISECONDS_PER_MINUTE;

export function HostList() {
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    listHosts()
      .then(setHosts)
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  // Fleet-overview counts. isOnline calls Date.now(), so memoise the whole
  // tally per hosts change rather than re-walking the array on every render.
  const { online, offline, total } = useMemo(() => {
    const onlineCount = hosts.filter((h) => isOnline(h.last_seen_ns)).length;
    return { online: onlineCount, offline: hosts.length - onlineCount, total: hosts.length };
  }, [hosts]);

  return (
    <>
      {loading && <EmptyState>Loading hosts...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {!loading && !error && hosts.length === 0 && (
        <EmptyState>No hosts reporting yet.</EmptyState>
      )}
      {!loading && !error && hosts.length > 0 && (
        <>
          <SummaryStrip>
            <StatCard accent="green" value={online} label="Online" />
            <StatCard accent="red" value={offline} label="Offline" />
            <StatCard accent="neutral" value={total} label="Total hosts" />
          </SummaryStrip>
          <Table className="table--clickable host-list__table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Platform</th>
                <th>Status</th>
                <th className="host-list__events-col">Events</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => {
                // Compute online once per row: isOnline calls Date.now(), so calling it
                // twice (for className and label) could theoretically flip the two reads
                // at the exact threshold boundary and render an "online" class with an
                // "offline" label.
                const rowOnline = isOnline(h.last_seen_ns);
                const pillClass = rowOnline ? "status-pill status-pill--online" : "status-pill status-pill--offline";
                return (
                  <tr
                    key={h.host_id}
                    onClick={() => {
                      const result = navigate(`/hosts/${encodeURIComponent(h.host_id)}`);
                      // navigate() may return void or Promise<void> in react-router v7.
                      if (result instanceof Promise) result.catch(() => { /* ignored */ });
                    }}
                  >
                    <td>
                      {/* hostname (from enrollment) over the full hardware UUID. Older rows with no enrollment
                          metadata fall back to the UUID on the primary line and omit the secondary line. */}
                      {h.hostname ? (
                        <>
                          <div className="host-list__hostname">{h.hostname}</div>
                          <div className="host-list__uuid">{h.host_id}</div>
                        </>
                      ) : (
                        <div className="host-list__hostname">{h.host_id}</div>
                      )}
                    </td>
                    <td className="host-list__platform">{h.os_version || "-"}</td>
                    <td>
                      <span className={pillClass}>{rowOnline ? "online" : "offline"}</span>
                    </td>
                    <td className="host-list__events-col">{h.event_count.toLocaleString()}</td>
                    <td>{formatRelative(h.last_seen_ns)}</td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </>
      )}
    </>
  );
}

function isOnline(lastSeenNs: number): boolean {
  if (lastSeenNs === 0) return false;
  return Date.now() - lastSeenNs / NANOSECONDS_PER_MILLISECOND < offlineThresholdMs;
}

function formatRelative(ns: number): string {
  if (ns === 0) return "never";
  const diff = Date.now() - ns / NANOSECONDS_PER_MILLISECOND;
  if (diff < MILLISECONDS_PER_MINUTE) return "just now";
  if (diff < MILLISECONDS_PER_HOUR) return `${String(Math.floor(diff / MILLISECONDS_PER_MINUTE))}m ago`;
  if (diff < MILLISECONDS_PER_DAY) return `${String(Math.floor(diff / MILLISECONDS_PER_HOUR))}h ago`;
  return `${String(Math.floor(diff / MILLISECONDS_PER_DAY))}d ago`;
}
