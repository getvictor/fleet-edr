import { useEffect, useState } from "react";
import { listHosts } from "../../api";
import type { HostSummary } from "../../types";

// useHostNames resolves a host_id -> hostname map once from listHosts so a search row can show a name, not a bare id (issue #582). The
// host set is small, so one call decorates every row; on failure the map stays empty and rows fall back to the id. Shared by the
// process and event search modes so both decorate rows identically.
export function useHostNames(): Map<string, string> {
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
  return hostNames;
}
