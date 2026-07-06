import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { getAlertDetail } from "../api";
import type { AlertDetail } from "../types";
import { ProcessTreeView } from "./ProcessTree";
import { EmptyState } from "./ui/Table";

// AlertGraphRoute is the thin wrapper for the /alerts/:alertId route: it fetches the alert, then renders the SHARED ProcessTreeView
// seeded with the alert's host and the alert itself. Sharing the component (not the route) keeps the top nav on "Alerts" while the
// analyst sees the same process graph, timeline, and breadcrumb the host route renders.
export function AlertGraphRoute() {
  const { alertId } = useParams<{ alertId: string }>();
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getAlertDetail(Number(alertId))
      .then((result) => { if (!cancelled) setAlert(result); })
      .catch(() => { if (!cancelled) setErrored(true); });
    return () => { cancelled = true; };
  }, [alertId]);

  if (errored) return <EmptyState>Alert not found.</EmptyState>;
  if (alert === null) return <EmptyState>Loading alert...</EmptyState>;
  return <ProcessTreeView hostId={alert.host_id} entryAlert={alert} />;
}
