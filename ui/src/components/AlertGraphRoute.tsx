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
  // Validate the route param up front: a non-numeric or non-positive id can never resolve to an alert, so treat it as not-found
  // rather than firing a getAlertDetail(NaN) request.
  const id = Number(alertId);
  const validId = Number.isInteger(id) && id > 0;
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    if (!validId) return;
    let cancelled = false;
    // Reset on every id change so navigating from one alert to another shows the loading state (and remounts ProcessTreeView fresh
    // via the key below) instead of leaving the previous alert's tree + breadcrumb on screen, and so a prior fetch error clears.
    setAlert(null); // eslint-disable-line react-hooks/set-state-in-effect -- reset before refetch on alertId change
    setErrored(false);
    getAlertDetail(id)
      .then((result) => { if (!cancelled) setAlert(result); })
      .catch(() => { if (!cancelled) setErrored(true); });
    return () => { cancelled = true; };
  }, [id, validId]);

  if (!validId || errored) return <EmptyState>Alert not found.</EmptyState>;
  if (alert === null) return <EmptyState>Loading alert...</EmptyState>;
  // key on the alert id so a switch between alerts remounts ProcessTreeView with a clean slate (its alert-derived state is seeded on
  // mount), rather than reusing the prior alert's instance.
  return <ProcessTreeView key={alert.id} hostId={alert.host_id} entryAlert={alert} />;
}
