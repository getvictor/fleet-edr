import { useCallback, useState } from "react";
import { updateAlertStatus } from "../api";
import { useReauthRetry } from "../hooks/useReauthRetry";
import { ReauthModal } from "./ReauthModal";
import { Button } from "./ui/Button";
import "./AlertTriageActions.scss";

interface Props {
  readonly alertId: number;
  readonly status: string;
  // onStatusChange lets the owner (the alert header) reflect the new status locally on success without a refetch.
  readonly onStatusChange: (status: string) => void;
}

// AlertTriageActions is the alert's lifecycle controls (acknowledge / resolve / reopen), rendered on the alert header where the alert's
// identity already lives. Top EDRs put triage on the detection surface, not on a process node inspector; hanging it off the alert header
// also means process-optional alerts (no process to click) can finally be triaged from the graph page. alert.resolve is reauth-gated by
// the chokepoint when the session is stale, so the mutation goes through useReauthRetry (a no-op until the gate throws).
export function AlertTriageActions({ alertId, status, onStatusChange }: Props) {
  const updateStatus = useCallback(async (id: number, newStatus: string) => updateAlertStatus(id, newStatus), []);
  const { call, modal } = useReauthRetry(updateStatus);
  // A transition is single-flight: disable the controls while one is in flight so a quick Acknowledge-then-Resolve cannot land two
  // PUTs whose promises resolve out of order and leave the locally-reflected status inconsistent with the analyst's last action.
  const [pending, setPending] = useState(false);

  const change = (newStatus: string) => {
    setPending(true);
    call(alertId, newStatus)
      .then(() => { onStatusChange(newStatus); })
      .catch(() => { /* cancelled reauth / transient failure: leave the status unchanged */ })
      .finally(() => { setPending(false); });
  };

  return (
    <div className="alert-triage" role="group" aria-label="Alert status">
      <span className={`status-text status-text--${status}`}>{status}</span>
      {status === "open" && (
        <Button size="small" variant="inverse" disabled={pending} onClick={() => { change("acknowledged"); }}>
          Acknowledge
        </Button>
      )}
      {status !== "resolved" && (
        <Button size="small" variant="inverse" disabled={pending} onClick={() => { change("resolved"); }}>
          Resolve
        </Button>
      )}
      {status === "resolved" && (
        <Button size="small" variant="inverse" disabled={pending} onClick={() => { change("open"); }}>
          Reopen
        </Button>
      )}
      <ReauthModal {...modal} />
    </div>
  );
}
