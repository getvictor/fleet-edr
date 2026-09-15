import { useCallback, useEffect, useState } from "react";
import { getHostContainment, setHostContainment } from "../api";
import { containmentBadge, containmentPhase, containmentSettled } from "../containment";
import { PermissionAction, useCan } from "../permissions-core";
import type { ContainmentState } from "../types";
import { ConfirmActionModal } from "./ApplicationControl/ConfirmActionModal";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import "./HostContainment.scss";

// CONTAINMENT_POLL_MS is how often a pending containment or release is re-read. The agent confirms within seconds of receiving the
// command, and an offline host confirms when it next connects, so a few seconds keeps the badge current without hammering the API.
const CONTAINMENT_POLL_MS = 3000;

// REASON_MAX_LENGTH is the server's limit on a containment reason.
const REASON_MAX_LENGTH = 1024;

// HostContainment is the host header's network containment control (#948): a badge for where containment stands, and, for an operator
// holding host.isolate, a Contain or Release action that asks for a reason. Containment cuts the host off from the network except its
// connection to the EDR server, so the confirmation says so. The state is best-effort: a failed read shows nothing rather than block
// the header.
export function HostContainment({ hostId }: { readonly hostId: string }) {
  const can = useCan();
  const [state, setState] = useState<ContainmentState | null>(null);
  const [confirming, setConfirming] = useState(false);

  const refresh = useCallback(() => {
    getHostContainment(hostId)
      .then(setState)
      .catch(() => {
        // Best-effort, like the rest of the header.
      });
  }, [hostId]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- reset on host change so another host's state never shows here
    setState(null);
    refresh();
  }, [refresh]);

  const phase = containmentPhase(state);
  useEffect(() => {
    if (containmentSettled(phase)) return;
    const timer = setInterval(refresh, CONTAINMENT_POLL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [phase, refresh]);

  const contain = !(state?.contained ?? false);
  const badge = containmentBadge(phase);
  return (
    <span className="host-containment">
      {badge && (
        <Badge variant={badge.variant} className="host-containment__badge">
          {badge.label}
        </Badge>
      )}
      {state && can(PermissionAction.HostIsolate) && (
        <Button
          type="button"
          size="small"
          variant={contain ? "alert" : "inverse"}
          onClick={() => {
            setConfirming(true);
          }}
        >
          {contain ? "Contain host" : "Release host"}
        </Button>
      )}
      <ConfirmActionModal
        open={confirming}
        title={contain ? "Contain this host?" : "Release this host?"}
        description={
          contain
            ? "The host loses network access except to the EDR server and the DNS and DHCP it needs to reach it. Established " +
              "connections are cut. It takes effect when the agent receives it, and stays in force until you release the host."
            : "The host gets its network access back when the agent receives the release."
        }
        confirmLabel={contain ? "Contain host" : "Release host"}
        confirmVariant={contain ? "alert" : "primary"}
        reasonPlaceholder={contain ? "Why is this host being contained?" : "Why is this host being released?"}
        reasonMaxLength={REASON_MAX_LENGTH}
        onClose={() => {
          setConfirming(false);
        }}
        onConfirm={async (reason) => {
          const change = await setHostContainment(hostId, contain, reason);
          setState(change.state);
          setConfirming(false);
        }}
      />
    </span>
  );
}
