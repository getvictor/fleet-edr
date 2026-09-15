import { useEffect, useState } from "react";
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
// the header. The host header mounts one per host (keyed by host id), so a navigation to another host starts fresh: no read, open
// confirmation or pending change carries across hosts.
export function HostContainment({ hostId }: { readonly hostId: string }) {
  const can = useCan();
  const [state, setState] = useState<ContainmentState | null>(null);
  const [confirming, setConfirming] = useState(false);
  // reads restarts the read chain: a change the operator just made is read back at once and followed until the host settles it.
  const [reads, setReads] = useState(0);

  // One read at a time: the next is scheduled only after the current one settles, so a slow response cannot land after a newer one,
  // and nothing is applied once the effect is cleaned up. A read that fails while a change is on its way is retried; otherwise the
  // badge is best-effort, like the rest of the header.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const read = (pending: boolean) => {
      getHostContainment(hostId)
        .then((next) => {
          if (cancelled) return;
          setState(next);
          if (!containmentSettled(containmentPhase(next))) timer = setTimeout(read, CONTAINMENT_POLL_MS, true);
        })
        .catch(() => {
          if (!cancelled && pending) timer = setTimeout(read, CONTAINMENT_POLL_MS, true);
        });
    };
    read(reads > 0);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [hostId, reads]);

  const phase = containmentPhase(state);

  const contain = !(state?.contained ?? false);
  const badge = containmentBadge(phase);
  return (
    <span className="host-containment">
      {/* A polite live region, so a change the host confirms or fails later is announced. Not role="status": the host page already
          has a status notice (the process tree's truncation notice), and this region is always present. */}
      <span aria-live="polite" aria-atomic="true" className="host-containment__status">
        {badge && (
          <Badge variant={badge.variant} className="host-containment__badge">
            {badge.label}
          </Badge>
        )}
      </span>
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
          setReads((n) => n + 1);
        }}
      />
    </span>
  );
}
