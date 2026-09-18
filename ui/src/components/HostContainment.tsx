import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { ContainmentVersionConflictError, getHostContainment, setHostContainment } from "../api";
import { containmentBadge, containmentPhase, containmentSettled, nameFiltering } from "../containment";
import { PermissionAction, useCan } from "../permissions-core";
import type { ContainmentState, HostHealth } from "../types";
import { ConfirmActionModal } from "./ApplicationControl/ConfirmActionModal";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import "./HostContainment.scss";

// CONTAINMENT_POLL_MS is how often a pending containment or release is re-read. The agent confirms within seconds of receiving the
// command, and an offline host confirms when it next connects, so a few seconds keeps the badge current without hammering the API.
const CONTAINMENT_POLL_MS = 3000;

// What each caveat means, and each says only as much as its evidence supports (issue #1078). Containment restricts a contained host's
// DNS in two layers: the content filter allows DNS only to the host's own resolvers and always holds, while the DNS proxy is what
// refuses every name but the server's.
//
// The disabled case is what the host itself reports, so it is stated. The no-capture case is the server inferring from silence, which
// it grades degraded rather than unhealthy because a skewed clock or an ingest backlog explain silence too, so it is put as the
// question it is rather than as a finding.
const CAVEATS = {
  disabled: {
    label: "DNS by destination only",
    note:
      "This Mac reaches only its own DNS resolvers, but its DNS proxy is switched off, so it is not restricting which names it can " +
      "look up. Re-enable the DNS proxy to restrict names again.",
  },
  noCapture: {
    label: "DNS filtering unconfirmed",
    note:
      "No DNS capture has reached the server from this Mac while it was otherwise reporting, which can mean its DNS proxy is not " +
      "restricting which names it can look up. Check the DNS capture condition under Details.",
  },
} as const;

// HostContainment is the host header's network containment control (#948): a badge for where containment stands, and, for an operator
// holding host.isolate, a Contain or Release action that asks for a reason. Containment cuts the host off from the network except its
// connection to the EDR server, so the confirmation says so. The state is best-effort: a failed read shows nothing rather than block
// the header. The host header mounts one per host (keyed by host id), so a navigation to another host starts fresh: no read, open
// confirmation or pending change carries across hosts. The control sits in the page's <h1>, where a <dialog> is not allowed and would
// take the heading's type styles, so the confirmation (and the reauthentication prompt inside it) renders into the document body.
export function HostContainment({ hostId, health }: { readonly hostId: string; readonly health?: HostHealth | null }) {
  const can = useCan();
  const [state, setState] = useState<ContainmentState | null>(null);
  const [confirming, setConfirming] = useState(false);
  // reads restarts the read chain: a change the operator just made is read back at once and followed until the host settles it.
  const [reads, setReads] = useState(0);
  // released is set when a release this page was following completes. A released host shows no badge, and an emptied live region is
  // not announced, so the region says Released to assistive technology instead. A host already released when the page opened says
  // nothing.
  const [released, setReleased] = useState(false);
  // The caveat's explanation is revealed on press rather than on hover, so a keyboard reaches it.
  const [caveatOpen, setCaveatOpen] = useState(false);

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
          setReleased(pending && containmentPhase(next) === "released");
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
  // Only for a host that IS contained and whose live health says the proxy is not filtering. A host still on its way is not told on,
  // and neither is one whose health has not been read: null is not false (issue #1078).
  // Both lists: the agent reports `dns_proxy` and the SERVER derives `dns_proxy_delivery`, and they arrive in separate arrays.
  // Reading only the first is reading only half the reasons a proxy is not filtering.
  const conditions = health ? [...(health.components ?? []), ...(health.derived_components ?? [])] : null;
  const filtering = nameFiltering(conditions);
  // Only for a host that IS contained and whose live health says something is wrong with name filtering. A host still on its way is
  // not told on, and neither is one whose health has not been read: null is not an answer.
  // Switched rather than indexed: the union has two members and naming each keeps a dynamic key out of the lookup.
  let caveat: { label: string; note: string } | null = null;
  if (phase === "contained") {
    if (filtering === "disabled") caveat = CAVEATS.disabled;
    if (filtering === "no-capture") caveat = CAVEATS.noCapture;
  }
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
        {/* A button, not a span with a title: the explanation has to be reachable by a keyboard, and a tooltip on a non-focusable
            element is not. Pressing it toggles the sentence, which is also in the accessible name, so a screen reader gets it
            without pressing anything. */}
        {caveat && (
          <button
            type="button"
            className="host-containment__caveat"
            aria-expanded={caveatOpen}
            aria-label={`${caveat.label}. ${caveat.note}`}
            onClick={() => {
              setCaveatOpen((open) => !open);
            }}
          >
            <Badge variant="medium" className="host-containment__badge">
              {caveat.label}
            </Badge>
          </button>
        )}
        {released && <span className="host-containment__sr-only">Released</span>}
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
      {/* Last, so the badges and the action keep the first line and the sentence takes the next. Its flex-basis is a full line, and
          the container is bounded, which is what makes that a second row rather than a wider first one. */}
      {caveat && caveatOpen && (
        <span className="host-containment__caveat-text" role="note">
          {caveat.note}
        </span>
      )}
      {createPortal(
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
          onClose={() => {
            setConfirming(false);
          }}
          onConfirm={async (reason) => {
            try {
              // The version this page read is what the change is made against, so a host someone else changed in the meantime is
              // reported rather than having this operator's decision applied over theirs (issue #1076).
              const change = await setHostContainment(hostId, contain, reason, state?.version);
              setState(change.state);
              setReleased(false);
              setConfirming(false);
              setReads((n) => n + 1);
            } catch (err) {
              if (err instanceof ContainmentVersionConflictError) {
                // Show what the host holds now, so the operator decides again from the state that stands rather than the one they
                // opened the dialog on. The confirmation stays open and the modal reports what happened.
                if (err.state) setState(err.state);
                setReleased(false);
                setReads((n) => n + 1);
              }
              throw err;
            }
          }}
        />,
        document.body,
      )}
    </span>
  );
}
