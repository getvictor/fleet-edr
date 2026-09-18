import type { ContainmentState } from "./types";
import type { BadgeVariant } from "./components/ui/Badge";

// ContainmentPhase is where a host's network containment (#948) stands: what was asked for, and whether the host has confirmed it.
// The server's delivery is "current" when the latest command carries the state asked for; an agent completes it only once the
// network extension applied the state, and fails it with the reason otherwise. A current command that expired or was cancelled
// is waiting on the server's catch-up, so it is still on its way.
export type ContainmentPhase = "containing" | "contained" | "contain_failed" | "releasing" | "release_failed" | "released";

export function containmentPhase(state: ContainmentState | null | undefined): ContainmentPhase | null {
  if (!state || state.version === 0) return null;
  const delivery = state.delivery?.current ? state.delivery : undefined;
  if (state.contained) {
    if (delivery?.status === "completed") return "contained";
    return delivery?.status === "failed" ? "contain_failed" : "containing";
  }
  if (delivery?.status === "completed") return "released";
  return delivery?.status === "failed" ? "release_failed" : "releasing";
}

// NAME_FILTERING_OFF is what the console has to know from a host's live health: the network extension's DNS proxy is not filtering
// names, so a contained host reaches only its own resolvers but every name they answer still resolves (issue #1078).
//
// Two conditions, because the proxy can fail to filter in two ways and each has its own evidence:
//
//   - `dns_proxy` reporting `provider_disabled`, which is an operator switching the opt-in proxy off. Live, immediate, and not a
//     fault: the host is configured the way somebody meant it to be.
//   - `dns_proxy_delivery` degraded, which the server derives from DNS flow stopping while process telemetry continued. That is the
//     case a lifecycle state cannot see, because a wedged provider still reports itself running.
//
// A provider reported `stopped` is a fault the host surfaces on its own and the health section already says so, so it is not
// duplicated here.
const NAME_FILTERING_OFF: ReadonlyArray<{ type: string; reason?: string }> = [
  { type: "dns_proxy", reason: "provider_disabled" },
  { type: "dns_proxy_delivery" },
];

// nameFilteringOff reports whether a host's health says its DNS proxy is not restricting names. Null when health is not known yet,
// which is not the same as false: a page that has not read health, or a host too old to report, must not be shown as either.
export function nameFilteringOff(components: ReadonlyArray<{ type: string; reason?: string }> | null | undefined): boolean | null {
  if (!components) return null;
  return NAME_FILTERING_OFF.some((want) =>
    components.some((c) => c.type === want.type && (want.reason === undefined || c.reason === want.reason)),
  );
}

// containmentSettled reports whether a phase is final until the next change, so a view can stop polling.
export function containmentSettled(phase: ContainmentPhase | null): boolean {
  return phase !== "containing" && phase !== "releasing";
}

// containmentBadge is the badge a phase shows, or null for a host that is not contained and has nothing pending.
export function containmentBadge(phase: ContainmentPhase | null): { label: string; variant: BadgeVariant } | null {
  switch (phase) {
    case "containing":
      return { label: "Containing", variant: "info" };
    case "contained":
      return { label: "Contained", variant: "critical" };
    case "contain_failed":
      return { label: "Containment failed", variant: "high" };
    case "releasing":
      return { label: "Releasing", variant: "info" };
    case "release_failed":
      return { label: "Release failed", variant: "high" };
    default:
      return null;
  }
}
