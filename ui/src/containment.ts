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

// containmentNamesFiltered reports what the host said about the restriction on WHICH names it resolves while contained (issue #1078).
//
// Containment restricts a contained host's DNS in two layers and only one of them always holds: the content filter allows DNS to the
// host's own resolvers whatever else is running, while the network extension's DNS proxy is what refuses every name but the server's.
// A host contained with that proxy disabled or stopped resolves any name those resolvers answer, and nothing else in the console says
// so, because a deliberately disabled provider is dropped from host health rather than graded unhealthy.
//
// null when the host did not report it, which is not the same as false: an agent or extension that predates the field says nothing,
// and rendering that as "names are not filtered" would tell an operator a host is leakier than it is. Read from the delivery only
// while it carries the state the host actually holds, since an older command's result describes an older state.
export function containmentNamesFiltered(state: ContainmentState | null | undefined): boolean | null {
  if (!state?.delivery?.current) return null;
  const reported = state.delivery.result?.names_filtered;
  return typeof reported === "boolean" ? reported : null;
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
