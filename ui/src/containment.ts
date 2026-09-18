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

// NameFiltering is what a host's live health says about the restriction on WHICH names it resolves while contained (issue #1078).
//
// Four answers, because the two ways a proxy fails to filter are not equally certain and must not be reported as though they were:
//
//   - "disabled": the host itself reports the opt-in DNS proxy switched off. Definite, and immediate.
//   - "no-capture": the SERVER saw no DNS capture arrive while process telemetry continued. Evidence, not proof. The server grades it
//     degraded rather than unhealthy for the same reason, since a skewed clock or an ingest backlog also explain silence, and its own
//     message says the provider MAY be running without capturing.
//   - "filtering": nothing says otherwise.
//   - null: health has not been read, which is not the same as "filtering".
//
// A provider reported `stopped` is a fault the host surfaces on its own and the health section already reports it, so it is not
// repeated here.
export type NameFiltering = "disabled" | "no-capture" | "filtering";

export function nameFiltering(
  conditions: ReadonlyArray<{ type: string; reason?: string }> | null | undefined,
): NameFiltering | null {
  if (!conditions) return null;
  if (conditions.some((c) => c.type === "dns_proxy" && c.reason === "provider_disabled")) return "disabled";
  if (conditions.some((c) => c.type === "dns_proxy_delivery")) return "no-capture";
  return "filtering";
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
