import { PermissionAction } from "../../permissions-core";

export interface NavLink {
  to: string;
  label: string;
  // action gates the entry on the operator's effective permission set: the entry is
  // hidden when the action is absent. Undefined means the destination is not gated by
  // a dedicated read action (wave-1 Coverage has no `coverage.read`), so it shows for
  // every authenticated operator. Hiding is presentation only; the server still
  // enforces every read on the destination surface.
  action?: string;
}

export const NAV_LINKS: NavLink[] = [
  { to: "/alerts", label: "Alerts", action: PermissionAction.AlertRead },
  { to: "/hosts", label: "Hosts", action: PermissionAction.HostRead },
  { to: "/app-control", label: "Application control", action: PermissionAction.AppControlRead },
  { to: "/coverage", label: "Coverage" },
];

// firstPermittedRoute is the landing-redirect target for "/": the first nav entry the
// operator's permission set confers, in display order. It reads the same NAV_LINKS the
// nav renders so the landing and the visible nav cannot disagree, and the ungated
// Coverage entry guarantees a match for every authenticated operator.
export function firstPermittedRoute(can: (action: string) => boolean): string {
  const firstVisible = NAV_LINKS.find((link) => link.action === undefined || can(link.action)) ?? NAV_LINKS[NAV_LINKS.length - 1];
  return firstVisible.to;
}
