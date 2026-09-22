import { PermissionAction, PermissionActionValue } from "../../permissions-core";

export interface NavLink {
  to: string;
  label: string;
  // action gates the entry on the operator's effective permission set: the entry is hidden when the action is absent. It is the
  // action the SERVER gates that entry's destination on, so the two answer alike: an entry gated on more than the server asks
  // withholds a page from an operator entitled to it, and one gated on less is reached and then fails with a transport error.
  // Hiding is presentation only; the server still enforces every read on the destination surface.
  action: PermissionActionValue;
}

export const NAV_LINKS: NavLink[] = [
  { to: "/alerts", label: "Alerts", action: PermissionAction.AlertRead },
  { to: "/hosts", label: "Hosts", action: PermissionAction.HostRead },
  { to: "/search", label: "Search", action: PermissionAction.ProcessRead },
  { to: "/app-control", label: "Application control", action: PermissionAction.AppControlRead },
  { to: "/rules", label: "Rules", action: PermissionAction.AlertRead },
  { to: "/coverage", label: "Coverage", action: PermissionAction.AlertRead },
];

// firstPermittedRoute is the landing-redirect target for "/": the first nav entry the operator's permission set confers, in
// display order. It reads the same NAV_LINKS the nav renders so the landing and the visible nav cannot disagree.
//
// An operator holding no actions matches nothing, and the last entry is returned so they land on a gated route, which renders the
// no-access state. Leaving one entry ungated to guarantee a match is what this replaces: it guaranteed a ROUTE rather than a page
// they could read, so the landing answered with that surface's own 403 instead of saying they lack access (issue #1144).
export function firstPermittedRoute(can: (action: string) => boolean): string {
  const firstVisible = NAV_LINKS.find((link) => can(link.action)) ?? NAV_LINKS[NAV_LINKS.length - 1];
  return firstVisible.to;
}
