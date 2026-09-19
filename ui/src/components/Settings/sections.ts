import { PermissionAction } from "../../permissions-core";

// The Admin settings sections, in the order the sub-navigation shows them, each with the permission that opens it.
//
// Shared with AccountMenu rather than held in SettingsLayout, because the menu's "Admin settings" link is the only way into this
// area: a section whose permission the menu does not know about is a page nobody can navigate to. That is not hypothetical. The
// link was gated on `sso.manage` alone, so the moment Containment arrived with `containment_config.read`, the senior analysts it
// was added for could reach it only by typing the URL.
export const SETTINGS_SECTIONS = [
  { to: "/admin/settings/sso", label: "Single sign-on", action: PermissionAction.SSOManage },
  { to: "/admin/settings/webhooks", label: "Webhooks", action: PermissionAction.WebhookManage },
  { to: "/admin/settings/containment", label: "Containment", action: PermissionAction.ContainmentConfigRead },
  { to: "/admin/settings/users", label: "Users", action: PermissionAction.UserRead },
  { to: "/admin/settings/service-accounts", label: "Service accounts", action: PermissionAction.ServiceAccountRead },
] as const;

// settingsEntry is where "Admin settings" should land an operator: the first section they can open, or null when they can open
// none, in which case the entry is not offered. The server chokepoint remains the authority (ADR-0012); this decides what to
// offer, not what is allowed.
export function settingsEntry(can: (action: string) => boolean): string | null {
  return SETTINGS_SECTIONS.find((s) => can(s.action))?.to ?? null;
}
