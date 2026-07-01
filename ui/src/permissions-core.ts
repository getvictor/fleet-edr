import { createContext, useCallback, useContext, useMemo } from "react";

// Capability seam core: the permission context, the useCan hook, and the action
// identifiers. The React components that consume these (PermissionsProvider, Can,
// RequirePermission) live in permissions.tsx. The split keeps that .tsx exporting only
// components so react-refresh fast-refresh stays happy; the non-component exports
// (hook + constants + context) live here.
//
// This is PRESENTATION ONLY. The authorization chokepoint on the server remains the
// sole security boundary (ADR-0012): a wrong or stale permission set can only change
// what the UI shows, never what the server allows. The UI holds NO mapping from role
// names to actions; it reads only the flat, server-computed action set, whose
// identifiers are the same strings the chokepoint enforces and the audit log records.

// PermissionAction collects the action identifiers the UI gates on, so call sites use
// a checked constant instead of a bare string literal. It is a subset of the server's
// full action registry: only actions that gate a visible affordance need an entry.
export const PermissionAction = {
  HostRead: "host.read",
  AlertRead: "alert.read",
  AlertComment: "alert.comment",
  AlertAcknowledge: "alert.acknowledge",
  AlertResolve: "alert.resolve",
  AlertReopen: "alert.reopen",
  HostKillProcess: "host.kill_process",
  AppControlRead: "application_control.read",
  DetectionConfigRead: "detection_config.read",
  DetectionConfigWrite: "detection_config.write",
  SSOManage: "sso.manage",
  WebhookManage: "webhook.manage",
  ServiceAccountRead: "service_account.read",
  UserRead: "user.read",
  UserManage: "user.manage",
  UserInvite: "user.invite",
} as const;

export type PermissionActionValue = (typeof PermissionAction)[keyof typeof PermissionAction];

// The context value is the effective action set, or undefined when the server did not
// return one (an older server predating the permissions field). undefined means
// "render optimistically": can() returns true for everything and the UI leans on the
// server's 403 + graceful-denial path. An empty array means "this operator may do
// nothing" and gates everything off.
export const PermissionsContext = createContext<readonly string[] | undefined>(undefined);

// useCan returns a stable predicate over the operator's effective permission set. When
// the set is unknown (undefined) it returns true for every action so an older server
// degrades to the pre-gating behaviour; the server still enforces.
export function useCan(): (action: string) => boolean {
  const perms = useContext(PermissionsContext);
  // Memoize the lookup set (data, not a closure) so the predicate below stays stable
  // across renders while perms is unchanged. null means "unknown set" -> optimistic.
  const set = useMemo(() => (perms === undefined ? null : new Set(perms)), [perms]);
  return useCallback((action: string) => set === null || set.has(action), [set]);
}
