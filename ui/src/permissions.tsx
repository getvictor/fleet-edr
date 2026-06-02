import { type ReactNode } from "react";

import { NoAccess } from "./components/NoAccess";
import { PermissionsContext, useCan } from "./permissions-core";

// React components for the capability seam. The hook (useCan), the action constants
// (PermissionAction), and the context live in permissions-core.ts; this file exports
// only components so react-refresh fast-refresh works. See permissions-core.ts and
// ADR-0012 for the model. Gating here is presentation only; the server's authorization
// chokepoint remains the sole security boundary.

interface PermissionsProviderProps {
  readonly permissions: readonly string[] | undefined;
  readonly children: ReactNode;
}

export function PermissionsProvider({ permissions, children }: PermissionsProviderProps) {
  return <PermissionsContext.Provider value={permissions}>{children}</PermissionsContext.Provider>;
}

interface CanProps {
  readonly action: string;
  readonly children: ReactNode;
  // fallback renders when the action is not permitted. Defaults to nothing (the
  // affordance simply disappears), which is the right behaviour for buttons + nav.
  readonly fallback?: ReactNode;
}

// Can renders its children only when the operator's permission set includes the
// action. Use for inline affordances (buttons, nav entries). For whole-surface
// gating prefer RequirePermission, which renders a no-access state on a deep-link.
export function Can({ action, children, fallback = null }: CanProps) {
  const can = useCan();
  return <>{can(action) ? children : fallback}</>;
}

interface RequirePermissionProps {
  readonly action: string;
  // surface is the human label passed to NoAccess when access is denied.
  readonly surface?: string;
  readonly children: ReactNode;
}

// RequirePermission guards a whole route/surface. When the operator's permission set
// includes the action it renders the children; otherwise it renders the NoAccess
// state. This is what turns a direct navigation to a gated route (where the nav entry
// is already hidden) into a friendly no-access page instead of a raw API error.
export function RequirePermission({ action, surface, children }: RequirePermissionProps) {
  const can = useCan();
  if (!can(action)) return <NoAccess surface={surface} />;
  return <>{children}</>;
}
