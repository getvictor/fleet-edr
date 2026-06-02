import { describe, it, expect } from "vitest";
import { renderHook } from "@testing-library/react";
import type { ReactNode } from "react";

import { PermissionsProvider } from "./permissions";
import { useCan, PermissionAction } from "./permissions-core";

// wrapper builds a PermissionsProvider around the hook under test with the given
// permission set (or undefined for "older server / optimistic").
function wrapper(permissions: string[] | undefined) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>;
  };
}

describe("useCan", () => {
  it("grants only actions in the permission set", () => {
    const { result } = renderHook(() => useCan(), {
      wrapper: wrapper([PermissionAction.HostRead, PermissionAction.AlertRead]),
    });
    expect(result.current(PermissionAction.HostRead)).toBe(true);
    expect(result.current(PermissionAction.AlertRead)).toBe(true);
    expect(result.current(PermissionAction.HostKillProcess)).toBe(false);
    expect(result.current(PermissionAction.AppControlRead)).toBe(false);
  });

  it("denies everything when the set is empty", () => {
    const { result } = renderHook(() => useCan(), { wrapper: wrapper([]) });
    expect(result.current(PermissionAction.HostRead)).toBe(false);
    expect(result.current(PermissionAction.HostKillProcess)).toBe(false);
  });

  it("grants everything optimistically when the set is unavailable (older server)", () => {
    const { result } = renderHook(() => useCan(), { wrapper: wrapper(undefined) });
    expect(result.current(PermissionAction.HostKillProcess)).toBe(true);
    expect(result.current("anything.at.all")).toBe(true);
  });
});
