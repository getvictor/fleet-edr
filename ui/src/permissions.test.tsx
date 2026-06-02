import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";

import { Can, RequirePermission, PermissionsProvider } from "./permissions";
import { PermissionAction } from "./permissions-core";

// wrapper builds a PermissionsProvider around a component under test with the given
// permission set (or undefined for "older server / optimistic").
function wrapper(permissions: string[] | undefined) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>;
  };
}

describe("Can", () => {
  // spec:web-ui/navigation-and-action-affordances-are-capability-gated/kill-process-control-shown-with-the-action
  it("renders children when the action is permitted", () => {
    render(
      <Can action={PermissionAction.HostKillProcess}>
        <button type="button">Kill process</button>
      </Can>,
      { wrapper: wrapper([PermissionAction.HostKillProcess]) },
    );
    expect(screen.getByRole("button", { name: "Kill process" })).toBeInTheDocument();
  });

  // spec:web-ui/navigation-and-action-affordances-are-capability-gated/kill-process-control-hidden-without-the-action
  it("hides children (renders fallback) when the action is not permitted", () => {
    render(
      <Can action={PermissionAction.HostKillProcess} fallback={<span>nope</span>}>
        <button type="button">Kill process</button>
      </Can>,
      { wrapper: wrapper([PermissionAction.HostRead]) },
    );
    expect(screen.queryByRole("button", { name: "Kill process" })).not.toBeInTheDocument();
    expect(screen.getByText("nope")).toBeInTheDocument();
  });
});

describe("RequirePermission", () => {
  it("renders the guarded surface when permitted", () => {
    render(
      <RequirePermission action={PermissionAction.AppControlRead} surface="Application control">
        <div>secret surface</div>
      </RequirePermission>,
      { wrapper: wrapper([PermissionAction.AppControlRead]) },
    );
    expect(screen.getByText("secret surface")).toBeInTheDocument();
    expect(screen.queryByText(/don't have access/i)).not.toBeInTheDocument();
  });

  // spec:web-ui/authorization-denials-degrade-gracefully/deep-link-to-a-gated-surface-shows-a-no-access-state
  it("renders a no-access state instead of the surface when not permitted", () => {
    render(
      <RequirePermission action={PermissionAction.AppControlRead} surface="Application control">
        <div>secret surface</div>
      </RequirePermission>,
      { wrapper: wrapper([PermissionAction.HostRead]) },
    );
    expect(screen.queryByText("secret surface")).not.toBeInTheDocument();
    expect(screen.getByText(/don't have access/i)).toBeInTheDocument();
    expect(screen.getByText(/Application control/)).toBeInTheDocument();
    // The raw transport error must never be what the operator sees.
    expect(screen.queryByText(/API error: 403/)).not.toBeInTheDocument();
  });
});
