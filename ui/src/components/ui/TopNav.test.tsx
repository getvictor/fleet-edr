import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

import { TopNav } from "./TopNav";
import { PermissionsProvider } from "../../permissions";
import { PermissionAction } from "../../permissions-core";

function renderNav(permissions: string[] | undefined, children: ReactNode = null) {
  return render(
    <MemoryRouter>
      <PermissionsProvider permissions={permissions}>
        <TopNav user={{ id: 1, email: "op@example.com" }} authMethod="oidc" onLogout={() => undefined} />
        {children}
      </PermissionsProvider>
    </MemoryRouter>,
  );
}

describe("TopNav capability gating", () => {
  // spec:web-ui/navigation-and-action-affordances-are-capability-gated/application-control-entry-hidden-without-read-access
  it("hides the Application control entry without application_control.read", () => {
    renderNav([PermissionAction.HostRead, PermissionAction.AlertRead]);
    expect(screen.queryByRole("link", { name: "Application control" })).not.toBeInTheDocument();
    // Entries the operator can reach still render.
    expect(screen.getByRole("link", { name: "Hosts" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Alerts" })).toBeInTheDocument();
  });

  // spec:web-ui/navigation-and-action-affordances-are-capability-gated/application-control-entry-shown-with-read-access
  it("shows the Application control entry with application_control.read", () => {
    renderNav([PermissionAction.HostRead, PermissionAction.AlertRead, PermissionAction.AppControlRead]);
    expect(screen.getByRole("link", { name: "Application control" })).toBeInTheDocument();
  });

  it("hides the Detection tuning entry without detection_config.read", () => {
    renderNav([PermissionAction.HostRead, PermissionAction.AlertRead]);
    expect(screen.queryByRole("link", { name: "Detection tuning" })).not.toBeInTheDocument();
  });

  it("shows the Detection tuning entry with detection_config.read", () => {
    renderNav([PermissionAction.HostRead, PermissionAction.DetectionConfigRead]);
    expect(screen.getByRole("link", { name: "Detection tuning" })).toBeInTheDocument();
  });

  it("always shows the ungated Coverage entry", () => {
    // Even an operator with an empty permission set sees Coverage (no gating action).
    renderNav([]);
    expect(screen.getByRole("link", { name: "Coverage" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Hosts" })).not.toBeInTheDocument();
  });

  it("shows every entry optimistically when the permission set is unavailable", () => {
    renderNav(undefined);
    expect(screen.getByRole("link", { name: "Hosts" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Application control" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Coverage" })).toBeInTheDocument();
  });
});
