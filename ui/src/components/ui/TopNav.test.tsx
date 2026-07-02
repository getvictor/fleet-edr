import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

import { TopNav } from "./TopNav";
import { PermissionsProvider } from "../../permissions";
import { PermissionAction } from "../../permissions-core";

function renderNav(permissions: string[] | undefined, children: ReactNode = null, initialPath = "/") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <PermissionsProvider permissions={permissions}>
        <TopNav user={{ id: 1, email: "op@example.com" }} authMethod="oidc" onLogout={() => undefined} />
        {children}
      </PermissionsProvider>
    </MemoryRouter>,
  );
}

const ALL_NAV_PERMISSIONS = [PermissionAction.AlertRead, PermissionAction.HostRead, PermissionAction.AppControlRead];

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

  it("never renders Detection tuning in the top nav (it lives in the account menu)", () => {
    // Even with detection_config.read, Detection tuning is not a top-nav tab; it moved into the account dropdown.
    renderNav([PermissionAction.HostRead, PermissionAction.DetectionConfigRead]);
    expect(screen.queryByRole("link", { name: "Detection tuning" })).not.toBeInTheDocument();
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

describe("TopNav alert-first order and active state", () => {
  // spec:web-ui/alert-first-navigation-order/navigation-lists-alerts-first
  it("lists entries in the order Alerts, Hosts, Application control, Coverage", () => {
    renderNav(ALL_NAV_PERMISSIONS);
    const labels = screen.getAllByRole("link").map((link) => link.textContent);
    expect(labels).toEqual(["Alerts", "Hosts", "Application control", "Coverage"]);
  });

  // spec:web-ui/alert-first-navigation-order/hosts-entry-active-on-host-detail
  it("marks Hosts active on a host's process tree route", () => {
    renderNav(ALL_NAV_PERMISSIONS, null, "/hosts/ABC-123");
    expect(screen.getByRole("link", { name: "Hosts" })).toHaveClass("top-nav__link--active");
    expect(screen.getByRole("link", { name: "Alerts" })).not.toHaveClass("top-nav__link--active");
  });

  it("marks Hosts active on the host list route", () => {
    renderNav(ALL_NAV_PERMISSIONS, null, "/hosts");
    expect(screen.getByRole("link", { name: "Hosts" })).toHaveClass("top-nav__link--active");
  });
});
