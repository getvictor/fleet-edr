import { describe, it, expect } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
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

  // Coverage is gated like every other entry, on the action the server gates its data on. It used to be left ungated so the
  // landing redirect always matched something, which showed it to an operator whose every read of it the server refuses.
  it("hides Coverage from an operator who cannot read what it is built from", () => {
    renderNav([]);
    expect(screen.queryByRole("link", { name: "Coverage" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Hosts" })).not.toBeInTheDocument();
  });

  it("shows Coverage and Rules to an operator holding alert.read", () => {
    renderNav([PermissionAction.AlertRead]);
    expect(screen.getByRole("link", { name: "Coverage" })).toBeVisible();
    // The rule catalogue is reached on the same action: the server serves GET /api/rules on alert.read.
    expect(screen.getByRole("link", { name: "Rules" })).toBeVisible();
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
    expect(labels).toEqual(["Alerts", "Hosts", "Application control", "Rules", "Coverage"]);
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

describe("TopNav account menu", () => {
  it("passes the session's roles to the account menu", () => {
    render(
      <MemoryRouter>
        <PermissionsProvider permissions={[]}>
          <TopNav user={{ id: 1, email: "op@example.com" }} authMethod="oidc" roles={["admin"]} onLogout={() => undefined} />
        </PermissionsProvider>
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByText("Role: Admin")).toBeVisible();
  });
});
