import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { AccountMenu } from "./AccountMenu";
import { PermissionsProvider } from "../../permissions";
import { PermissionAction } from "../../permissions-core";

function renderMenu(permissions: string[] | undefined, onLogout = vi.fn()) {
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <MemoryRouter>
        <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>
      </MemoryRouter>
    );
  }
  render(<AccountMenu user={{ id: 1, email: "mike@fleetdm.com" }} onLogout={onLogout} />, { wrapper: Wrapper });
  return { onLogout };
}

describe("AccountMenu", () => {
  it("shows the email and is collapsed by default", () => {
    renderMenu([PermissionAction.SSOManage]);
    expect(screen.getByText("mike@fleetdm.com")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /mike@fleetdm.com/ })).toHaveAttribute("aria-expanded", "false");
  });

  it("opens the dropdown and shows Admin settings when sso.manage is granted", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.getByRole("button", { name: /mike@fleetdm.com/ })).toHaveAttribute("aria-expanded", "true");
    const link = screen.getByRole("link", { name: "Admin settings" });
    expect(link).toHaveAttribute("href", "/admin/settings/sso");
  });

  // spec:sso-configuration/the-single-sign-on-admin-settings-page/page-is-hidden-from-operators-without-the-grant
  it("hides Admin settings when sso.manage is absent", () => {
    renderMenu([PermissionAction.HostRead]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.queryByRole("link", { name: "Admin settings" })).not.toBeInTheDocument();
  });

  it("shows Detection tuning when detection_config.read is granted, linking to the page", () => {
    renderMenu([PermissionAction.DetectionConfigRead]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    const link = screen.getByRole("link", { name: "Detection tuning" });
    expect(link).toHaveAttribute("href", "/detection-config");
  });

  it("hides Detection tuning when detection_config.read is absent", () => {
    renderMenu([PermissionAction.HostRead]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.queryByRole("link", { name: "Detection tuning" })).not.toBeInTheDocument();
  });

  it("closes the menu when Detection tuning is clicked", () => {
    renderMenu([PermissionAction.DetectionConfigRead]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    fireEvent.click(screen.getByRole("link", { name: "Detection tuning" }));
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  it("calls onLogout from the menu", () => {
    const { onLogout } = renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    fireEvent.click(screen.getByRole("button", { name: "Log out" }));
    expect(onLogout).toHaveBeenCalledTimes(1);
  });

  it("opens the Documentation link safely and closes the menu when clicked", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    const docs = screen.getByRole("link", { name: "Documentation" });
    expect(docs).toHaveAttribute("target", "_blank");
    expect(docs).toHaveAttribute("rel", "noopener noreferrer");
    fireEvent.click(docs);
    expect(screen.queryByRole("link", { name: "Documentation" })).not.toBeInTheDocument();
  });

  it("closes the menu when Admin settings is clicked", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    fireEvent.click(screen.getByRole("link", { name: "Admin settings" }));
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  it("closes on an outside click", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.getByRole("button", { name: "Log out" })).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  it("closes on Escape", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.getByRole("button", { name: "Log out" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  it("shows a break-glass badge for a local_password session", () => {
    function Wrapper({ children }: { children: ReactNode }) {
      return (
        <MemoryRouter>
          <PermissionsProvider permissions={[]}>{children}</PermissionsProvider>
        </MemoryRouter>
      );
    }
    render(
      <AccountMenu user={{ id: 1, email: "bg@fleetdm.com" }} authMethod="local_password" onLogout={vi.fn()} />,
      { wrapper: Wrapper },
    );
    expect(screen.getByText("Break-glass")).toBeInTheDocument();
  });
});
