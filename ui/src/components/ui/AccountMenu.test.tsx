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
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /mike@fleetdm.com/ })).toHaveAttribute("aria-expanded", "false");
  });

  it("opens the dropdown and shows Admin settings when sso.manage is granted", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    const link = screen.getByRole("menuitem", { name: "Admin settings" });
    expect(link).toHaveAttribute("href", "/admin/settings/sso");
  });

  // spec:sso-configuration/the-single-sign-on-admin-settings-page/page-is-hidden-from-operators-without-the-grant
  it("hides Admin settings when sso.manage is absent", () => {
    renderMenu([PermissionAction.HostRead]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.queryByRole("menuitem", { name: "Admin settings" })).not.toBeInTheDocument();
  });

  it("calls onLogout from the menu", () => {
    const { onLogout } = renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Log out" }));
    expect(onLogout).toHaveBeenCalledTimes(1);
  });

  it("closes on Escape", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: /mike@fleetdm.com/ }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
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
