import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import type { ReactNode } from "react";
import { AccountMenu } from "./AccountMenu";
import { PermissionsProvider } from "../../permissions";
import { PermissionAction } from "../../permissions-core";

function renderMenu(permissions: string[] | undefined, onLogout = vi.fn(), roles?: readonly string[]) {
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <MemoryRouter>
        <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>
      </MemoryRouter>
    );
  }
  render(<AccountMenu user={{ id: 1, email: "mike@fleetdm.com" }} roles={roles} onLogout={onLogout} />, { wrapper: Wrapper });
  return { onLogout };
}

describe("AccountMenu", () => {
  // spec:web-ui/account-menu-conceals-the-signed-in-identity-until-opened/the-signed-in-email-is-hidden-until-the-account-menu-is-opened
  it("keeps the email out of the always-visible bar and is collapsed by default", () => {
    renderMenu([PermissionAction.SSOManage]);
    // The signed-in email must not be shown passively (shoulder-surfing): it is absent until the menu is opened.
    expect(screen.queryByText("mike@fleetdm.com")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Account menu" })).toHaveAttribute("aria-expanded", "false");
  });

  it("reveals the signed-in email inside the dropdown when opened", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByText("mike@fleetdm.com")).toBeInTheDocument();
  });

  it("opens the dropdown and shows Admin settings when sso.manage is granted", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByRole("button", { name: "Account menu" })).toHaveAttribute("aria-expanded", "true");
    const link = screen.getByRole("link", { name: "Admin settings" });
    expect(link).toHaveAttribute("href", "/admin/settings/sso");
  });

  // spec:sso-configuration/the-single-sign-on-admin-settings-page/page-is-hidden-from-operators-without-the-grant
  it("hides Admin settings when sso.manage is absent", () => {
    renderMenu([PermissionAction.HostRead]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.queryByRole("link", { name: "Admin settings" })).not.toBeInTheDocument();
  });

  // The Admin settings link is the ONLY way into that area, so gating it on one section's permission hid every other section from
  // whoever could open those instead. A senior analyst holds containment_config.read and no sso.manage.
  //
  // spec:web-ui/reachable-destinations-are-edited-in-containment-settings/a-reader-cannot-change-the-destinations
  it("offers Admin settings to an operator who can open a section other than single sign-on", () => {
    renderMenu([PermissionAction.ContainmentConfigRead]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));

    expect(screen.getByRole("link", { name: "Admin settings" })).toHaveAttribute("href", "/admin/settings/containment");
  });

  // An admin holds several, and lands on the first section rather than on whichever was added most recently.
  it("lands on the first section the operator can open", () => {
    renderMenu([PermissionAction.ContainmentConfigRead, PermissionAction.SSOManage, PermissionAction.UserRead]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));

    expect(screen.getByRole("link", { name: "Admin settings" })).toHaveAttribute("href", "/admin/settings/sso");
  });

  it("shows Detection tuning when detection_config.read is granted, linking to the page", () => {
    renderMenu([PermissionAction.DetectionConfigRead]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    const link = screen.getByRole("link", { name: "Detection tuning" });
    expect(link).toHaveAttribute("href", "/detection-config");
  });

  it("hides Detection tuning when detection_config.read is absent", () => {
    renderMenu([PermissionAction.HostRead]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.queryByRole("link", { name: "Detection tuning" })).not.toBeInTheDocument();
  });

  it("closes the menu when Detection tuning is clicked", () => {
    renderMenu([PermissionAction.DetectionConfigRead]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    fireEvent.click(screen.getByRole("link", { name: "Detection tuning" }));
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  it("calls onLogout from the menu", () => {
    const { onLogout } = renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    fireEvent.click(screen.getByRole("button", { name: "Log out" }));
    expect(onLogout).toHaveBeenCalledTimes(1);
  });

  it("opens the Documentation link safely and closes the menu when clicked", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    const docs = screen.getByRole("link", { name: "Documentation" });
    expect(docs).toHaveAttribute("target", "_blank");
    expect(docs).toHaveAttribute("rel", "noopener noreferrer");
    fireEvent.click(docs);
    expect(screen.queryByRole("link", { name: "Documentation" })).not.toBeInTheDocument();
  });

  it("closes the menu when Admin settings is clicked", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    fireEvent.click(screen.getByRole("link", { name: "Admin settings" }));
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  it("closes on an outside click", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByRole("button", { name: "Log out" })).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  it("closes on Escape", () => {
    renderMenu([PermissionAction.SSOManage]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByRole("button", { name: "Log out" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("button", { name: "Log out" })).not.toBeInTheDocument();
  });

  // spec:web-ui/the-account-menu-names-the-session-s-role-and-sign-in-method/an-sso-operator-sees-their-role-and-sign-in-method
  it("names the session's roles and its sign-in method inside the dropdown only", () => {
    function Wrapper({ children }: { children: ReactNode }) {
      return (
        <MemoryRouter>
          <PermissionsProvider permissions={[]}>{children}</PermissionsProvider>
        </MemoryRouter>
      );
    }
    render(
      <AccountMenu user={{ id: 1, email: "sa@fleetdm.com" }} authMethod="oidc" roles={["senior_analyst", "auditor"]} onLogout={vi.fn()} />,
      { wrapper: Wrapper },
    );
    expect(screen.queryByText(/Role:/)).not.toBeInTheDocument();
    expect(screen.queryByText("Break-glass")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByText("Role: Senior analyst, Auditor")).toBeVisible();
    expect(screen.getByText("Signed in with SSO")).toBeVisible();
  });

  // spec:web-ui/the-account-menu-names-the-session-s-role-and-sign-in-method/a-break-glass-operator-sees-their-role-and-sign-in-method
  it("names a break-glass session's role and says it was signed in with break-glass", () => {
    function Wrapper({ children }: { children: ReactNode }) {
      return (
        <MemoryRouter>
          <PermissionsProvider permissions={[]}>{children}</PermissionsProvider>
        </MemoryRouter>
      );
    }
    render(
      <AccountMenu user={{ id: 1, email: "bg@fleetdm.com" }} authMethod="local_password" roles={["super_admin"]} onLogout={vi.fn()} />,
      { wrapper: Wrapper },
    );
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByText("Role: Super admin")).toBeVisible();
    expect(screen.getByText("Signed in with break-glass")).toBeVisible();
  });

  it("says a session with no role has none, and names no sign-in method it does not know", () => {
    renderMenu([], vi.fn(), []);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByText("Role: none")).toBeVisible();
    expect(screen.queryByText(/Signed in with/)).not.toBeInTheDocument();
  });

  // spec:web-ui/the-account-menu-names-the-session-s-role-and-sign-in-method/a-session-whose-roles-are-not-reported-names-no-role
  it("names no role when the server did not send the session's roles", () => {
    renderMenu([]);
    fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
    expect(screen.getByText("mike@fleetdm.com")).toBeVisible();
    expect(screen.queryByText(/Role:/)).not.toBeInTheDocument();
  });

  it("shows a break-glass badge for a local_password session", () => {
    function Wrapper({ children }: { children: ReactNode }) {
      return (
        <MemoryRouter>
          <PermissionsProvider permissions={[]}>{children}</PermissionsProvider>
        </MemoryRouter>
      );
    }
    render(<AccountMenu user={{ id: 1, email: "bg@fleetdm.com" }} authMethod="local_password" onLogout={vi.fn()} />, { wrapper: Wrapper });
    expect(screen.getByText("Break-glass")).toBeInTheDocument();
  });
});
