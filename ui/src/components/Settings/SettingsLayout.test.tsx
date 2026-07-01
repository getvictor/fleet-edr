import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { SettingsLayout } from "./SettingsLayout";
import { PermissionsProvider } from "../../permissions";
import { PermissionAction } from "../../permissions-core";

function renderLayout(permissions: string[] | undefined, path = "/admin/settings/sso") {
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <MemoryRouter initialEntries={[path]}>
        <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>
      </MemoryRouter>
    );
  }
  render(<SettingsLayout><div>section content</div></SettingsLayout>, { wrapper: Wrapper });
}

describe("SettingsLayout", () => {
  it("renders the section content and all sub-nav links when permitted", () => {
    renderLayout([PermissionAction.SSOManage, PermissionAction.UserRead, PermissionAction.ServiceAccountRead]);
    expect(screen.getByText("section content")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Single sign-on" })).toHaveAttribute("href", "/admin/settings/sso");
    expect(screen.getByRole("link", { name: "Users" })).toHaveAttribute("href", "/admin/settings/users");
    expect(screen.getByRole("link", { name: "Service accounts" })).toHaveAttribute("href", "/admin/settings/service-accounts");
  });

  it("omits a section the operator lacks permission for", () => {
    renderLayout([PermissionAction.ServiceAccountRead]);
    expect(screen.queryByRole("link", { name: "Single sign-on" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Service accounts" })).toBeInTheDocument();
  });

  it("marks the active section with aria-current", () => {
    renderLayout([PermissionAction.SSOManage, PermissionAction.ServiceAccountRead], "/admin/settings/service-accounts");
    expect(screen.getByRole("link", { name: "Service accounts" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Single sign-on" })).not.toHaveAttribute("aria-current");
  });

  // spec:web-ui/the-settings-area-manages-webhook-destinations/the-webhooks-section-is-hidden-without-the-manage-grant
  it("shows the Webhooks section only with webhook.manage", () => {
    renderLayout([PermissionAction.WebhookManage]);
    expect(screen.getByRole("link", { name: "Webhooks" })).toHaveAttribute("href", "/admin/settings/webhooks");
  });

  it("hides the Webhooks section without webhook.manage", () => {
    renderLayout([PermissionAction.ServiceAccountRead]);
    expect(screen.queryByRole("link", { name: "Webhooks" })).not.toBeInTheDocument();
  });
});
