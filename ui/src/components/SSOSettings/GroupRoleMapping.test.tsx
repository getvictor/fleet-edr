import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import type { SSOGroupRole } from "../../api";
import { GroupRoleMapping } from "./GroupRoleMapping";

function renderMapping(groupRoles: SSOGroupRole[] = [], claim = "groups", requestGroupsScope = false) {
  const handlers = { onClaimChange: vi.fn(), onGroupRolesChange: vi.fn(), onRequestGroupsScopeChange: vi.fn() };
  render(<GroupRoleMapping claim={claim} groupRoles={groupRoles} requestGroupsScope={requestGroupsScope} {...handlers} />);
  return handlers;
}

describe("GroupRoleMapping", () => {
  it("lists the mappings with each role's label", () => {
    renderMapping([
      { group: "edr-admins", role: "admin" },
      { group: "edr-senior", role: "senior_analyst" },
    ]);
    expect(screen.getByLabelText("Groups claim")).toHaveValue("groups");
    expect(screen.getByText("edr-admins")).toBeVisible();
    expect(screen.getByRole("cell", { name: "Admin" })).toBeVisible();
    expect(screen.getByRole("cell", { name: "Senior analyst" })).toBeVisible();
  });

  it("says when there are no mappings", () => {
    renderMapping();
    expect(screen.getByText("No group mappings.")).toBeVisible();
  });

  it("adds a trimmed group with the chosen role and clears the field", () => {
    const { onGroupRolesChange } = renderMapping([{ group: "edr-admins", role: "admin" }]);
    fireEvent.change(screen.getByLabelText("Group"), { target: { value: "  edr-auditors " } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "auditor" } });
    fireEvent.click(screen.getByRole("button", { name: "Add mapping" }));
    expect(onGroupRolesChange).toHaveBeenCalledWith([
      { group: "edr-admins", role: "admin" },
      { group: "edr-auditors", role: "auditor" },
    ]);
    expect(screen.getByLabelText("Group")).toHaveValue("");
  });

  it("adds on Enter and cancels the key's default, so the surrounding settings form is not submitted", () => {
    const { onGroupRolesChange } = renderMapping();
    fireEvent.change(screen.getByLabelText("Group"), { target: { value: "edr-admins" } });
    // fireEvent returns false when a handler called preventDefault; jsdom does not submit a form on Enter, so this is what shows it.
    expect(fireEvent.keyDown(screen.getByLabelText("Group"), { key: "Enter" })).toBe(false);
    expect(onGroupRolesChange).toHaveBeenCalledWith([{ group: "edr-admins", role: "analyst" }]);
  });

  it("offers only the roles an admin can grant, never super admin", () => {
    renderMapping();
    const options = Array.from(screen.getByLabelText("Role").querySelectorAll("option")).map((o) => o.value);
    expect(options).toEqual(["analyst", "senior_analyst", "auditor", "admin"]);
  });

  it("refuses a blank group and a group already mapped", () => {
    const { onGroupRolesChange } = renderMapping([{ group: "edr-admins", role: "admin" }]);
    const add = screen.getByRole("button", { name: "Add mapping" });
    expect(add).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Group"), { target: { value: "edr-admins" } });
    expect(add).toBeDisabled();
    expect(screen.getByText("edr-admins is already mapped. Remove it first to change its role.")).toBeVisible();
    fireEvent.keyDown(screen.getByLabelText("Group"), { key: "Enter" });
    expect(onGroupRolesChange).not.toHaveBeenCalled();
  });

  it("removes a mapping", () => {
    const { onGroupRolesChange } = renderMapping([
      { group: "edr-admins", role: "admin" },
      { group: "edr-auditors", role: "auditor" },
    ]);
    fireEvent.click(screen.getByRole("button", { name: "Remove edr-admins" }));
    expect(onGroupRolesChange).toHaveBeenCalledWith([{ group: "edr-auditors", role: "auditor" }]);
  });

  it("reports claim edits and the groups scope checkbox", () => {
    const { onClaimChange, onRequestGroupsScopeChange } = renderMapping([], "", true);
    fireEvent.change(screen.getByLabelText("Groups claim"), { target: { value: "roles" } });
    expect(onClaimChange).toHaveBeenCalledWith("roles");
    const scope = screen.getByRole("checkbox", { name: /Request the groups scope/ });
    expect(scope).toBeChecked();
    fireEvent.click(scope);
    expect(onRequestGroupsScopeChange).toHaveBeenCalledWith(false);
  });
});
