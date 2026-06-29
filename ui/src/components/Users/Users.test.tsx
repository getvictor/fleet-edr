import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { PermissionsContext } from "../../permissions-core";
import * as api from "../../api";
import { Users } from "./Users";

const baseUsers: api.AdminUser[] = [
  { id: 1, email: "alice@acme.com", role: "analyst", roles: ["analyst"], status: "active", is_breakglass: false },
  { id: 2, email: "bob@acme.com", role: "admin", roles: ["admin"], status: "disabled", is_breakglass: false },
  { id: 3, email: "root@acme.com", role: "super_admin", roles: ["super_admin"], status: "active", is_breakglass: false },
  { id: 4, email: "bg@acme.com", display_name: "Recovery", role: "admin", roles: ["admin"], status: "active", is_breakglass: true },
];

function renderUsers(perms?: readonly string[]) {
  return render(
    <PermissionsContext.Provider value={perms}>
      <Users />
    </PermissionsContext.Provider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Users", () => {
  // spec:web-ui/admin-settings-exposes-a-user-management-page/the-users-page-lists-operators-and-changes-a-role
  it("lists operators with role + status and submits a role change", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue(baseUsers);
    const setRole = vi.spyOn(api, "setUserRole").mockResolvedValue(baseUsers[0]);
    renderUsers(); // no provider value -> optimistic, can manage

    expect(await screen.findByText("alice@acme.com")).toBeInTheDocument();
    expect(screen.getAllByText("Active").length).toBeGreaterThan(0);
    expect(screen.getByText("Disabled")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Role for alice@acme.com"), { target: { value: "senior_analyst" } });
    await waitFor(() => { expect(setRole).toHaveBeenCalledWith(1, "senior_analyst"); });
  });

  it("renders super_admin and break-glass rows read-only even when the operator can manage", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue(baseUsers);
    renderUsers();
    await screen.findByText("root@acme.com");

    // Editable rows expose a role selector; super_admin + break-glass rows do not.
    expect(screen.getByLabelText("Role for alice@acme.com")).toBeInTheDocument();
    expect(screen.queryByLabelText("Role for root@acme.com")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Role for bg@acme.com")).not.toBeInTheDocument();
    expect(screen.getByText("Super admin")).toBeInTheDocument();
    expect(screen.getByText("Break-glass")).toBeInTheDocument();
  });

  it("disables a user", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue([baseUsers[0]]);
    const setStatus = vi.spyOn(api, "setUserStatus").mockResolvedValue({ ...baseUsers[0], status: "disabled" });
    renderUsers();
    await screen.findByText("alice@acme.com");

    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    await waitFor(() => { expect(setStatus).toHaveBeenCalledWith(1, "disabled"); });
  });

  it("enables a disabled user", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue([baseUsers[1]]);
    const setStatus = vi.spyOn(api, "setUserStatus").mockResolvedValue({ ...baseUsers[1], status: "active" });
    renderUsers();
    await screen.findByText("bob@acme.com");

    fireEvent.click(screen.getByRole("button", { name: "Enable" }));
    await waitFor(() => { expect(setStatus).toHaveBeenCalledWith(2, "active"); });
  });

  it("hides mutation controls when the operator lacks user.manage", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue(baseUsers);
    renderUsers(["user.read"]); // read but not manage
    await screen.findByText("alice@acme.com");

    expect(screen.queryByLabelText("Role for alice@acme.com")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
    // The role is still shown, as a badge.
    expect(screen.getByText("Analyst")).toBeInTheDocument();
  });

  it("surfaces a guardrail conflict with friendly copy", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue([baseUsers[0]]);
    vi.spyOn(api, "setUserRole").mockRejectedValue(new Error("API error: 409 Conflict"));
    renderUsers();
    await screen.findByText("alice@acme.com");

    fireEvent.change(screen.getByLabelText("Role for alice@acme.com"), { target: { value: "admin" } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/last admin|break-glass/i);
  });

  it("keeps the table and shows a transient error when a background refresh fails", async () => {
    // Initial load succeeds; the post-mutation reload() rejects. The table must stay visible (not be replaced by a page error).
    vi.spyOn(api, "listUsers").mockResolvedValueOnce([baseUsers[0]]).mockRejectedValue(new Error("refresh boom"));
    vi.spyOn(api, "setUserStatus").mockResolvedValue({ ...baseUsers[0], status: "disabled" });
    renderUsers();
    await screen.findByText("alice@acme.com");

    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("refresh boom");
    // Table is still there (not replaced by the page-level "Error:" state).
    expect(screen.getByText("alice@acme.com")).toBeInTheDocument();
    expect(screen.queryByText(/Error: refresh boom/)).not.toBeInTheDocument();
  });

  // spec:web-ui/the-users-page-pre-provisions-a-new-user-and-distinguishes-the-pending-state/an-admin-pre-provisions-a-user-from-the-users-page
  it("pre-provisions a user from the add-user form and refreshes the list", async () => {
    const staged: api.AdminUser = {
      id: 9, email: "carol@acme.com", role: "senior_analyst", roles: ["senior_analyst"], status: "provisioned", is_breakglass: false,
    };
    const listUsers = vi.spyOn(api, "listUsers").mockResolvedValueOnce([baseUsers[0]]).mockResolvedValue([baseUsers[0], staged]);
    const createUser = vi.spyOn(api, "createUser").mockResolvedValue(staged);
    renderUsers(); // optimistic -> can invite

    await screen.findByText("alice@acme.com");
    // Opening the form unmounts the header trigger, leaving the form's submit button as the only "Add user" button.
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "carol@acme.com" } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "senior_analyst" } });
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));

    await waitFor(() => { expect(createUser).toHaveBeenCalledWith("carol@acme.com", "senior_analyst"); });
    // The refreshed list shows the new user with a pending indicator.
    expect(await screen.findByText("carol@acme.com")).toBeInTheDocument();
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(listUsers).toHaveBeenCalledTimes(2);
  });

  // spec:web-ui/the-users-page-pre-provisions-a-new-user-and-distinguishes-the-pending-state/the-add-user-control-is-hidden-without-the-invite-grant
  it("hides the add-user control when the operator lacks user.invite", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue(baseUsers);
    renderUsers(["user.read", "user.manage"]); // manage but not invite
    await screen.findByText("alice@acme.com");
    expect(screen.queryByRole("button", { name: "Add user" })).not.toBeInTheDocument();
  });

  it("shows a pending badge and no enable/disable control for a provisioned user", async () => {
    const staged: api.AdminUser = {
      id: 7, email: "dora@acme.com", role: "auditor", roles: ["auditor"], status: "provisioned", is_breakglass: false,
    };
    vi.spyOn(api, "listUsers").mockResolvedValue([staged]);
    renderUsers();
    await screen.findByText("dora@acme.com");
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enable" })).not.toBeInTheDocument();
    // Their role is still editable (re-stage before first login).
    expect(screen.getByLabelText("Role for dora@acme.com")).toBeInTheDocument();
  });

  it("surfaces a duplicate-email conflict in the add-user form", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue([baseUsers[0]]);
    vi.spyOn(api, "createUser").mockRejectedValue(new Error("API error: 409 Conflict"));
    renderUsers();
    await screen.findByText("alice@acme.com");

    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "dup@acme.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/already exists/i);
  });

  it("shows a permission message when add-user is forbidden (stale invite grant)", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue([baseUsers[0]]);
    vi.spyOn(api, "createUser").mockRejectedValue(new Error("API error: 403 Forbidden"));
    renderUsers();
    await screen.findByText("alice@acme.com");

    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new@acme.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/permission to add users/i);
  });

  it("shows the empty state", async () => {
    vi.spyOn(api, "listUsers").mockResolvedValue([]);
    renderUsers();
    expect(await screen.findByText("No users yet.")).toBeInTheDocument();
  });

  it("renders the load error state", async () => {
    vi.spyOn(api, "listUsers").mockRejectedValue(new Error("boom"));
    renderUsers();
    expect(await screen.findByText(/Error: boom/)).toBeInTheDocument();
  });
});
