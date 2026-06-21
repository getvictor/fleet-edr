import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import * as api from "../../api";
import { ServiceAccounts } from "./ServiceAccounts";

const baseAccounts: api.ServiceAccount[] = [
  {
    id: 1, client_id: "sa_abc", name: "ci-pipeline", role: "analyst", status: "active",
    created_at: "2026-06-01T00:00:00Z", expires_at: "2026-09-01T00:00:00Z",
  },
  {
    id: 2, client_id: "sa_def", name: "old-bot", role: "auditor", status: "revoked",
    created_at: "2026-05-01T00:00:00Z", expires_at: "2026-08-01T00:00:00Z", last_used_at: "2026-06-10T00:00:00Z",
  },
];

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ServiceAccounts", () => {
  // spec:server-identity-service-accounts/service-accounts-are-managed-from-an-admin-surface-behind-the-chokepoint/page-is-hidden-without-the-grant
  it("renders the list with role and status badges", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue(baseAccounts);
    render(<ServiceAccounts />);
    expect(await screen.findByText("ci-pipeline")).toBeInTheDocument();
    expect(screen.getByText("sa_abc")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.getByText("Analyst")).toBeInTheDocument();
    expect(screen.getByText("Auditor")).toBeInTheDocument();
    // Account 1 was never used.
    expect(screen.getByText("Never")).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([]);
    render(<ServiceAccounts />);
    expect(await screen.findByText("No service accounts yet.")).toBeInTheDocument();
  });

  it("renders the load error state", async () => {
    vi.spyOn(api, "listServiceAccounts").mockRejectedValue(new Error("boom"));
    render(<ServiceAccounts />);
    expect(await screen.findByText(/Error: boom/)).toBeInTheDocument();
  });

  it("creates a service account and shows the one-time secret", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([]);
    const create = vi.spyOn(api, "createServiceAccount").mockResolvedValue({
      id: 3, client_id: "sa_new", name: "bot", role: "analyst", status: "active",
      created_at: "2026-06-20T00:00:00Z", expires_at: "2026-09-18T00:00:00Z", secret: "edrsa_one_time",
    });
    render(<ServiceAccounts />);
    await screen.findByText("No service accounts yet.");

    fireEvent.click(screen.getByRole("button", { name: "Create service account" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "bot" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => { expect(create).toHaveBeenCalledTimes(1); });
    expect(create.mock.calls[0][0]).toEqual({ name: "bot", role: "analyst" });
    expect(await screen.findByLabelText("Client secret")).toHaveValue("edrsa_one_time");
    expect(screen.getByLabelText("Client ID")).toHaveValue("sa_new");
  });

  it("passes expires_in_days when provided", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([]);
    const create = vi.spyOn(api, "createServiceAccount").mockResolvedValue({
      id: 4, client_id: "sa_x", name: "x", role: "auditor", status: "active",
      created_at: "2026-06-20T00:00:00Z", expires_at: "2026-07-20T00:00:00Z", secret: "edrsa_x",
    });
    render(<ServiceAccounts />);
    await screen.findByText("No service accounts yet.");

    fireEvent.click(screen.getByRole("button", { name: "Create service account" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "auditor" } });
    fireEvent.change(screen.getByLabelText("Expires in (days)"), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => { expect(create).toHaveBeenCalledTimes(1); });
    expect(create.mock.calls[0][0]).toEqual({ name: "x", role: "auditor", expires_in_days: 30 });
  });

  it("requires a name", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([]);
    const create = vi.spyOn(api, "createServiceAccount");
    render(<ServiceAccounts />);
    await screen.findByText("No service accounts yet.");

    fireEvent.click(screen.getByRole("button", { name: "Create service account" }));
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Name is required.");
    expect(create).not.toHaveBeenCalled();
  });

  it("surfaces a create error", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([]);
    vi.spyOn(api, "createServiceAccount").mockRejectedValue(new Error("API error: 400 Bad Request"));
    render(<ServiceAccounts />);
    await screen.findByText("No service accounts yet.");

    fireEvent.click(screen.getByRole("button", { name: "Create service account" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "bot" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("API error: 400");
  });

  it("rotates a secret and shows the new value", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue(baseAccounts);
    const rotate = vi.spyOn(api, "rotateServiceAccount").mockResolvedValue({ secret: "edrsa_rotated" });
    render(<ServiceAccounts />);
    await screen.findByText("ci-pipeline");

    fireEvent.click(screen.getByRole("button", { name: "Rotate" }));
    await waitFor(() => { expect(rotate).toHaveBeenCalledWith(1); });
    expect(await screen.findByLabelText("Client secret")).toHaveValue("edrsa_rotated");
  });

  it("surfaces a rotate error", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue(baseAccounts);
    vi.spyOn(api, "rotateServiceAccount").mockRejectedValue(new Error("rotate failed"));
    render(<ServiceAccounts />);
    await screen.findByText("ci-pipeline");
    fireEvent.click(screen.getByRole("button", { name: "Rotate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("rotate failed");
  });

  it("revokes only after confirmation", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue(baseAccounts);
    const revoke = vi.spyOn(api, "revokeServiceAccount").mockResolvedValue();
    render(<ServiceAccounts />);
    await screen.findByText("ci-pipeline");

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(revoke).not.toHaveBeenCalled();
    expect(screen.getByText(/Revoke ci-pipeline\?/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => { expect(revoke).toHaveBeenCalledWith(1); });
  });

  it("cancels a revoke confirmation without calling the API", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue(baseAccounts);
    const revoke = vi.spyOn(api, "revokeServiceAccount").mockResolvedValue();
    render(<ServiceAccounts />);
    await screen.findByText("ci-pipeline");

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(revoke).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
  });

  it("offers no rotate/revoke actions on a revoked account", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([baseAccounts[1]]); // revoked only
    render(<ServiceAccounts />);
    await screen.findByText("old-bot");
    expect(screen.queryByRole("button", { name: "Rotate" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });

  it("copies the issued secret when the clipboard API is available", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([]);
    vi.spyOn(api, "createServiceAccount").mockResolvedValue({
      id: 5, client_id: "sa_c", name: "c", role: "analyst", status: "active",
      created_at: "2026-06-20T00:00:00Z", expires_at: "2026-09-18T00:00:00Z", secret: "edrsa_copy",
    });
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(<ServiceAccounts />);
    await screen.findByText("No service accounts yet.");

    fireEvent.click(screen.getByRole("button", { name: "Create service account" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "c" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await screen.findByLabelText("Client secret");
    fireEvent.click(screen.getByRole("button", { name: "Copy client secret" }));
    await waitFor(() => { expect(writeText).toHaveBeenCalledWith("edrsa_copy"); });
    vi.unstubAllGlobals();

    // Dismissing the secret callout hides it.
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByLabelText("Client secret")).not.toBeInTheDocument();
  });

  it("does not throw copying without a clipboard API", async () => {
    vi.spyOn(api, "listServiceAccounts").mockResolvedValue([]);
    vi.spyOn(api, "createServiceAccount").mockResolvedValue({
      id: 6, client_id: "sa_d", name: "d", role: "analyst", status: "active",
      created_at: "2026-06-20T00:00:00Z", expires_at: "2026-09-18T00:00:00Z", secret: "edrsa_d",
    });
    vi.stubGlobal("navigator", {});
    render(<ServiceAccounts />);
    await screen.findByText("No service accounts yet.");
    fireEvent.click(screen.getByRole("button", { name: "Create service account" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "d" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await screen.findByLabelText("Client secret");
    expect(() => { fireEvent.click(screen.getByRole("button", { name: "Copy client secret" })); }).not.toThrow();
    vi.unstubAllGlobals();
  });
});
