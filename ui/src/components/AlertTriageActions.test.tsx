import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AlertTriageActions } from "./AlertTriageActions";
import * as api from "../api";

afterEach(() => { vi.restoreAllMocks(); });

// AlertTriageActions is the alert's lifecycle controls, relocated from the process-detail panel to the alert header (issue: the node
// inspector restated the alert and was the only place its status could change). Tests pin the status pill, each transition's api call,
// the local onStatusChange callback, and that a resolved alert offers reopen instead of acknowledge.
describe("AlertTriageActions", () => {
  // spec:web-ui/alert-pivots-to-the-host-process-tree/operator-triages-the-alert-from-its-detail-surface
  it("shows the current status and acknowledges an open alert", async () => {
    const spy = vi.spyOn(api, "updateAlertStatus").mockResolvedValue(undefined);
    const onStatusChange = vi.fn();
    render(<AlertTriageActions alertId={7} status="open" onStatusChange={onStatusChange} />);
    expect(screen.getByText("open")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /acknowledge/i }));
    await waitFor(() => { expect(spy).toHaveBeenCalledWith(7, "acknowledged"); });
    expect(onStatusChange).toHaveBeenCalledWith("acknowledged");
  });

  it("resolves an acknowledged alert (no acknowledge control once past open)", async () => {
    const spy = vi.spyOn(api, "updateAlertStatus").mockResolvedValue(undefined);
    const onStatusChange = vi.fn();
    render(<AlertTriageActions alertId={7} status="acknowledged" onStatusChange={onStatusChange} />);
    expect(screen.queryByRole("button", { name: /acknowledge/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /resolve/i }));
    await waitFor(() => { expect(spy).toHaveBeenCalledWith(7, "resolved"); });
    expect(onStatusChange).toHaveBeenCalledWith("resolved");
  });

  it("offers reopen for a resolved alert instead of acknowledge or resolve", async () => {
    const spy = vi.spyOn(api, "updateAlertStatus").mockResolvedValue(undefined);
    const onStatusChange = vi.fn();
    render(<AlertTriageActions alertId={7} status="resolved" onStatusChange={onStatusChange} />);
    expect(screen.queryByRole("button", { name: /acknowledge/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /resolve/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /reopen/i }));
    await waitFor(() => { expect(spy).toHaveBeenCalledWith(7, "open"); });
    expect(onStatusChange).toHaveBeenCalledWith("open");
  });

  it("leaves the status unchanged when the mutation fails", async () => {
    vi.spyOn(api, "updateAlertStatus").mockRejectedValue(new Error("boom"));
    const onStatusChange = vi.fn();
    render(<AlertTriageActions alertId={7} status="open" onStatusChange={onStatusChange} />);
    fireEvent.click(screen.getByRole("button", { name: /acknowledge/i }));
    await waitFor(() => { expect(api.updateAlertStatus).toHaveBeenCalled(); });
    expect(onStatusChange).not.toHaveBeenCalled();
  });
});
