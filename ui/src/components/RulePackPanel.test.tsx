import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { RulePackPanel } from "./RulePackPanel";
import * as api from "../api";
import type { RulePackStatus } from "../api";

const status = (over: Partial<RulePackStatus> = {}): RulePackStatus => ({
  installed: "pack-2",
  available: "pack-2",
  previous: "pack-1",
  declined: "",
  current: true,
  can_roll_back: true,
  added: [],
  removed: [],
  changed: [],
  ...over,
});

beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() { this.open = true; };
  HTMLDialogElement.prototype.close = function close() { this.open = false; };
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("RulePackPanel", () => {
  it("says the deployment runs the shipped rules this build carries", async () => {
    vi.spyOn(api, "getRulePackStatus").mockResolvedValue(status());
    render(<RulePackPanel canWrite={false} />);

    expect(await screen.findByText("This deployment runs the shipped rules this build carries.")).toBeVisible();
    // Reading status is not permission to change it.
    expect(screen.queryByRole("button", { name: "Roll back shipped rules" })).toBeNull();
  });

  it("names the rules that differ when the deployment is not current", async () => {
    vi.spyOn(api, "getRulePackStatus").mockResolvedValue(
      status({ current: false, added: ["new_rule"], changed: ["noisy_rule", "other_rule"] }),
    );
    render(<RulePackPanel canWrite={false} />);

    expect(await screen.findByText("Rules this build adds: 1")).toBeVisible();
    expect(screen.getByText("Rules this build changes: 2")).toBeVisible();
    expect(screen.queryByText(/Rules this build removes/)).toBeNull();
  });

  // spec:web-ui/rules-can-be-written-in-the-console/an-operator-rolls-back-the-shipped-rules-with-a-reason
  it("rolls back with a reason and names the shipped rules it did not restore", async () => {
    vi.spyOn(api, "getRulePackStatus").mockResolvedValue(status());
    const rollback = vi.spyOn(api, "rollbackRulePack").mockResolvedValue({ restored: "pack-1", version: 9, withheld: ["keychain_dump"] });
    render(<RulePackPanel canWrite />);

    fireEvent.click(await screen.findByRole("button", { name: "Roll back shipped rules" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "new pack is noisy" } });
    fireEvent.click(screen.getByRole("button", { name: "Roll back" }));

    expect(await screen.findByRole("status")).toHaveTextContent("Rolled back to the previous shipped rules.");
    expect(screen.getByRole("status")).toHaveTextContent("keychain_dump");
    expect(rollback).toHaveBeenCalledWith("new pack is noisy");
  });

  it("offers no rollback when there is nothing to roll back to", async () => {
    vi.spyOn(api, "getRulePackStatus").mockResolvedValue(status({ can_roll_back: false }));
    render(<RulePackPanel canWrite />);

    await screen.findByText("This deployment runs the shipped rules this build carries.");
    expect(screen.queryByRole("button", { name: "Roll back shipped rules" })).toBeNull();
  });
});
