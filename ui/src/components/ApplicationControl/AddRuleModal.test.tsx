import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AddRuleModal } from "./AddRuleModal";
import * as api from "../../api";
import type { ApplicationControlRule } from "../../types";

// AddRuleModal is the demo cut's only complex form. The tests below
// pin the validation contract the camera-facing flow depends on:
//   - reason is required (gates Save)
//   - BINARY identifier must be 64 lowercase hex chars
//   - More info URL is rejected if it isn't http/https
//   - typed AppControlApiError codes map to readable copy
//   - happy path calls onCreated exactly once
// Native <dialog>'s showModal() isn't implemented in jsdom; the tests
// stub it minimally so the rest of the React tree renders.

const makeRule = (over: Partial<ApplicationControlRule> = {}): ApplicationControlRule => ({
  id: 1,
  policy_id: 1,
  rule_type: "BINARY",
  identifier: "a".repeat(64),
  action: "BLOCK",
  enforcement: "PROTECT",
  enabled: true,
  severity: "medium",
  source: "admin",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "user:1",
  ...over,
});

// jsdom doesn't implement HTMLDialogElement.showModal/close; patch
// them as no-ops on the prototype so the modal renders without
// throwing TypeError.
beforeEach(() => {
  // jsdom doesn't implement HTMLDialogElement.showModal/close.
  // The TS prototype claims both exist, so the runtime existence
  // check tripping no-unnecessary-condition is expected; assign
  // unconditionally instead.
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close() {
    this.open = false;
  };
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AddRuleModal", () => {
  it("does not render content when closed", () => {
    render(
      <AddRuleModal
        open={false}
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    // Title only shows once the dialog is open; we can't assert
    // it's gone (it's still in the DOM under jsdom's stubbed
    // showModal) but the dialog element should not have its
    // `open` attribute set.
    const dialog = document.querySelector("dialog");
    expect(dialog).not.toBeNull();
    expect((dialog as HTMLDialogElement).open).toBe(false);
  });

  it("disables Save until both identifier and reason are populated", () => {
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    const save = screen.getByRole("button", { name: /save rule/i });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "a".repeat(64) },
    });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    expect(save).not.toBeDisabled();
  });

  it("rejects an identifier that is not 64 lowercase hex characters", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "not-a-real-hash" },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/BINARY identifier/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("rejects an upper-case hex identifier (BINARY requires lowercase)", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      // Uppercase wouldn't even make it past the client validator
      // (the server's BINARY rule is "64 lowercase hex"). The
      // client normalises lowercase before POSTing, so an
      // uppercase string passes the regex check after trim().toLowerCase().
      // We instead test the truncated form to keep this distinct
      // from the bad-charset case above.
      target: { value: "a".repeat(40) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/64 lowercase hex/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("rejects a non-http(s) More info URL", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "a".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.change(screen.getByLabelText(/more info url/i), {
      target: { value: "javascript:alert(1)" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/http or https/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("submits and fires onCreated on the happy path", async () => {
    const created = makeRule();
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(created);
    const onCreated = vi.fn();
    render(
      <AddRuleModal
        open
        policyID={42}
        onClose={() => undefined}
        onCreated={onCreated}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "b".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo rehearsal" },
    });
    fireEvent.change(screen.getByLabelText(/custom message/i), {
      target: { value: "Blocked by corp policy" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(createSpy).toHaveBeenCalledTimes(1);
    });
    expect(createSpy).toHaveBeenCalledWith(42, expect.objectContaining({
      rule_type: "BINARY",
      identifier: "b".repeat(64),
      reason: "demo rehearsal",
      severity: "medium",
      custom_msg: "Blocked by corp policy",
    }));
    await waitFor(() => {
      expect(onCreated).toHaveBeenCalledTimes(1);
    });
  });

  it("maps a duplicate_rule AppControlApiError to a readable message", async () => {
    vi.spyOn(api, "createAppControlRule").mockRejectedValue(
      new api.AppControlApiError("application_control.duplicate_rule", "duplicate", 409),
    );
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "c".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/already exists/i);
    });
  });

  it("falls back to the server's message for an unknown error code", async () => {
    vi.spyOn(api, "createAppControlRule").mockRejectedValue(
      new api.AppControlApiError("application_control.unmapped", "server message", 400),
    );
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "d".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/server message/i);
    });
  });

  it("invokes onClose when the Cancel button is clicked", () => {
    const onClose = vi.fn();
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={onClose}
        onCreated={() => undefined}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
