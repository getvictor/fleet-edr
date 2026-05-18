import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { EditRuleModal } from "./EditRuleModal";
import * as api from "../../api";
import type { ApplicationControlRule } from "../../types";

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
  custom_msg: "",
  custom_url: "",
  comment: "",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "user:1",
  ...over,
});

beforeEach(() => {
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

describe("EditRuleModal", () => {
  it("disables Save until a field actually changes AND a reason is typed", () => {
    render(
      <EditRuleModal open rule={makeRule()} onClose={() => undefined} onSaved={() => undefined} />,
    );
    const save = screen.getByRole("button", { name: /save changes/i });
    // Initial state: no diff, no reason → disabled.
    expect(save).toBeDisabled();

    // Reason alone, no field change → still disabled.
    fireEvent.change(screen.getByLabelText(/reason \(required/i), {
      target: { value: "reason but no field change" },
    });
    expect(save).toBeDisabled();

    // Now flip severity → enables.
    fireEvent.change(screen.getByLabelText(/^severity$/i), { target: { value: "critical" } });
    expect(save).not.toBeDisabled();
  });

  it("rejects a non-http(s) More info URL client-side", async () => {
    const updateSpy = vi.spyOn(api, "updateAppControlRule").mockResolvedValue(makeRule());
    render(
      <EditRuleModal open rule={makeRule()} onClose={() => undefined} onSaved={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/more info url/i), {
      target: { value: "javascript:alert(1)" },
    });
    fireEvent.change(screen.getByLabelText(/reason \(required/i), {
      target: { value: "trying bad URL" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/http or https/i);
    });
    expect(updateSpy).not.toHaveBeenCalled();
  });

  // NOTE: the catch-block branch of EditRuleModal's URL guard (new URL throws on malformed input) is not directly reachable
  // through fireEvent because <input type="url"> performs HTML5 form validation BEFORE submit fires; the browser intercepts a
  // truly malformed value with its native tooltip and never invokes handleSubmit. The branch is defense-in-depth for any
  // future caller that bypasses the input element entirely. The protocol-check branch is covered by the test above.

  it("surfaces a typed AppControlApiError as an inline form error", async () => {
    vi.spyOn(api, "updateAppControlRule").mockRejectedValue(
      new api.AppControlApiError("application_control.rule_not_found", "rule not found", 404),
    );
    render(
      <EditRuleModal open rule={makeRule()} onClose={() => undefined} onSaved={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^severity$/i), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText(/reason \(required/i), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));
    await waitFor(() => {
      // EditRuleModal's errorMessageByCode maps rule_not_found to a UI-friendly message.
      expect(screen.getByRole("alert").textContent).toMatch(/rule was deleted/i);
    });
  });

  it("calls onSaved on the happy path and submits only the changed fields + reason", async () => {
    const updateSpy = vi.spyOn(api, "updateAppControlRule").mockResolvedValue(
      makeRule({ severity: "critical" }),
    );
    const onSaved = vi.fn();
    render(
      <EditRuleModal open rule={makeRule()} onClose={() => undefined} onSaved={onSaved} />,
    );
    fireEvent.change(screen.getByLabelText(/^severity$/i), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText(/reason \(required/i), { target: { value: "promote" } });
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));
    await waitFor(() => {
      expect(onSaved).toHaveBeenCalled();
    });
    expect(updateSpy.mock.calls[0]).toEqual([1, { severity: "critical", reason: "promote" }]);
  });

  it("renders harmlessly with rule=null and short-circuits submit", async () => {
    const updateSpy = vi.spyOn(api, "updateAppControlRule");
    render(
      <EditRuleModal open rule={null} onClose={() => undefined} onSaved={() => undefined} />,
    );
    // Reason input is reachable (the dialog is open); the rule=null parameter is a defensive prop signaling the parent has
    // no row to edit. Typing a reason + clicking save must NOT issue an API call because handleSubmit's `if (!rule) return`
    // short-circuit fires. Without this guard, a stale modal instance could PATCH against a deleted rule.
    fireEvent.change(screen.getByLabelText(/reason \(required/i), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));
    await waitFor(() => {
      expect(updateSpy).not.toHaveBeenCalled();
    });
  });
});
