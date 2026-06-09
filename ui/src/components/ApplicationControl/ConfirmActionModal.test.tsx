import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ConfirmActionModal } from "./ConfirmActionModal";
import { AppControlApiError, ReauthRequiredError } from "../../api";

// Isolate ConfirmActionModal from the reauth hook: a pass-through `call` lets a propagated ReauthRequiredError reach
// handleSubmit's catch (the real hook intercepts it inside its own modal flow), so the reauth-handled branch is
// unit-testable from this component's perspective.
vi.mock("../../hooks/useReauthRetry", () => ({
  useReauthRetry: <A extends readonly unknown[], R>(action: (...args: A) => Promise<R>) => ({
    call: action,
    modal: { open: false, challenge: null, resolve: () => undefined },
  }),
}));

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

describe("ConfirmActionModal", () => {
  it("disables the submit button until a reason is typed", () => {
    render(
      <ConfirmActionModal
        open
        title="Delete rule"
        description="will be removed"
        confirmLabel="Delete rule"
        confirmVariant="alert"
        onClose={() => undefined}
        onConfirm={vi.fn()}
      />,
    );
    const confirm = screen.getByRole("button", { name: /delete rule/i });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/reason \(required/i), { target: { value: "good reason" } });
    expect(confirm).not.toBeDisabled();
  });

  it("calls onConfirm with the trimmed reason on submit", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(
      <ConfirmActionModal
        open
        title="Disable rule"
        description="will be paused"
        confirmLabel="Disable rule"
        onClose={() => undefined}
        onConfirm={onConfirm}
      />,
    );
    fireEvent.change(screen.getByLabelText(/reason \(required/i), {
      target: { value: "  trim me   " },
    });
    fireEvent.click(screen.getByRole("button", { name: /disable rule/i }));
    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith("trim me");
    });
  });

  it("maps a typed AppControlApiError onto the inline alert via dialogErrors", async () => {
    const onConfirm = vi.fn().mockRejectedValue(
      new AppControlApiError("application_control.policy_immutable", "cannot delete Default", 409),
    );
    render(
      <ConfirmActionModal
        open
        title="Delete rule"
        description="will be removed"
        confirmLabel="Delete rule"
        confirmVariant="alert"
        onClose={() => undefined}
        onConfirm={onConfirm}
      />,
    );
    fireEvent.change(screen.getByLabelText(/reason \(required/i), { target: { value: "try delete" } });
    fireEvent.click(screen.getByRole("button", { name: /delete rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/default policy cannot be deleted/i);
    });
  });

  it("swallows ReauthRequiredError without surfacing an inline alert (the reauth modal handles the retry)", async () => {
    const onConfirm = vi.fn().mockRejectedValue(
      new ReauthRequiredError({ authMethod: "oidc", reauthURL: "https://idp.example/reauth" }),
    );
    render(
      <ConfirmActionModal
        open
        title="Delete rule"
        description="will be removed"
        confirmLabel="Delete rule"
        confirmVariant="alert"
        onClose={() => undefined}
        onConfirm={onConfirm}
      />,
    );
    fireEvent.change(screen.getByLabelText(/reason \(required/i), { target: { value: "needs reauth" } });
    fireEvent.click(screen.getByRole("button", { name: /delete rule/i }));
    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith("needs reauth");
    });
    // applyAppControlSubmitError returns true for a reauth error, so handleSubmit returns early without setting formError.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("clicking Cancel routes through onClose", () => {
    const onClose = vi.fn();
    render(
      <ConfirmActionModal
        open
        title="Enable rule"
        description="will resume"
        confirmLabel="Enable rule"
        onClose={onClose}
        onConfirm={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
