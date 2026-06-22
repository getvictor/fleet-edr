import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ReasonModal } from "./ReasonModal";

// jsdom doesn't implement HTMLDialogElement.showModal/close; stub them so the modal renders.
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() { this.open = true; };
  HTMLDialogElement.prototype.close = function close() { this.open = false; };
});

afterEach(() => { vi.restoreAllMocks(); });

describe("ReasonModal", () => {
  it("renders the title + description and disables confirm until a reason is typed", () => {
    render(
      <ReasonModal title='Disable "x"?' description="reduces alerting" confirmLabel="Disable rule"
        onConfirm={vi.fn()} onCancel={vi.fn()} />,
    );
    expect(screen.getByText('Disable "x"?')).toBeInTheDocument();
    expect(screen.getByText("reduces alerting")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disable rule" })).toBeDisabled();
  });

  it("passes the trimmed reason to onConfirm on submit", () => {
    const onConfirm = vi.fn();
    render(<ReasonModal title="t" confirmLabel="Save" onConfirm={onConfirm} onCancel={vi.fn()} />);
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "  too noisy  " } });
    const confirm = screen.getByRole("button", { name: "Save" });
    expect(confirm).not.toBeDisabled();
    fireEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith("too noisy");
  });

  it("calls onCancel from the cancel button", () => {
    const onCancel = vi.fn();
    render(<ReasonModal title="t" confirmLabel="Save" onConfirm={vi.fn()} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it("calls onCancel on a backdrop click (target is the dialog itself)", () => {
    const onCancel = vi.fn();
    render(<ReasonModal title="t" confirmLabel="Save" onConfirm={vi.fn()} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole("dialog"));
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it("disables both controls and the textarea while busy", () => {
    render(<ReasonModal title="t" confirmLabel="Save" busy onConfirm={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByLabelText(/reason/i)).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  });

  it("ignores a backdrop click while busy (no dismiss mid-mutation)", () => {
    const onCancel = vi.fn();
    render(<ReasonModal title="t" confirmLabel="Save" busy onConfirm={vi.fn()} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole("dialog"));
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("surfaces an error message", () => {
    render(<ReasonModal title="t" confirmLabel="Save" error="boom" onConfirm={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });
});
