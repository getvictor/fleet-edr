import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { EnforcementChoice } from "./EnforcementChoice";

describe("EnforcementChoice", () => {
  it("checks the option matching the value and reports a change", () => {
    const onChange = vi.fn();
    const { rerender } = render(<EnforcementChoice name="choice" value={null} onChange={onChange} />);
    expect(screen.getByRole("radio", { name: /detect/i })).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /protect/i })).not.toBeChecked();

    fireEvent.click(screen.getByRole("radio", { name: /protect/i }));
    expect(onChange).toHaveBeenCalledWith("PROTECT");

    rerender(<EnforcementChoice name="choice" value="DETECT" onChange={onChange} />);
    expect(screen.getByRole("radio", { name: /detect/i })).toBeChecked();
    expect(screen.getByRole("radio", { name: /protect/i })).not.toBeChecked();
  });

  it("names each option by its label and describes it with its help", () => {
    const onChange = vi.fn();
    render(<EnforcementChoice name="choice" value={null} onChange={onChange} />);
    expect(screen.getByRole("radio", { name: "Detect" })).toHaveAccessibleDescription(/record each match without blocking it/i);
    expect(screen.getByRole("radio", { name: "Protect" })).toHaveAccessibleDescription("Block the executable.");

    fireEvent.click(screen.getByText("Detect"));
    expect(onChange).toHaveBeenCalledWith("DETECT");
  });

  it("disables both options while the form is busy", () => {
    render(<EnforcementChoice name="choice" value={null} onChange={() => undefined} disabled />);
    expect(screen.getByRole("radio", { name: /detect/i })).toBeDisabled();
    expect(screen.getByRole("radio", { name: /protect/i })).toBeDisabled();
  });
});
