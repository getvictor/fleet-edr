import { describe, it, expect } from "vitest";
import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Toggle } from "./Toggle";

function Controlled() {
  const [on, setOn] = useState(false);
  return <Toggle id="t" aria-label="Enable" checked={on} onChange={(e) => { setOn(e.target.checked); }} />;
}

describe("Toggle", () => {
  it("renders as a switch reflecting the checked prop", () => {
    render(<Toggle id="t" label="Enable" checked readOnly />);
    const sw = screen.getByRole("switch", { name: "Enable" });
    expect(sw).toBeChecked();
    expect(screen.getByText("Enable")).toBeInTheDocument();
  });

  it("is unchecked when checked is false", () => {
    render(<Toggle id="t" aria-label="Enable" checked={false} readOnly />);
    expect(screen.getByRole("switch", { name: "Enable" })).not.toBeChecked();
  });

  it("drives controlled state on click", async () => {
    const user = userEvent.setup();
    render(<Controlled />);
    const sw = screen.getByRole("switch", { name: "Enable" });
    expect(sw).not.toBeChecked();
    await user.click(sw);
    expect(sw).toBeChecked();
  });

  it("is reached with Tab and flipped with Space", async () => {
    const user = userEvent.setup();
    render(<Controlled />);
    const sw = screen.getByRole("switch", { name: "Enable" });
    await user.tab();
    expect(sw).toHaveFocus();
    await user.keyboard(" ");
    expect(sw).toBeChecked();
  });
});
