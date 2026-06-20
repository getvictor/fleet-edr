import { describe, it, expect } from "vitest";
import { useState } from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { Toggle } from "./Toggle";

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

  it("drives controlled state on change", () => {
    function Controlled() {
      const [on, setOn] = useState(false);
      return <Toggle id="t" aria-label="Enable" checked={on} onChange={(e) => { setOn(e.target.checked); }} />;
    }
    render(<Controlled />);
    const sw = screen.getByRole("switch", { name: "Enable" });
    expect(sw).not.toBeChecked();
    fireEvent.click(sw);
    expect(sw).toBeChecked();
  });
});
