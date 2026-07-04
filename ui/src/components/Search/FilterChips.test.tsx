import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { FilterChips, type FilterField } from "./FilterChips";

const FIELDS: FilterField[] = [
  { key: "path", label: "Path" },
  { key: "hash", label: "SHA256" },
  {
    key: "signing",
    label: "Signing",
    options: [
      { value: "unsigned", label: "Unsigned" },
      { value: "platform", label: "Apple platform" },
    ],
  },
];

describe("FilterChips", () => {
  it("renders active filters as chips with the option label", () => {
    render(<FilterChips fields={FIELDS} active={{ path: "grep", signing: "unsigned" }} onChange={vi.fn()} />);
    expect(screen.getByText("Path: grep")).toBeInTheDocument();
    expect(screen.getByText("Signing: Unsigned")).toBeInTheDocument();
  });

  // spec:web-ui/fleet-wide-search-page/removing-a-chip-drops-that-filter
  it("removing a chip clears that field", () => {
    const onChange = vi.fn();
    render(<FilterChips fields={FIELDS} active={{ path: "grep" }} onChange={onChange} />);
    fireEvent.click(screen.getByRole("button", { name: "Remove Path filter" }));
    expect(onChange).toHaveBeenCalledWith("path", "");
  });

  it("adds a free-text filter", () => {
    const onChange = vi.fn();
    render(<FilterChips fields={FIELDS} active={{}} onChange={onChange} />);
    fireEvent.change(screen.getByLabelText("Add filter field"), { target: { value: "hash" } });
    fireEvent.change(screen.getByLabelText("SHA256 value"), { target: { value: "abc123" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(onChange).toHaveBeenCalledWith("hash", "abc123");
  });

  it("offers a dropdown for an option-backed field", () => {
    const onChange = vi.fn();
    render(<FilterChips fields={FIELDS} active={{}} onChange={onChange} />);
    fireEvent.change(screen.getByLabelText("Add filter field"), { target: { value: "signing" } });
    fireEvent.change(screen.getByLabelText("Signing value"), { target: { value: "platform" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(onChange).toHaveBeenCalledWith("signing", "platform");
  });
});
