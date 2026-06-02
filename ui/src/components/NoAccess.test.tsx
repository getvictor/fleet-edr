import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { NoAccess } from "./NoAccess";

describe("NoAccess", () => {
  it("renders a generic no-access message with no surface", () => {
    render(<NoAccess />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.getByText(/don't have access/i)).toBeInTheDocument();
    expect(screen.getByText(/this page/i)).toBeInTheDocument();
  });

  it("names the surface when provided", () => {
    render(<NoAccess surface="Application control" />);
    expect(screen.getByText(/Application control/)).toBeInTheDocument();
  });

  it("never leaks a raw transport error", () => {
    render(<NoAccess surface="Application control" />);
    expect(screen.queryByText(/API error/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/403/)).not.toBeInTheDocument();
  });
});
