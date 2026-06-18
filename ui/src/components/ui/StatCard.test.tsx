import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatCard, SummaryStrip } from "./StatCard";

describe("StatCard", () => {
  it("renders the value and label", () => {
    render(<StatCard value={42} label="Online" />);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("Online")).toBeInTheDocument();
  });

  it("defaults to the neutral accent when none is given", () => {
    const { container } = render(<StatCard value={0} label="Total" />);
    expect(container.querySelector(".stat-card")).toHaveClass("stat-card--neutral");
  });

  it.each(["green", "red", "neutral"] as const)(
    "maps the %s accent to its modifier class",
    (accent) => {
      const { container } = render(<StatCard value={1} label="x" accent={accent} />);
      expect(container.querySelector(".stat-card")).toHaveClass(`stat-card--${accent}`);
    },
  );

  it("wraps children in a summary strip", () => {
    const { container } = render(
      <SummaryStrip>
        <StatCard value={1} label="a" />
        <StatCard value={2} label="b" />
      </SummaryStrip>,
    );
    const strip = container.querySelector(".summary-strip");
    expect(strip).toBeInTheDocument();
    expect(strip?.querySelectorAll(".stat-card")).toHaveLength(2);
  });
});
