import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { HealthBadge } from "./HealthBadge";

describe("HealthBadge", () => {
  it("maps unhealthy to a critical 'needs attention' badge", () => {
    render(<HealthBadge status="unhealthy" />);
    expect(screen.getByText("needs attention")).toHaveClass("badge--critical");
  });

  it("maps healthy to a success badge", () => {
    render(<HealthBadge status="healthy" />);
    expect(screen.getByText("healthy")).toHaveClass("badge--success");
  });

  it("maps degraded to a medium badge", () => {
    render(<HealthBadge status="degraded" />);
    expect(screen.getByText("degraded")).toHaveClass("badge--medium");
  });

  it("maps unknown to a neutral badge", () => {
    render(<HealthBadge status="unknown" />);
    expect(screen.getByText("unknown")).toHaveClass("badge--neutral");
  });

  it("falls back to a neutral badge showing the raw value for an unrecognized status", () => {
    render(<HealthBadge status="brand_new_state" />);
    expect(screen.getByText("brand_new_state")).toHaveClass("badge--neutral");
  });
});
