import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { useRef } from "react";

import { useIsTruncated } from "./useIsTruncated";

// jsdom lays nothing out, so scrollWidth and clientWidth are both 0 on every element. Each case therefore states the geometry it is
// about by defining those two properties on the node, which is the only thing the hook reads.
function Probe({ scrollWidth, clientWidth }: { readonly scrollWidth: number; readonly clientWidth: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const truncated = useIsTruncated(ref);
  return (
    <span
      ref={(node) => {
        if (node) {
          Object.defineProperty(node, "scrollWidth", { value: scrollWidth, configurable: true });
          Object.defineProperty(node, "clientWidth", { value: clientWidth, configurable: true });
        }
        ref.current = node;
      }}
      data-testid="probe"
    >
      {truncated ? "clipped" : "whole"}
    </span>
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useIsTruncated", () => {
  it("reports clipping when the content is wider than its box", () => {
    render(<Probe scrollWidth={400} clientWidth={200} />);
    expect(screen.getByTestId("probe")).toHaveTextContent("clipped");
  });

  it("reports nothing to reveal when the content fits", () => {
    render(<Probe scrollWidth={180} clientWidth={200} />);
    expect(screen.getByTestId("probe")).toHaveTextContent("whole");
  });

  // Content exactly as wide as its box shows in full. Off by one the other way and every cell claims to be clipped, which puts a
  // tooltip on values that are entirely on screen.
  it("treats content exactly as wide as its box as whole", () => {
    render(<Probe scrollWidth={200} clientWidth={200} />);
    expect(screen.getByTestId("probe")).toHaveTextContent("whole");
  });

  // Without ResizeObserver the first measurement has to stand rather than the hook throwing on construction, because that would
  // take the whole table down on a browser that lacks it.
  it("still answers from the first measurement where ResizeObserver is absent", () => {
    vi.stubGlobal("ResizeObserver", undefined);
    render(<Probe scrollWidth={400} clientWidth={200} />);
    expect(screen.getByTestId("probe")).toHaveTextContent("clipped");
  });
});
