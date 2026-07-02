import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { TimeRangeControl } from "./TimeRangeControl";
import type { TimeWindow } from "../timewindow";

const NS = 1_000_000;
const HOUR_MS = 3_600_000;
const NOW = new Date("2026-07-02T12:00:00Z");

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
});

function renderControl(window: TimeWindow) {
  const onChange = vi.fn();
  render(<TimeRangeControl window={window} onChange={onChange} />);
  return onChange;
}

describe("TimeRangeControl", () => {
  // spec:web-ui/host-page-time-navigation/one-control-at-rest-with-relative-and-absolute-selection
  it("labels the active relative window and applies a quick-pick", () => {
    const onChange = renderControl({ kind: "relative", ms: HOUR_MS });
    const label = screen.getByRole("button", { name: "Last 1 hour" });
    fireEvent.click(label);
    fireEvent.click(screen.getByRole("button", { name: "Last 7 days" }));
    expect(onChange).toHaveBeenCalledWith({ kind: "relative", ms: 7 * 24 * HOUR_MS });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("applies an absolute from/to selection", () => {
    const onChange = renderControl({ kind: "relative", ms: HOUR_MS });
    fireEvent.click(screen.getByRole("button", { name: "Last 1 hour" }));
    const dialog = screen.getByRole("dialog", { name: "Select time range" });
    const [fromInput, toInput] = dialog.querySelectorAll("input");
    fireEvent.change(fromInput, { target: { value: "2026-07-01T09:00" } });
    fireEvent.change(toInput, { target: { value: "2026-07-01T11:30" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    expect(onChange).toHaveBeenCalledTimes(1);
    const next = onChange.mock.calls[0][0] as TimeWindow;
    expect(next.kind).toBe("absolute");
    if (next.kind === "absolute") {
      expect(next.fromNs).toBe(new Date("2026-07-01T09:00").getTime() * NS);
      expect(next.toNs).toBe(new Date("2026-07-01T11:30").getTime() * NS);
    }
  });

  it("rejects an inverted absolute selection", () => {
    const onChange = renderControl({ kind: "relative", ms: HOUR_MS });
    fireEvent.click(screen.getByRole("button", { name: "Last 1 hour" }));
    const dialog = screen.getByRole("dialog", { name: "Select time range" });
    const [fromInput, toInput] = dialog.querySelectorAll("input");
    fireEvent.change(fromInput, { target: { value: "2026-07-01T11:30" } });
    fireEvent.change(toInput, { target: { value: "2026-07-01T09:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onChange).not.toHaveBeenCalled();
  });

  // spec:web-ui/host-page-time-navigation/shift-arrows-move-the-window-by-its-width
  it("shifts the window back by its width as an absolute span", () => {
    const onChange = renderControl({ kind: "relative", ms: HOUR_MS });
    fireEvent.click(screen.getByRole("button", { name: "Shift time window back" }));
    expect(onChange).toHaveBeenCalledWith({
      kind: "absolute",
      fromNs: (NOW.getTime() - 2 * HOUR_MS) * NS,
      toNs: (NOW.getTime() - HOUR_MS) * NS,
    });
  });
});
