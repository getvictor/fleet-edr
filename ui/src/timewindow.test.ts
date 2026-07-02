import { describe, it, expect } from "vitest";

import { windowBounds, windowLabel, shiftWindow, RELATIVE_PRESETS, type TimeWindow } from "./timewindow";

const NS = 1_000_000;
const HOUR_MS = 3_600_000;
const NOW_MS = 1_700_000_000_000;

describe("windowBounds", () => {
  const cases: { name: string; window: TimeWindow; from: number; to: number }[] = [
    {
      name: "relative window ends at now",
      window: { kind: "relative", ms: HOUR_MS },
      from: (NOW_MS - HOUR_MS) * NS,
      to: NOW_MS * NS,
    },
    {
      name: "anchored relative window ends at its anchor",
      window: { kind: "relative", ms: HOUR_MS, anchorNs: 500 * NS },
      from: 500 * NS - HOUR_MS * NS,
      to: 500 * NS,
    },
    {
      name: "absolute window passes through",
      window: { kind: "absolute", fromNs: 100, toNs: 200 },
      from: 100,
      to: 200,
    },
  ];
  it.each(cases)("$name", ({ window, from, to }) => {
    expect(windowBounds(window, NOW_MS)).toEqual({ fromNs: from, toNs: to });
  });
});

describe("windowLabel", () => {
  it("names presets for un-anchored relative windows", () => {
    for (const preset of RELATIVE_PRESETS) {
      expect(windowLabel({ kind: "relative", ms: preset.ms })).toBe(preset.label);
    }
  });

  it("falls back to minutes for a non-preset relative width", () => {
    expect(windowLabel({ kind: "relative", ms: 5 * 60_000 })).toBe("Last 5 min");
  });

  it("renders anchored and absolute windows as a span", () => {
    const anchored = windowLabel({ kind: "relative", ms: HOUR_MS, anchorNs: NOW_MS * NS });
    const absolute = windowLabel({ kind: "absolute", fromNs: (NOW_MS - HOUR_MS) * NS, toNs: NOW_MS * NS });
    expect(anchored).toContain(" to ");
    expect(anchored).toBe(absolute);
  });
});

// spec:web-ui/host-page-time-navigation/shift-arrows-move-the-window-by-its-width
describe("shiftWindow", () => {
  it("moves a relative window back by its width as an absolute span", () => {
    const shifted = shiftWindow({ kind: "relative", ms: HOUR_MS }, -1, NOW_MS);
    expect(shifted).toEqual({
      kind: "absolute",
      fromNs: (NOW_MS - 2 * HOUR_MS) * NS,
      toNs: (NOW_MS - HOUR_MS) * NS,
    });
  });

  it("shifting forward then back round-trips an absolute window", () => {
    const start: TimeWindow = { kind: "absolute", fromNs: 1_000 * NS, toNs: 2_000 * NS };
    expect(shiftWindow(shiftWindow(start, 1, NOW_MS), -1, NOW_MS)).toEqual(start);
  });
});
