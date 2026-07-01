import { describe, it, expect } from "vitest";
import { formatRelativeNs } from "./time";
import { NANOSECONDS_PER_MILLISECOND } from "./constants";

const msAgoNs = (ms: number) => (Date.now() - ms) * NANOSECONDS_PER_MILLISECOND;

describe("formatRelativeNs", () => {
  it("returns 'never' for a zero timestamp", () => {
    expect(formatRelativeNs(0)).toBe("never");
  });

  it("returns 'just now' for a sub-minute age", () => {
    expect(formatRelativeNs(msAgoNs(5_000))).toBe("just now");
  });

  it("formats minutes", () => {
    expect(formatRelativeNs(msAgoNs(5 * 60 * 1000))).toBe("5m ago");
  });

  it("formats hours", () => {
    expect(formatRelativeNs(msAgoNs(3 * 60 * 60 * 1000))).toBe("3h ago");
  });

  it("formats days", () => {
    expect(formatRelativeNs(msAgoNs(2 * 24 * 60 * 60 * 1000))).toBe("2d ago");
  });
});
