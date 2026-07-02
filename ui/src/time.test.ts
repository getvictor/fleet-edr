import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { formatRelativeNs } from "./time";
import {
  MILLISECONDS_PER_DAY,
  MILLISECONDS_PER_HOUR,
  MILLISECONDS_PER_MINUTE,
  MILLISECONDS_PER_SECOND,
  NANOSECONDS_PER_MILLISECOND,
} from "./constants";

// Freeze the clock so formatRelativeNs (which reads Date.now internally) and the test's own "now" can never drift apart, and so a
// result never depends on the wall clock. The instant is arbitrary but fixed.
const FROZEN_NOW = new Date("2026-06-15T12:00:00Z").getTime();

// msAgoNs builds a nanosecond epoch timestamp `ms` milliseconds before the frozen now.
//
// Every offset below sits comfortably INSIDE its bucket (5m30s, not exactly 5m) on purpose. An epoch-ns value is ~1.75e18, well past
// Number.MAX_SAFE_INTEGER, so the *1e6 then /1e6 round-trip inside formatRelativeNs carries sub-nanosecond error. An offset landing
// exactly on a bucket boundary (300000 ms is exactly 5.0 minutes) can be nudged a hair under it and floor to 4, which was a real
// ~1-in-8 CI flake ("expected '4m ago' to be '5m ago'"). Mid-bucket offsets are immune, and real last-seen timestamps are never
// boundary-exact to the nanosecond, so the hazard only ever existed for a boundary-exact synthetic input.
const msAgoNs = (ms: number): number => (Date.now() - ms) * NANOSECONDS_PER_MILLISECOND;

describe("formatRelativeNs", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FROZEN_NOW);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns 'never' for a zero timestamp", () => {
    expect(formatRelativeNs(0)).toBe("never");
  });

  it("returns 'just now' for a sub-minute age", () => {
    expect(formatRelativeNs(msAgoNs(5 * MILLISECONDS_PER_SECOND))).toBe("just now");
  });

  it("formats minutes", () => {
    expect(formatRelativeNs(msAgoNs(5 * MILLISECONDS_PER_MINUTE + 30 * MILLISECONDS_PER_SECOND))).toBe("5m ago");
  });

  it("formats hours", () => {
    expect(formatRelativeNs(msAgoNs(3 * MILLISECONDS_PER_HOUR + 30 * MILLISECONDS_PER_MINUTE))).toBe("3h ago");
  });

  it("formats days", () => {
    expect(formatRelativeNs(msAgoNs(2 * MILLISECONDS_PER_DAY + 12 * MILLISECONDS_PER_HOUR))).toBe("2d ago");
  });
});
