import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { formatElapsedNs, formatRelativeISO, formatRelativeNs } from "./time";
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

// formatRelativeISO exists so the detection-tuning match counts, whose API returns RFC 3339 rather than a nanosecond epoch, phrase
// recency exactly as the Hosts list does. These cases pin the delegation and the one thing it adds: a bad timestamp is empty, not
// "Invalid Date".
describe("formatRelativeISO", () => {
  // Same frozen clock as the block above, for the same reason, and the same MID-BUCKET discipline: an offset of exactly 2 days is
  // boundary-exact, and the *1e6 round-trip inside formatRelativeNs can nudge it a hair under and floor to "1d ago". That is the
  // documented ~1-in-8 flake at the top of this file, so these offsets sit well inside their buckets.
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FROZEN_NOW);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("phrases an ISO timestamp exactly as the nanosecond helper would", () => {
    const when = new Date(Date.now() - (2 * MILLISECONDS_PER_DAY + 7 * MILLISECONDS_PER_HOUR));
    expect(formatRelativeISO(when.toISOString())).toBe(formatRelativeNs(when.getTime() * NANOSECONDS_PER_MILLISECOND));
    expect(formatRelativeISO(when.toISOString())).toBe("2d ago");
  });

  it("uses the finer buckets the shared helper already has", () => {
    const when = new Date(Date.now() - (5 * MILLISECONDS_PER_MINUTE + 30 * MILLISECONDS_PER_SECOND));
    expect(formatRelativeISO(when.toISOString())).toBe("5m ago");
  });

  it("renders an unparseable timestamp as empty rather than Invalid Date", () => {
    expect(formatRelativeISO("not-a-date")).toBe("");
    expect(formatRelativeISO("")).toBe("");
  });
});

// formatElapsedNs takes a SPAN, not an epoch instant, so these values are small and exact: the MAX_SAFE_INTEGER rounding that forces the
// mid-bucket offsets above does not apply. Boundary cases are therefore asserted exactly, which is where a two-unit formatter goes wrong.
describe("formatElapsedNs", () => {
  const seconds = (n: number) => n * MILLISECONDS_PER_SECOND * NANOSECONDS_PER_MILLISECOND;
  const cases: { name: string; spanNs: number; want: string }[] = [
    { name: "an instantaneous episode", spanNs: 0, want: "0s" },
    { name: "a negative span, which the server never records", spanNs: -seconds(5), want: "0s" },
    { name: "under a minute", spanNs: seconds(36), want: "36s" },
    { name: "exactly a minute", spanNs: seconds(60), want: "1m" },
    { name: "minutes only, seconds dropped", spanNs: seconds(5 * 60 + 20), want: "5m" },
    { name: "exactly an hour, no zero minutes shown", spanNs: seconds(3600), want: "1h" },
    { name: "hours and minutes", spanNs: seconds(2 * 3600 + 14 * 60), want: "2h 14m" },
    { name: "exactly a day, no zero hours shown", spanNs: seconds(86_400), want: "1d" },
    // The motivating incident's 37.8 hours.
    { name: "the 37.8-hour providerless episode", spanNs: seconds(37.8 * 3600), want: "1d 13h" },
    // What subtracting two epoch-nanosecond instants actually produces: a few hundred nanoseconds short of the true span, because
    // both exceed Number.MAX_SAFE_INTEGER. Flooring rendered this exact 2h 14m as "2h 13m".
    { name: "a span a hair short of a whole minute boundary", spanNs: seconds(2 * 3600 + 14 * 60) - 256, want: "2h 14m" },
  ];
  for (const c of cases) {
    it(`renders ${c.name}`, () => {
      expect(formatElapsedNs(c.spanNs)).toBe(c.want);
    });
  }
});
