import { describe, it, expect } from "vitest";
import { severityBadgeVariant } from "./severity";

describe("severityBadgeVariant", () => {
  it("maps each known severity to its own badge", () => {
    expect(["critical", "high", "medium", "low"].map(severityBadgeVariant)).toEqual(["critical", "high", "medium", "low"]);
  });

  // The mapping it replaced was an object literal, where a lookup resolves inherited keys: "constructor" came back as a function,
  // not a variant. Anything unrecognised has to fall back to neutral instead.
  it("renders an unrecognised or inherited-key severity as neutral", () => {
    expect(severityBadgeVariant("")).toBe("neutral");
    expect(severityBadgeVariant("informational")).toBe("neutral");
    expect(severityBadgeVariant("constructor")).toBe("neutral");
    expect(severityBadgeVariant("__proto__")).toBe("neutral");
  });
});
