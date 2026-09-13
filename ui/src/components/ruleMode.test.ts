import { describe, it, expect } from "vitest";
import { ruleModeLabel } from "./ruleMode";

describe("ruleModeLabel", () => {
  it("names each known mode", () => {
    expect(["alert", "monitor", "disabled"].map(ruleModeLabel)).toEqual(["Alert", "Monitor", "Disabled"]);
  });

  it("renders an unknown or inherited-key mode as sent", () => {
    expect(ruleModeLabel("quarantine")).toBe("quarantine");
    expect(ruleModeLabel("constructor")).toBe("constructor");
  });
});
