import { describe, it, expect } from "vitest";
import { formatPlatform } from "./platform";

describe("formatPlatform", () => {
  it("maps known platforms to display labels and falls back for empty or unknown", () => {
    expect(formatPlatform("darwin")).toBe("macOS");
    expect(formatPlatform("windows")).toBe("Windows");
    expect(formatPlatform("linux")).toBe("Linux");
    expect(formatPlatform("")).toBe("unknown");
    expect(formatPlatform("beos")).toBe("beos");
  });
});
