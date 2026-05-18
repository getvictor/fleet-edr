import { describe, it, expect } from "vitest";
import {
  HINT_BINARY_COULD_BE_CERTIFICATE,
  inferRuleType,
  parsePasteInput,
} from "./pasteInference";

// pasteInference is the per-line shape-detection the PasteManyModal renders. Tests pin the shape regexes the spec calls out
// (web-ui spec.md, Requirement: Paste-many flow infers rule type by identifier shape) so a future regex tweak that drifts from
// the server-side validators fails here rather than at first paste against a real server.

describe("inferRuleType", () => {
  it("infers CDHASH for 40 lowercase hex characters", () => {
    expect(inferRuleType("a".repeat(40))).toEqual({ ruleType: "CDHASH" });
  });

  it("infers BINARY with a CERTIFICATE hint for 64 lowercase hex characters", () => {
    expect(inferRuleType("0".repeat(64))).toEqual({
      ruleType: "BINARY",
      hint: HINT_BINARY_COULD_BE_CERTIFICATE,
    });
  });

  it("infers TEAMID for exactly 10 uppercase alphanumeric characters", () => {
    expect(inferRuleType("EQHXZ8M8AV")).toEqual({ ruleType: "TEAMID" });
  });

  it("infers SIGNINGID for <TeamID>:<bundle.id>", () => {
    expect(inferRuleType("EQHXZ8M8AV:com.google.Chrome")).toEqual({ ruleType: "SIGNINGID" });
  });

  it("infers SIGNINGID for platform:<bundle.id>", () => {
    expect(inferRuleType("platform:com.apple.curl")).toEqual({ ruleType: "SIGNINGID" });
  });

  it("infers PATH for absolute paths", () => {
    expect(inferRuleType("/Applications/Mail.app/Contents/MacOS/Mail")).toEqual({ ruleType: "PATH" });
  });

  it("returns ruleType=null when no shape matches", () => {
    expect(inferRuleType("not a shape")).toEqual({ ruleType: null });
  });

  it("rejects uppercase hex characters for BINARY (server validator is strict on case)", () => {
    expect(inferRuleType("A".repeat(64))).toEqual({ ruleType: null });
  });

  it("rejects an 11-character TEAMID-shaped value", () => {
    expect(inferRuleType("EQHXZ8M8AV1")).toEqual({ ruleType: null });
  });

  it("rejects lowercase TEAMID (server-side validator requires uppercase)", () => {
    expect(inferRuleType("eqhxz8m8av")).toEqual({ ruleType: null });
  });
});

describe("parsePasteInput", () => {
  it("returns the spec's mixed-identifiers shape inferences in order", () => {
    const input = [
      "a".repeat(40),
      "b".repeat(64),
      "EQHXZ8M8AV",
      "/Applications/Mail.app/Contents/MacOS/Mail",
    ].join("\n");
    const result = parsePasteInput(input);
    expect(result.map((r) => r.ruleType)).toEqual(["CDHASH", "BINARY", "TEAMID", "PATH"]);
    expect(result[1].hint).toBe(HINT_BINARY_COULD_BE_CERTIFICATE);
  });

  it("strips blank lines including trailing whitespace-only lines", () => {
    const input = "\nEQHXZ8M8AV\n   \n\n";
    expect(parsePasteInput(input).map((r) => r.identifier)).toEqual(["EQHXZ8M8AV"]);
  });

  it("trims each identifier so a trailing space doesn't fall through to ruleType=null", () => {
    const input = "  EQHXZ8M8AV  \n";
    const result = parsePasteInput(input);
    expect(result).toHaveLength(1);
    expect(result[0].identifier).toBe("EQHXZ8M8AV");
    expect(result[0].ruleType).toBe("TEAMID");
  });

  it("handles CRLF line endings (Windows-pasted spreadsheets)", () => {
    const input = "EQHXZ8M8AV\r\nplatform:com.apple.curl\r\n";
    const result = parsePasteInput(input);
    expect(result.map((r) => r.identifier)).toEqual([
      "EQHXZ8M8AV",
      "platform:com.apple.curl",
    ]);
  });

  it("preserves the raw line so the modal can show the operator the original input", () => {
    const result = parsePasteInput("  EQHXZ8M8AV  ");
    expect(result[0].raw).toBe("  EQHXZ8M8AV  ");
    expect(result[0].identifier).toBe("EQHXZ8M8AV");
  });
});
