import { describe, it, expect } from "vitest";

import { CS_ADHOC, deriveSigningVerdict, isEvidenceMarked } from "./signing";
import type { CodeSigning } from "./types";

function cs(overrides: Partial<CodeSigning>): CodeSigning {
  return { team_id: "", signing_id: "", flags: 0, is_platform_binary: false, ...overrides };
}

// spec:web-ui/process-detail-content/verdict-distinguishes-the-signer-categories
describe("deriveSigningVerdict", () => {
  const cases: { name: string; input: CodeSigning | undefined; kind: string; label: string }[] = [
    { name: "no code-signing block is unsigned", input: undefined, kind: "unsigned", label: "unsigned" },
    {
      name: "ad-hoc flag wins even with identifiers present",
      input: cs({ signing_id: "local-build", team_id: "FDG8Q7N4CC", flags: CS_ADHOC | 0x100 }),
      kind: "ad-hoc",
      label: "ad-hoc signature",
    },
    {
      name: "team id means Developer ID",
      input: cs({ signing_id: "com.vendor.tool", team_id: "FDG8Q7N4CC" }),
      kind: "developer-id",
      label: "Developer ID (Team FDG8Q7N4CC)",
    },
    {
      // Team id is checked before the platform flag: ESF redaction on ad-hoc dev builds reports is_platform_binary=true for
      // everything (issue #187), while a team id is only present when the signature carries one.
      name: "team id outranks a claimed platform flag",
      input: cs({ signing_id: "com.vendor.tool", team_id: "FDG8Q7N4CC", is_platform_binary: true }),
      kind: "developer-id",
      label: "Developer ID (Team FDG8Q7N4CC)",
    },
    {
      name: "platform flag without a team id is Apple platform",
      input: cs({ signing_id: "com.apple.zsh", is_platform_binary: true }),
      kind: "platform",
      label: "Apple platform",
    },
    {
      name: "identity with no team, flag, or ad-hoc bit is the signed residual",
      input: cs({ signing_id: "com.vendor.legacy" }),
      kind: "signed",
      label: "signed",
    },
  ];
  it.each(cases)("$name", ({ input, kind, label }) => {
    const v = deriveSigningVerdict(input);
    expect(v.kind).toBe(kind);
    expect(v.label).toBe(label);
  });
});

describe("isEvidenceMarked", () => {
  it("marks unsigned and ad-hoc, nothing else", () => {
    expect(isEvidenceMarked(deriveSigningVerdict(undefined))).toBe(true);
    expect(isEvidenceMarked(deriveSigningVerdict(cs({ flags: CS_ADHOC })))).toBe(true);
    expect(isEvidenceMarked(deriveSigningVerdict(cs({ team_id: "T" })))).toBe(false);
    expect(isEvidenceMarked(deriveSigningVerdict(cs({ is_platform_binary: true })))).toBe(false);
    expect(isEvidenceMarked(deriveSigningVerdict(cs({ signing_id: "x" })))).toBe(false);
  });
});
