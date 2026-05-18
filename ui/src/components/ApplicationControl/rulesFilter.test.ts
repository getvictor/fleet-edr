import { describe, it, expect } from "vitest";
import {
  applyRulesFilter,
  distinctRuleTypes,
  distinctSources,
  EMPTY_RULES_FILTER,
  filterIsActive,
  type RulesFilter,
} from "./rulesFilter";
import type { ApplicationControlRule } from "../../types";

// Pin the filter contract the spec requires: the four dimensions (rule_type, enabled, source, free-text over identifier and
// comment) act independently and intersect via logical AND. distinctRuleTypes orders by the canonical UI order; distinctSources
// is alphabetical.

const makeRule = (over: Partial<ApplicationControlRule>): ApplicationControlRule => ({
  id: 1,
  policy_id: 1,
  rule_type: "BINARY",
  identifier: "a".repeat(64),
  action: "BLOCK",
  enforcement: "PROTECT",
  enabled: true,
  severity: "medium",
  source: "admin",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "user:1",
  ...over,
});

const rules: ApplicationControlRule[] = [
  makeRule({ id: 1, rule_type: "BINARY",    identifier: "a".repeat(64), source: "admin",  enabled: true,  comment: "blocked by IT" }),
  makeRule({ id: 2, rule_type: "CDHASH",    identifier: "b".repeat(40), source: "import", enabled: false, comment: "legacy entry" }),
  makeRule({ id: 3, rule_type: "TEAMID",    identifier: "EQHXZ8M8AV",   source: "admin",  enabled: true,  comment: "" }),
  makeRule({ id: 4, rule_type: "SIGNINGID", identifier: "platform:com.apple.curl", source: "import", enabled: true }),
  makeRule({ id: 5, rule_type: "BINARY",    identifier: "c".repeat(64), source: "api",    enabled: false, comment: "rolled back" }),
];

describe("applyRulesFilter", () => {
  it("returns every rule when the filter is empty (EMPTY_RULES_FILTER)", () => {
    expect(applyRulesFilter(rules, EMPTY_RULES_FILTER)).toHaveLength(rules.length);
  });

  it("filters by exact rule_type", () => {
    const filter: RulesFilter = { ...EMPTY_RULES_FILTER, ruleType: "BINARY" };
    expect(applyRulesFilter(rules, filter).map((r) => r.id)).toEqual([1, 5]);
  });

  it("filters enabled-only and disabled-only via the tri-state", () => {
    expect(applyRulesFilter(rules, { ...EMPTY_RULES_FILTER, enabled: "enabled" }).map((r) => r.id)).toEqual([1, 3, 4]);
    expect(applyRulesFilter(rules, { ...EMPTY_RULES_FILTER, enabled: "disabled" }).map((r) => r.id)).toEqual([2, 5]);
  });

  it("filters by exact source", () => {
    expect(applyRulesFilter(rules, { ...EMPTY_RULES_FILTER, source: "import" }).map((r) => r.id)).toEqual([2, 4]);
  });

  it("free-text search matches identifier substrings case-insensitively", () => {
    expect(applyRulesFilter(rules, { ...EMPTY_RULES_FILTER, search: "PLATFORM" }).map((r) => r.id)).toEqual([4]);
  });

  it("free-text search also matches comment substrings", () => {
    expect(applyRulesFilter(rules, { ...EMPTY_RULES_FILTER, search: "legacy" }).map((r) => r.id)).toEqual([2]);
  });

  it("free-text search treats whitespace-only as empty", () => {
    expect(applyRulesFilter(rules, { ...EMPTY_RULES_FILTER, search: "   " })).toHaveLength(rules.length);
  });

  it("intersects dimensions: BINARY + enabled returns only rules satisfying both", () => {
    const filter: RulesFilter = { ...EMPTY_RULES_FILTER, ruleType: "BINARY", enabled: "enabled" };
    expect(applyRulesFilter(rules, filter).map((r) => r.id)).toEqual([1]);
  });

  it("returns empty array when no rule passes every dimension", () => {
    const filter: RulesFilter = { ...EMPTY_RULES_FILTER, ruleType: "TEAMID", source: "api" };
    expect(applyRulesFilter(rules, filter)).toEqual([]);
  });

  it("handles rules without a comment when free-text search is set (comment is optional)", () => {
    // rule 3 has comment = "", rule 4 has no comment field at all. search "EQHX" matches identifier of rule 3 only.
    expect(applyRulesFilter(rules, { ...EMPTY_RULES_FILTER, search: "EQHX" }).map((r) => r.id)).toEqual([3]);
  });
});

describe("filterIsActive", () => {
  it("returns false for EMPTY_RULES_FILTER", () => {
    expect(filterIsActive(EMPTY_RULES_FILTER)).toBe(false);
  });

  it("returns true when ANY dimension is constraining", () => {
    expect(filterIsActive({ ...EMPTY_RULES_FILTER, ruleType: "BINARY" })).toBe(true);
    expect(filterIsActive({ ...EMPTY_RULES_FILTER, enabled: "disabled" })).toBe(true);
    expect(filterIsActive({ ...EMPTY_RULES_FILTER, source: "admin" })).toBe(true);
    expect(filterIsActive({ ...EMPTY_RULES_FILTER, search: "foo" })).toBe(true);
  });

  it("treats whitespace-only search as inactive (matches applyRulesFilter)", () => {
    expect(filterIsActive({ ...EMPTY_RULES_FILTER, search: "   " })).toBe(false);
  });
});

describe("distinctRuleTypes", () => {
  it("returns unique types in canonical UI order (BINARY, CDHASH, SIGNINGID, TEAMID, ...)", () => {
    expect(distinctRuleTypes(rules)).toEqual(["BINARY", "CDHASH", "SIGNINGID", "TEAMID"]);
  });

  it("returns an empty array for an empty rule list", () => {
    expect(distinctRuleTypes([])).toEqual([]);
  });
});

describe("distinctSources", () => {
  it("returns unique sources alphabetically", () => {
    expect(distinctSources(rules)).toEqual(["admin", "api", "import"]);
  });

  it("skips empty source values so they don't pollute the dropdown", () => {
    const withEmpty = [...rules, makeRule({ id: 99, source: "" })];
    expect(distinctSources(withEmpty)).toEqual(["admin", "api", "import"]);
  });
});
