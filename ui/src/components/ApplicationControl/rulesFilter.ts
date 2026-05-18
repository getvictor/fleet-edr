import type { ApplicationControlRule } from "../../types";

// Filter dimensions for the policy-detail rules table. Mirrors the web-ui spec's "filtered by rule_type, enabled, source, and
// free-text search over identifier and comment". Each dimension is independent: the empty / "all" value for a dimension means
// it doesn't constrain. A rule passes the filter iff every dimension's predicate accepts it (logical AND across dimensions).
export interface RulesFilter {
  // search is matched as a case-insensitive substring against the identifier AND the comment. An empty string disables the
  // search dimension entirely (every rule passes); a non-empty string passes a rule iff it appears in either field.
  readonly search: string;
  // ruleType matches the rule's rule_type EXACTLY. The empty string means "any type"; otherwise the rule must equal this
  // value (BINARY / CDHASH / SIGNINGID / TEAMID / CERTIFICATE / PATH).
  readonly ruleType: string;
  // enabled is a tri-state: "all" disables the dimension; "enabled" / "disabled" require the corresponding boolean.
  readonly enabled: "all" | "enabled" | "disabled";
  // source matches the rule's source string EXACTLY (admin / import / api / system, etc). The set of available sources is
  // derived from the policy's actual rules at render time so the dropdown adapts to whatever the deployment surfaces.
  readonly source: string;
}

export const EMPTY_RULES_FILTER: RulesFilter = {
  search: "",
  ruleType: "",
  enabled: "all",
  source: "",
};

// filterIsActive returns true when at least one dimension is constraining the result set. The PolicyDetail page uses this to
// decide whether to render the "Clear filters" link + the X-of-Y counter (both noisy when no filter is applied).
export function filterIsActive(filter: RulesFilter): boolean {
  return filter.search.trim() !== ""
    || filter.ruleType !== ""
    || filter.enabled !== "all"
    || filter.source !== "";
}

// applyRulesFilter walks the rule list once and returns the subset that passes every dimension. Pure + memoizable: the
// PolicyDetail caller wraps this in useMemo keyed on (rules, filter).
export function applyRulesFilter(
  rules: readonly ApplicationControlRule[],
  filter: RulesFilter,
): ApplicationControlRule[] {
  const needle = filter.search.trim().toLowerCase();
  return rules.filter((rule) => {
    if (filter.ruleType !== "" && rule.rule_type !== filter.ruleType) return false;
    if (filter.enabled === "enabled" && !rule.enabled) return false;
    if (filter.enabled === "disabled" && rule.enabled) return false;
    if (filter.source !== "" && rule.source !== filter.source) return false;
    if (needle !== "") {
      const identifier = rule.identifier.toLowerCase();
      const comment = (rule.comment ?? "").toLowerCase();
      if (!identifier.includes(needle) && !comment.includes(needle)) return false;
    }
    return true;
  });
}

// distinctSources returns the unique source strings present in the policy's rules, sorted alphabetically. The Source select
// in PolicyDetail builds its option list from this so the dropdown adapts to whatever values exist instead of hard-coding the
// admin/import/api/system enumeration (which would drift if the server adds a value).
export function distinctSources(rules: readonly ApplicationControlRule[]): string[] {
  const set = new Set<string>();
  for (const r of rules) {
    if (r.source && r.source.length > 0) set.add(r.source);
  }
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}

// RULE_TYPE_ORDER_KEYS is the canonical UI order the modals + dropdowns render rule types in (BINARY first since SHA-256
// is the most-pasted shape). distinctRuleTypes' Map below derives its values from the array index so each ordinal is
// self-documenting and the eslint no-magic-numbers rule doesn't trip on per-entry sort keys.
const RULE_TYPE_ORDER_KEYS = ["BINARY", "CDHASH", "SIGNINGID", "TEAMID", "CERTIFICATE", "PATH"] as const;
const RULE_TYPE_ORDER = new Map<string, number>(RULE_TYPE_ORDER_KEYS.map((k, i) => [k, i]));

// RULE_TYPE_ORDER_TRAILING is the fallback sort key for any rule_type not enumerated above (defense-in-depth for a future
// server addition the UI hasn't been taught yet). Sorts unknown values after every known type, then alphabetically.
const RULE_TYPE_ORDER_TRAILING = Number.MAX_SAFE_INTEGER;

export function distinctRuleTypes(rules: readonly ApplicationControlRule[]): string[] {
  const set = new Set<string>();
  for (const r of rules) set.add(r.rule_type);
  return Array.from(set).sort((a, b) => {
    const oa = RULE_TYPE_ORDER.get(a) ?? RULE_TYPE_ORDER_TRAILING;
    const ob = RULE_TYPE_ORDER.get(b) ?? RULE_TYPE_ORDER_TRAILING;
    if (oa !== ob) return oa - ob;
    return a.localeCompare(b);
  });
}
