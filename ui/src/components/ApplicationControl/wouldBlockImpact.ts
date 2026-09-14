import { APP_CONTROL_RULE_PREFIX, type RuleMatchCount } from "../../api";

// WouldBlockImpact is what the server counted for each application-control rule's would-block matches, over the window it reports.
// The counts come from the monitor-match counter, which keys a DETECT rule's matches under its `app_control:<id>` rule id.
export interface WouldBlockImpact {
  readonly days: number;
  readonly byRule: ReadonlyMap<string, RuleMatchCount>;
}

// wouldBlockImpactFrom indexes the match counts by rule id, keeping only application-control rules.
export function wouldBlockImpactFrom(counts: readonly RuleMatchCount[], days: number): WouldBlockImpact {
  const byRule = new Map<string, RuleMatchCount>();
  for (const row of counts) {
    if (row.rule_id.startsWith(APP_CONTROL_RULE_PREFIX)) byRule.set(row.rule_id, row);
  }
  return { days, byRule };
}

// appControlRuleID is the rule id an application-control rule's alerts, monitor records and match counts carry.
export function appControlRuleID(ruleID: number): string {
  return `${APP_CONTROL_RULE_PREFIX}${String(ruleID)}`;
}

function plural(n: number, word: string): string {
  return `${String(n)} ${word}${n === 1 ? "" : "s"}`;
}

// describeWouldBlock says what a DETECT rule would have blocked in the counted window, for the rules table and the promote dialog.
// A rule absent from the counts matched nothing that was counted, which is stated rather than left blank so an operator does not
// read a quiet rule as missing data.
export function describeWouldBlock(impact: WouldBlockImpact, ruleID: number): string {
  const row = impact.byRule.get(appControlRuleID(ruleID));
  const window = plural(impact.days, "day");
  if (!row) return `No would-block matches in ${window}`;
  return `Would have blocked ${plural(row.matches, "run")} on ${plural(row.hosts, "host")} in ${window}`;
}
