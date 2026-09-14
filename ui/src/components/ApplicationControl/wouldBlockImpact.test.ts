import { describe, it, expect } from "vitest";
import { appControlRuleID, describeWouldBlock, wouldBlockImpactFrom } from "./wouldBlockImpact";

const row = (rule_id: string, matches: number, hosts: number) => ({ rule_id, matches, hosts, last_seen: "2026-09-14T00:00:00Z" });

describe("wouldBlockImpact", () => {
  it("keeps only application-control rules and describes each rule's count", () => {
    const impact = wouldBlockImpactFrom([row("app_control:7", 12, 3), row("app_control:8", 1, 1), row("dns_c2_beacon", 99, 9)], 7);
    expect([...impact.byRule.keys()]).toEqual(["app_control:7", "app_control:8"]);
    expect(describeWouldBlock(impact, 7)).toBe("Would have blocked 12 runs on 3 hosts in 7 days");
    expect(describeWouldBlock(impact, 8)).toBe("Would have blocked 1 run on 1 host in 7 days");
  });

  it("says a rule with no counted matches matched nothing, in the window the server reported", () => {
    expect(describeWouldBlock(wouldBlockImpactFrom([], 1), 9)).toBe("No would-block matches in 1 day");
  });

  it("names rules the way their records do", () => {
    expect(appControlRuleID(42)).toBe("app_control:42");
  });
});
