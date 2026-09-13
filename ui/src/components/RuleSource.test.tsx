import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { RuleSource } from "./RuleSource";
import * as api from "../api";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("RuleSource", () => {
  // spec:web-ui/the-rule-catalogue-is-browsable/an-operator-reads-a-rule-as-written
  it("shows the rule document whose file stem is the rule, as written", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([
      { path: "imported/other_rule.yml", bytes: 10 },
      { path: "authored/keychain_extra.yml", bytes: 42 },
    ]);
    const content = "title: Keychain extra\nx-engine:\n  mode: monitor\n";
    const get = vi.spyOn(api, "getRuleContentDocument").mockResolvedValue(content);
    const { container } = render(<RuleSource ruleId="keychain_extra" />);

    expect(await screen.findByText("authored/keychain_extra.yml")).toBeVisible();
    expect(get).toHaveBeenCalledWith("authored/keychain_extra.yml");
    // Verbatim, whitespace included: indentation is structure in YAML.
    expect(container.querySelector("pre")?.textContent).toBe(content);
  });

  it("says a built-in rule has no document instead of showing an empty panel", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "authored/keychain_extra.yml", bytes: 42 }]);
    const get = vi.spyOn(api, "getRuleContentDocument");
    render(<RuleSource ruleId="suspicious_exec" />);

    expect(await screen.findByText(/built into the server/)).toBeVisible();
    expect(get).not.toHaveBeenCalled();
  });

  it("reports a failed read", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockRejectedValue(new Error("API error: 500"));
    render(<RuleSource ruleId="suspicious_exec" />);

    expect(await screen.findByText(/could not be loaded: API error: 500/)).toBeVisible();
    expect(screen.queryByText(/built into the server/)).toBeNull();
  });
});
