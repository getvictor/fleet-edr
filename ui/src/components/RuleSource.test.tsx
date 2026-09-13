import { describe, it, expect, vi, afterEach } from "vitest";
import { fireEvent, render as rtlRender, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";
import { RuleSource } from "./RuleSource";
import * as api from "../api";

// RuleSource navigates after a delete, so it renders inside a router.
function render(ui: ReactElement) {
  return rtlRender(<MemoryRouter>{ui}</MemoryRouter>);
}

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

  // spec:web-ui/rules-can-be-written-in-the-console/an-operator-deletes-a-rule-with-a-reason
  it("deletes the deployment's own rule with a reason", async () => {
    HTMLDialogElement.prototype.showModal = function showModal() { this.open = true; };
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "authored/keychain_extra.yml", bytes: 42 }]);
    vi.spyOn(api, "getRuleContentDocument").mockResolvedValue("title: Keychain extra\n");
    const remove = vi.spyOn(api, "deleteRuleContentDocument").mockResolvedValue({
      path: "authored/keychain_extra.yml", corpus_version: 4, warnings: [],
    });
    render(<RuleSource ruleId="keychain_extra" editable />);

    expect(await screen.findByRole("link", { name: "Edit" })).toHaveAttribute("href", "/rules/keychain_extra/edit");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "superseded" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" }));

    await waitFor(() => { expect(remove).toHaveBeenCalledWith("authored/keychain_extra.yml", "superseded"); });
  });

  it("offers no edit or delete when not editable", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "imported/curl.yml", bytes: 42 }]);
    vi.spyOn(api, "getRuleContentDocument").mockResolvedValue("title: Curl\n");
    render(<RuleSource ruleId="curl" />);

    await screen.findByText("imported/curl.yml");
    expect(screen.queryByRole("link", { name: "Edit" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
  });

  it("reports a failed read", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockRejectedValue(new Error("API error: 500"));
    render(<RuleSource ruleId="suspicious_exec" />);

    expect(await screen.findByText(/could not be loaded: API error: 500/)).toBeVisible();
    expect(screen.queryByText(/built into the server/)).toBeNull();
  });
});
