import { describe, it, expect, vi, afterEach } from "vitest";
import { fireEvent, render as rtlRender, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";
import { RuleSource } from "./RuleSource";
import * as api from "../api";
import * as downloadModule from "../download";

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

  // spec:web-ui/the-rule-catalogue-is-browsable/an-operator-reads-a-rule-as-written
  it("shows a built-in rule's exported rule file, parameters included, instead of an empty panel", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "authored/keychain_extra.yml", bytes: 42 }]);
    const get = vi.spyOn(api, "getRuleContentDocument");
    const exported = "title: Suspicious exec chain\nx-engine:\n  rule_id: suspicious_exec\n  params:\n    window: 30s\n";
    const exportRule = vi.spyOn(api, "exportRule").mockResolvedValue(exported);
    const { container } = render(<RuleSource ruleId="suspicious_exec" />);

    expect(await screen.findByText(/built into the server/)).toBeVisible();
    expect(exportRule).toHaveBeenCalledWith("suspicious_exec");
    expect(get).not.toHaveBeenCalled();
    expect(container.querySelector("pre")?.textContent).toBe(exported);
    // A built-in rule ships with the release, so it is never offered for editing here.
    expect(screen.queryByRole("link", { name: "Edit" })).toBeNull();
  });

  it("downloads a built-in rule's file under the rule's id", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([]);
    vi.spyOn(api, "exportRule").mockResolvedValue("title: Suspicious exec chain\n");
    const download = vi.spyOn(downloadModule, "downloadText").mockImplementation(() => undefined);
    render(<RuleSource ruleId="suspicious_exec" />);

    fireEvent.click(await screen.findByRole("button", { name: "Download" }));
    expect(download).toHaveBeenCalledWith("title: Suspicious exec chain\n", "suspicious_exec.yml", "application/yaml");
  });

  it("downloads a stored rule document under its own file name", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "imported/process_creation/curl.yml", bytes: 12 }]);
    vi.spyOn(api, "getRuleContentDocument").mockResolvedValue("title: Curl\n");
    const download = vi.spyOn(downloadModule, "downloadText").mockImplementation(() => undefined);
    render(<RuleSource ruleId="curl" />);

    fireEvent.click(await screen.findByRole("button", { name: "Download" }));
    expect(download).toHaveBeenCalledWith("title: Curl\n", "curl.yml", "application/yaml");
  });

  it("reports a built-in rule whose file could not be exported", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([]);
    vi.spyOn(api, "exportRule").mockRejectedValue(new Error("API error: 404"));
    render(<RuleSource ruleId="suspicious_exec" />);

    expect(await screen.findByText(/could not be loaded: API error: 404/)).toBeVisible();
    expect(screen.queryByRole("button", { name: "Download" })).toBeNull();
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
