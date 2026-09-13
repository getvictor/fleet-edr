import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { RuleEditor } from "./RuleEditor";
import * as api from "../api";

function renderEditor(entry: string) {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <Routes>
        <Route path="/rules/new" element={<RuleEditor />} />
        <Route path="/rules/:ruleId/edit" element={<RuleEditor />} />
        <Route path="/rules/:ruleId" element={<div>RULE PAGE</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

// jsdom does not implement HTMLDialogElement.showModal/close, which the reason modal opens with.
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() { this.open = true; };
  HTMLDialogElement.prototype.close = function close() { this.open = false; };
});

afterEach(() => {
  vi.restoreAllMocks();
});

const content = (): HTMLTextAreaElement => screen.getByLabelText<HTMLTextAreaElement>("Rule document");
const ruleDoc: api.RuleDoc = { title: "t", summary: "s", description: "d", severity: "high", event_types: ["exec"] };
const passingCheck = "The document is valid. Saving also checks it against the deployment's other rules.";

describe("RuleEditor, new rule", () => {
  // spec:web-ui/rules-can-be-written-in-the-console/a-new-rule-says-it-will-not-alert-until-promoted
  it("says a new rule runs in monitor mode until promoted, with the way to promote it", () => {
    renderEditor("/rules/new");

    expect(screen.getByText(/runs in/)).toHaveTextContent("A new rule runs in monitor mode");
    expect(screen.getByRole("link", { name: "Detection tuning" })).toHaveAttribute("href", "/detection-config");
  });

  // spec:web-ui/rules-can-be-written-in-the-console/an-invalid-rule-is-explained-before-anything-is-written
  it("shows the loader's refusal and keeps Save unavailable", async () => {
    vi.spyOn(api, "checkRuleContentDocument").mockResolvedValue({
      would_apply: false,
      warnings: [],
      refusal: "authored/my_rule.yml: detection: missing condition",
    });
    const put = vi.spyOn(api, "putRuleContentDocument");
    renderEditor("/rules/new");

    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "my_rule" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "would not load this rule: authored/my_rule.yml: detection: missing condition",
    );
    expect(api.checkRuleContentDocument).toHaveBeenCalledWith("authored/my_rule.yml", content().value);
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(put).not.toHaveBeenCalled();
  });

  it("does not check without a valid identifier", () => {
    renderEditor("/rules/new");

    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "not valid!" } });
    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
  });

  // spec:web-ui/rules-can-be-written-in-the-console/an-operator-creates-a-rule-with-a-reason
  it("saves a checked rule with a reason and opens its page", async () => {
    vi.spyOn(api, "checkRuleContentDocument").mockResolvedValue({ would_apply: true, warnings: ["runs on macOS only"] });
    const put = vi
      .spyOn(api, "putRuleContentDocument")
      .mockResolvedValue({ path: "authored/my_rule.yml", corpus_version: 3, warnings: [] });
    renderEditor("/rules/new");

    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "my_rule" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));
    // The dry run judges the document alone, so a pass claims no more than that.
    expect(await screen.findByRole("status")).toHaveTextContent(passingCheck);
    expect(screen.getByText("runs on macOS only")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "cover xattr quarantine removal" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("RULE PAGE")).toBeInTheDocument();
    expect(put).toHaveBeenCalledWith("authored/my_rule.yml", expect.stringContaining("title:"), "cover xattr quarantine removal");
  });

  // A check is a verdict about the content it saw. Editing afterwards must not leave Save armed by a verdict about different content.
  it("disarms Save when the content changes after a passing check", async () => {
    vi.spyOn(api, "checkRuleContentDocument").mockResolvedValue({ would_apply: true, warnings: [] });
    renderEditor("/rules/new");

    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "my_rule" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));
    await waitFor(() => { expect(screen.getByRole("button", { name: "Save" })).toBeEnabled(); });

    fireEvent.change(content(), { target: { value: "title: changed\n" } });
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.queryByText(passingCheck)).toBeNull();
  });

  // The identifier is the stored path and can collide with a shipped rule, so the check was about a different document too.
  it("disarms Save when the identifier changes after a passing check", async () => {
    vi.spyOn(api, "checkRuleContentDocument").mockResolvedValue({ would_apply: true, warnings: [] });
    renderEditor("/rules/new");

    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "my_rule" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));
    await waitFor(() => { expect(screen.getByRole("button", { name: "Save" })).toBeEnabled(); });

    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "suspicious_exec" } });
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.queryByText(passingCheck)).toBeNull();
  });

  // A check still in flight when the operator edits answers for the draft it was started on, not the one on screen.
  it("ignores a check that answers after the content changed", async () => {
    let answer: (result: api.RuleContentCheckResult) => void = () => undefined;
    vi.spyOn(api, "checkRuleContentDocument").mockReturnValue(new Promise((resolve) => { answer = resolve; }));
    renderEditor("/rules/new");

    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "my_rule" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));
    fireEvent.change(content(), { target: { value: "title: changed after the check started\n" } });
    answer({ would_apply: true, warnings: [] });

    await waitFor(() => { expect(screen.getByRole("button", { name: "Check" })).toBeEnabled(); });
    expect(screen.queryByText(passingCheck)).toBeNull();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("explains a write that lost a race with another change", async () => {
    vi.spyOn(api, "checkRuleContentDocument").mockResolvedValue({ would_apply: true, warnings: [] });
    vi.spyOn(api, "putRuleContentDocument").mockRejectedValue(
      new api.RuleContentApiError("rule_content.conflict", "corpus changed", 409),
    );
    renderEditor("/rules/new");

    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "my_rule" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));
    await waitFor(() => { expect(screen.getByRole("button", { name: "Save" })).toBeEnabled(); });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.change(screen.getByLabelText("Reason (required for audit log)"), { target: { value: "r" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText(/The rules changed while this was being saved/)).toBeVisible();
    // It says to check again, so the check the conflict invalidated no longer arms Save.
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });
});

describe("RuleEditor, existing rule", () => {
  beforeEach(() => {
    vi.spyOn(api, "fetchRuleDocs").mockResolvedValue([]);
  });

  it("loads the rule's stored document by its file stem", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "authored/keychain_extra.yml", bytes: 20 }]);
    vi.spyOn(api, "getRuleContentDocument").mockResolvedValue("title: Keychain extra\n");
    renderEditor("/rules/keychain_extra/edit");

    await waitFor(() => { expect(content().value).toBe("title: Keychain extra\n"); });
    expect(screen.queryByLabelText("Identifier")).toBeNull();
    expect(api.getRuleContentDocument).toHaveBeenCalledWith("authored/keychain_extra.yml");
  });

  // spec:web-ui/rules-can-be-written-in-the-console/a-shipped-rule-is-not-opened-for-editing
  // The Edit link is only offered on the deployment's own rules; an address typed directly must not reach around it.
  it("refuses a shipped rule, which is tuned rather than edited", async () => {
    const entry = (origin: string): api.RuleDocEntry => ({ id: "suspicious_exec", techniques: [], origin, doc: ruleDoc });
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "imported/suspicious_exec.yml", bytes: 20 }]);
    const read = vi.spyOn(api, "getRuleContentDocument").mockResolvedValue("title: Suspicious exec\n");

    vi.mocked(api.fetchRuleDocs).mockResolvedValue([entry("SigmaHQ, by Someone")]);
    const shipped = renderEditor("/rules/suspicious_exec/edit");
    expect(await screen.findByText(/ships with the product/)).toBeVisible();
    expect(screen.getByRole("link", { name: "Detection tuning" })).toHaveAttribute("href", "/detection-config");
    expect(screen.queryByLabelText("Rule document")).toBeNull();
    expect(read).not.toHaveBeenCalled();
    shipped.unmount();

    // A rule the server has not reported an origin for, one it refused or has not loaded yet, is still editable.
    vi.mocked(api.fetchRuleDocs).mockResolvedValue([]);
    renderEditor("/rules/suspicious_exec/edit");
    await waitFor(() => { expect(content().value).toBe("title: Suspicious exec\n"); });
  });

  it("edits the deployment's own rule", async () => {
    vi.mocked(api.fetchRuleDocs).mockResolvedValue([
      { id: "keychain_extra", techniques: [], origin: "Locally authored", doc: ruleDoc },
    ]);
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([{ path: "authored/keychain_extra.yml", bytes: 20 }]);
    vi.spyOn(api, "getRuleContentDocument").mockResolvedValue("title: Keychain extra\n");
    renderEditor("/rules/keychain_extra/edit");

    await waitFor(() => { expect(content().value).toBe("title: Keychain extra\n"); });
  });

  it("says when the rule has no stored document to edit", async () => {
    vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([]);
    renderEditor("/rules/suspicious_exec/edit");

    expect(await screen.findByText(/has no stored document to edit/)).toBeVisible();
  });
});
