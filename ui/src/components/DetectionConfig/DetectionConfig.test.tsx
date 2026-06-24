import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { DetectionConfig } from "./DetectionConfig";
import { PermissionsProvider } from "../../permissions";
import { PermissionAction } from "../../permissions-core";
import * as api from "../../api";
import type { DetectionExclusion, DetectionRuleSetting, RuleDoc, RuleDocEntry } from "../../api";

const makeRuleDoc = (over: Partial<RuleDoc> = {}): RuleDoc => ({
  title: "Suspicious execution",
  summary: "",
  description: "",
  severity: "medium",
  event_types: ["process_exec"],
  ...over,
});

const makeExclusion = (over: Partial<DetectionExclusion> = {}): DetectionExclusion => ({
  id: 1,
  rule_id: "suspicious_exec",
  match_type: "parent_path_glob",
  value: "*/claude/versions/*",
  host_group_id: 0,
  reason: "Claude Code CLI",
  enabled: true,
  created_by: "user:1",
  created_at: "2026-06-22T00:00:00Z",
  ...over,
});

const makeRuleEntry = (over: Partial<RuleDocEntry> = {}): RuleDocEntry => ({
  id: "suspicious_exec",
  techniques: ["T1059"],
  doc: makeRuleDoc(),
  ...over,
});

const makeSetting = (over: Partial<DetectionRuleSetting> = {}): DetectionRuleSetting => ({
  id: 1,
  rule_id: "suspicious_exec",
  host_group_id: 0,
  mode: "monitor",
  severity_override: "high",
  updated_by: "user:1",
  updated_at: "2026-06-22T00:00:00Z",
  ...over,
});

// stubReads wires the three read endpoints the page loads on mount.
function stubReads(opts: {
  exclusions?: DetectionExclusion[];
  rules?: RuleDocEntry[];
  settings?: DetectionRuleSetting[];
} = {}) {
  vi.spyOn(api, "listDetectionExclusions").mockResolvedValue(opts.exclusions ?? []);
  vi.spyOn(api, "fetchRuleDocs").mockResolvedValue(opts.rules ?? [makeRuleEntry()]);
  vi.spyOn(api, "listDetectionRuleSettings").mockResolvedValue(opts.settings ?? []);
}

// renderPage mounts the component under a permission set. Default grants write so affordances render; pass [read] for read-only.
function renderPage(
  permissions: string[] = [PermissionAction.DetectionConfigRead, PermissionAction.DetectionConfigWrite],
) {
  return render(
    <MemoryRouter>
      <PermissionsProvider permissions={permissions}>
        <DetectionConfig />
      </PermissionsProvider>
    </MemoryRouter>,
  );
}

// jsdom doesn't implement HTMLDialogElement.showModal/close; stub them so the reason modal renders.
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() { this.open = true; };
  HTMLDialogElement.prototype.close = function close() { this.open = false; };
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DetectionConfig", () => {
  // The mode + severity controls render for every rule straight from its fetchRuleDocs entry, with no rule-specific UI.
  // spec:web-ui/detection-configuration-admin-views/per-rule-mode-and-severity-controls-render-for-every-rule
  it("loads and renders exclusions plus the rule-modes table", async () => {
    stubReads({ exclusions: [makeExclusion()], rules: [makeRuleEntry()], settings: [makeSetting()] });
    renderPage();

    expect(screen.getByText(/loading detection configuration/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument();
    });
    expect(screen.getByText("Claude Code CLI")).toBeInTheDocument();
    // The rule-modes table reflects the persisted setting (monitor + high).
    expect(screen.getByLabelText("mode for suspicious_exec")).toHaveValue("monitor");
    expect(screen.getByLabelText("severity override for suspicious_exec")).toHaveValue("high");
    // The rule-modes table surfaces each rule's declared (default) severity from its catalog doc. Queried as a cell so the
    // "medium" option in the severity-override select doesn't make the match ambiguous.
    expect(screen.getByText("Default severity")).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "medium" })).toBeInTheDocument();
  });

  // The rule picker shows a concise rule name: the descriptive parenthetical and the rule id are dropped from the option text,
  // while the id still rides as the option value the form submits.
  it("renders a concise rule name in the picker, dropping the descriptive aside and id", async () => {
    const verbose = makeRuleEntry({
      id: "suspicious_exec",
      doc: makeRuleDoc({ title: "Suspicious exec chain (non-shell → shell → temp/network)" }),
    });
    stubReads({ rules: [verbose] });
    renderPage();
    await waitFor(() => { expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument(); });

    const option = screen.getByRole("option", { name: "Suspicious exec chain" });
    expect(option).toHaveValue("suspicious_exec");
    expect(screen.queryByRole("option", { name: /\(suspicious_exec\)/ })).not.toBeInTheDocument();
  });

  it("orders the rule picker alphabetically by display name", async () => {
    stubReads({
      rules: [
        makeRuleEntry({ id: "zeta", doc: makeRuleDoc({ title: "Zeta rule" }) }),
        makeRuleEntry({ id: "alpha", doc: makeRuleDoc({ title: "Alpha rule" }) }),
        makeRuleEntry({ id: "mid", doc: makeRuleDoc({ title: "Mid rule" }) }),
      ],
    });
    renderPage();
    await waitFor(() => { expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument(); });

    const options = within(screen.getByLabelText("Rule")).getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual(["Select a rule...", "Alpha rule", "Mid rule", "Zeta rule"]);
  });

  // The rule-modes table sorts by declared severity (critical first), ties broken alphabetically by title; an unspecified ("")
  // severity ranks last.
  it("orders the rule-modes table by severity, critical first, then alphabetically", async () => {
    stubReads({
      rules: [
        makeRuleEntry({ id: "unset_a", doc: makeRuleDoc({ title: "A rule", severity: "" }) }),
        makeRuleEntry({ id: "low_b", doc: makeRuleDoc({ title: "B rule", severity: "low" }) }),
        makeRuleEntry({ id: "crit_z", doc: makeRuleDoc({ title: "Z rule", severity: "critical" }) }),
        makeRuleEntry({ id: "high_a", doc: makeRuleDoc({ title: "A rule", severity: "high" }) }),
        makeRuleEntry({ id: "crit_a", doc: makeRuleDoc({ title: "A rule", severity: "critical" }) }),
      ],
    });
    renderPage();
    await waitFor(() => { expect(screen.getByLabelText("mode for crit_a")).toBeInTheDocument(); });

    const order = screen.getAllByLabelText(/^mode for /).map((s) => s.getAttribute("aria-label"));
    expect(order).toEqual([
      "mode for crit_a", "mode for crit_z", "mode for high_a", "mode for low_b", "mode for unset_a",
    ]);
  });

  it("shows an empty state when there are no exclusions", async () => {
    stubReads({ exclusions: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });
  });

  it("surfaces a load error", async () => {
    vi.spyOn(api, "listDetectionExclusions").mockRejectedValue(new Error("boom"));
    vi.spyOn(api, "fetchRuleDocs").mockResolvedValue([]);
    vi.spyOn(api, "listDetectionRuleSettings").mockResolvedValue([]);
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/error: boom/i)).toBeInTheDocument();
    });
  });

  // spec:web-ui/detection-configuration-admin-views/an-operator-adds-an-exclusion-from-the-ui
  it("creates an exclusion from the add form and reloads", async () => {
    stubReads({ rules: [makeRuleEntry()] });
    const create = vi.spyOn(api, "createDetectionExclusion").mockResolvedValue(makeExclusion());
    renderPage();
    await waitFor(() => { expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument(); });

    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "suspicious_exec" } });
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "*/foo/*" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "benign tool" } });
    fireEvent.click(screen.getByRole("button", { name: /add exclusion/i }));

    await waitFor(() => {
      expect(create).toHaveBeenCalledWith({
        rule_id: "suspicious_exec",
        match_type: "path_glob",
        value: "*/foo/*",
        reason: "benign tool",
      });
    });
  });

  it("sends an optional expiry as an RFC3339 end-of-day instant when set", async () => {
    stubReads({ rules: [makeRuleEntry()] });
    const create = vi.spyOn(api, "createDetectionExclusion").mockResolvedValue(makeExclusion());
    renderPage();
    await waitFor(() => { expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument(); });

    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "suspicious_exec" } });
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "*/foo/*" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "benign tool" } });
    fireEvent.change(screen.getByLabelText(/expires/i), { target: { value: "2026-07-01" } });
    fireEvent.click(screen.getByRole("button", { name: /add exclusion/i }));

    await waitFor(() => {
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ expires_at: "2026-07-01T23:59:59Z" }));
    });
  });

  it("disables Add until rule, value, and reason are filled", async () => {
    stubReads({ rules: [makeRuleEntry()] });
    renderPage();
    await waitFor(() => { expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument(); });
    expect(screen.getByRole("button", { name: /add exclusion/i })).toBeDisabled();
  });

  it("deletes an exclusion with an audit reason", async () => {
    stubReads({ exclusions: [makeExclusion()] });
    const del = vi.spyOn(api, "deleteDetectionExclusion").mockResolvedValue(undefined);
    renderPage();
    await waitFor(() => { expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument(); });

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(del).toHaveBeenCalledWith(1, "removed via admin UI");
    });
  });

  // Reducing a rule's alerting opens the reason modal; the operator's reason rides the upsert for the audit row.
  // spec:web-ui/detection-configuration-admin-views/disabling-or-monitoring-a-rule-requires-an-operator-reason
  it("requires a reason via the modal before disabling a rule", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "disabled" }));
    renderPage();
    await waitFor(() => { expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument(); });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "disabled" } });
    // The modal opens and nothing is sent yet.
    await waitFor(() => { expect(screen.getByText(/Disable "Suspicious execution"/)).toBeInTheDocument(); });
    expect(upsert).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText(/required for audit log/i), { target: { value: "noisy in the pilot fleet" } });
    fireEvent.click(screen.getByRole("button", { name: "Disable rule" }));
    await waitFor(() => {
      expect(upsert).toHaveBeenCalledWith({
        rule_id: "suspicious_exec",
        mode: "disabled",
        severity_override: undefined,
        reason: "noisy in the pilot fleet",
      });
    });
  });

  it("cancelling the reason modal sends no mutation", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting());
    renderPage();
    await waitFor(() => { expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument(); });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "disabled" } });
    await waitFor(() => { expect(screen.getByText(/Disable "Suspicious execution"/)).toBeInTheDocument(); });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => { expect(screen.queryByText(/Disable "Suspicious execution"/)).not.toBeInTheDocument(); });
    expect(upsert).not.toHaveBeenCalled();
  });

  // monitor is no longer operator-selectable: a rule with no persisted setting offers only alert and disabled.
  // spec:web-ui/detection-configuration-admin-views/monitor-is-not-an-operator-selectable-mode
  it("does not offer monitor as a selectable mode", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [] });
    renderPage();
    await waitFor(() => { expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument(); });

    const modes = within(screen.getByLabelText("mode for suspicious_exec")).getAllByRole("option").map((o) => o.textContent);
    expect(modes).toEqual(["alert", "disabled"]);
  });

  // A legacy persisted `monitor` row still displays correctly (monitor is shown so the controlled select matches), letting the
  // operator migrate it to alert/disabled.
  it("still displays a legacy monitor setting so it can be migrated", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "monitor" })] });
    renderPage();
    await waitFor(() => { expect(screen.getByLabelText("mode for suspicious_exec")).toHaveValue("monitor"); });

    const modes = within(screen.getByLabelText("mode for suspicious_exec")).getAllByRole("option").map((o) => o.textContent);
    expect(modes).toEqual(["monitor", "alert", "disabled"]);
  });

  // created_by shows the server-resolved email when present, falling back to the raw "user:<id>" identifier otherwise.
  // spec:web-ui/detection-configuration-admin-views/exclusion-author-is-shown-as-a-resolved-email
  it("renders created_by_email when the server resolves it, else the raw identifier", async () => {
    stubReads({
      exclusions: [
        makeExclusion({ id: 1, created_by: "user:8", created_by_email: "ops@fleetdm.com" }),
        makeExclusion({ id: 2, created_by: "user:9" }),
      ],
    });
    renderPage();
    await waitFor(() => { expect(screen.getByText("ops@fleetdm.com")).toBeInTheDocument(); });
    expect(screen.getByText("user:9")).toBeInTheDocument();
  });

  it("re-enabling a rule (mode -> alert) applies immediately with a generated reason and no modal", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "disabled", severity_override: undefined })] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "alert" }));
    renderPage();
    await waitFor(() => { expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument(); });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "alert" } });
    await waitFor(() => {
      expect(upsert).toHaveBeenCalledWith({
        rule_id: "suspicious_exec",
        mode: "alert",
        severity_override: undefined,
        reason: "re-enabled via admin UI",
      });
    });
    expect(screen.queryByRole("button", { name: "Disable rule" })).not.toBeInTheDocument();
  });

  it("changing only the severity override applies immediately with a generated reason and no modal", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "monitor", severity_override: undefined })] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting());
    renderPage();
    await waitFor(() => { expect(screen.getByLabelText("severity override for suspicious_exec")).toBeInTheDocument(); });

    fireEvent.change(screen.getByLabelText("severity override for suspicious_exec"), { target: { value: "critical" } });
    await waitFor(() => {
      expect(upsert).toHaveBeenCalledWith({
        rule_id: "suspicious_exec",
        mode: "monitor",
        severity_override: "critical",
        reason: "severity override changed via admin UI",
      });
    });
    expect(screen.queryByText(/to monitor|Disable/)).not.toBeInTheDocument();
  });

  it("disables the delete button while a mutation is in flight, then re-enables it", async () => {
    stubReads({ exclusions: [makeExclusion()] });
    // A deferred delete so the mutation stays in flight until we resolve it, letting us observe the disabled window.
    let resolveDelete: () => void = () => undefined;
    vi.spyOn(api, "deleteDetectionExclusion").mockReturnValue(
      new Promise<void>((res) => { resolveDelete = res; }),
    );
    renderPage();
    await waitFor(() => { expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument(); });

    const del = screen.getByRole("button", { name: "Delete" });
    expect(del).not.toBeDisabled();
    fireEvent.click(del);
    await waitFor(() => { expect(screen.getByRole("button", { name: "Delete" })).toBeDisabled(); });

    resolveDelete();
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Delete" })).not.toBeDisabled();
    });
  });

  it("renders a mutation error from a typed API error", async () => {
    stubReads({ exclusions: [makeExclusion()] });
    vi.spyOn(api, "deleteDetectionExclusion").mockRejectedValue(
      new api.DetectionConfigApiError("detection_config.invalid_input", "reason required", 400),
    );
    renderPage();
    await waitFor(() => { expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument(); });

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("reason required");
    });
  });

  it("hides write affordances for a read-only operator", async () => {
    stubReads({ exclusions: [makeExclusion()], rules: [makeRuleEntry()], settings: [makeSetting()] });
    renderPage([PermissionAction.DetectionConfigRead]);
    await waitFor(() => { expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument(); });

    // No add form and no delete control.
    expect(screen.queryByRole("button", { name: /add exclusion/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    // The mode/severity selects render disabled.
    expect(screen.getByLabelText("mode for suspicious_exec")).toBeDisabled();
    expect(screen.getByLabelText("severity override for suspicious_exec")).toBeDisabled();
  });
});
