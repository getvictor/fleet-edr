import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
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
  // Mirrors the real suspicious_exec supported set (issue #520): parent path glob plus signature dimensions. Tests that need a
  // different set (e.g. a path-only rule) override this.
  supported_exclusion_match_types: ["parent_path_glob", "team_id", "signing_id", "cdhash"],
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
function stubReads(
  opts: {
    exclusions?: DetectionExclusion[];
    rules?: RuleDocEntry[];
    settings?: DetectionRuleSetting[];
    matchCounts?: api.RuleMatchCount[];
    matchCountDays?: number;
  } = {},
) {
  vi.spyOn(api, "listDetectionExclusions").mockResolvedValue(opts.exclusions ?? []);
  vi.spyOn(api, "fetchRuleDocs").mockResolvedValue(opts.rules ?? [makeRuleEntry()]);
  vi.spyOn(api, "listDetectionRuleSettings").mockResolvedValue(opts.settings ?? []);
  vi.spyOn(api, "listDetectionRuleMatchCounts").mockResolvedValue({
    counts: opts.matchCounts ?? [],
    days: opts.matchCountDays ?? 7,
  });
}

// renderPage mounts the component under a permission set. Default grants write so affordances render; pass [read] for read-only.
function renderPage(permissions: string[] = [PermissionAction.DetectionConfigRead, PermissionAction.DetectionConfigWrite]) {
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
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close() {
    this.open = false;
  };
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

  // The rule picker shows the rule's canonical title verbatim as the option text (titles are clean single names, issue #519),
  // while the id rides as the option value the form submits.
  it("renders the canonical rule title in the picker, with the id as the option value", async () => {
    const entry = makeRuleEntry({
      id: "suspicious_exec",
      doc: makeRuleDoc({ title: "Suspicious exec chain" }),
    });
    stubReads({ rules: [entry] });
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });

    const option = screen.getByRole("option", { name: "Suspicious exec chain" });
    expect(option).toHaveValue("suspicious_exec");
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
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });

    const options = within(screen.getByLabelText("Rule"))
      .getAllByRole("option")
      .map((o) => o.textContent);
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
    await waitFor(() => {
      expect(screen.getByLabelText("mode for crit_a")).toBeInTheDocument();
    });

    const order = screen.getAllByLabelText(/^mode for /).map((s) => s.getAttribute("aria-label"));
    expect(order).toEqual(["mode for crit_a", "mode for crit_z", "mode for high_a", "mode for low_b", "mode for unset_a"]);
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
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "suspicious_exec" } });
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "*/foo/*" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "benign tool" } });
    fireEvent.click(screen.getByRole("button", { name: /add exclusion/i }));

    await waitFor(() => {
      // Selecting the rule defaulted the match type to its first supported type (parent_path_glob for suspicious_exec).
      expect(create).toHaveBeenCalledWith({
        rule_id: "suspicious_exec",
        match_type: "parent_path_glob",
        value: "*/foo/*",
        reason: "benign tool",
      });
    });
  });

  it("sends an optional expiry as an RFC3339 end-of-day instant when set", async () => {
    stubReads({ rules: [makeRuleEntry()] });
    const create = vi.spyOn(api, "createDetectionExclusion").mockResolvedValue(makeExclusion());
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });

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
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: /add exclusion/i })).toBeDisabled();
  });

  // The match-type picker offers ONLY the match types the selected rule consults (issue #520), in canonical display order, so an
  // operator cannot create an exclusion the rule would silently ignore.
  // spec:web-ui/detection-configuration-admin-views/exclusion-match-type-picker-offers-only-the-supported-types-for-a-rule
  it("offers only the selected rule's supported match types, in display order", async () => {
    stubReads({
      rules: [
        makeRuleEntry({
          id: "suspicious_exec",
          doc: makeRuleDoc({ title: "Suspicious execution" }),
          supported_exclusion_match_types: ["team_id", "cdhash", "parent_path_glob"],
        }),
      ],
    });
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });

    // Before a rule is picked the match-type select is disabled with a prompt option.
    const matchSelect = screen.getByLabelText("Match type");
    expect(matchSelect).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "suspicious_exec" } });
    // Options are the supported set intersected with the canonical order (parent_path_glob, team_id, cdhash), not the raw eight.
    const options = within(screen.getByLabelText("Match type"))
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(options).toEqual(["parent_path_glob", "team_id", "cdhash"]);
    expect(screen.getByLabelText("Match type")).not.toBeDisabled();
  });

  // Switching rules re-scopes the picker to the newly selected rule and resets the selection so a stale unsupported type can't submit.
  it("resets the match-type selection when the rule changes", async () => {
    stubReads({
      rules: [
        makeRuleEntry({
          id: "suspicious_exec",
          doc: makeRuleDoc({ title: "Suspicious execution" }),
          supported_exclusion_match_types: ["parent_path_glob", "team_id"],
        }),
        makeRuleEntry({
          id: "sudoers_tamper",
          doc: makeRuleDoc({ title: "Sudoers tamper" }),
          supported_exclusion_match_types: ["path_glob"],
        }),
      ],
    });
    const create = vi.spyOn(api, "createDetectionExclusion").mockResolvedValue(makeExclusion());
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/no exclusions configured/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "suspicious_exec" } });
    expect(screen.getByLabelText("Match type")).toHaveValue("parent_path_glob");

    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "sudoers_tamper" } });
    expect(screen.getByLabelText("Match type")).toHaveValue("path_glob");
    const options = within(screen.getByLabelText("Match type"))
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(options).toEqual(["path_glob"]);

    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "/etc/sudoers" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "package manager" } });
    fireEvent.click(screen.getByRole("button", { name: /add exclusion/i }));
    await waitFor(() => {
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ rule_id: "sudoers_tamper", match_type: "path_glob" }));
    });
  });

  it("deletes an exclusion with an audit reason", async () => {
    stubReads({ exclusions: [makeExclusion()] });
    const del = vi.spyOn(api, "deleteDetectionExclusion").mockResolvedValue(undefined);
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(del).toHaveBeenCalledWith(1, "removed via admin UI");
    });
  });

  // Disabling a rule opens the reason modal; the operator's reason rides the upsert for the audit row.
  // spec:web-ui/detection-configuration-admin-views/disabling-a-rule-requires-an-operator-reason
  it("requires a reason via the modal before disabling a rule", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "disabled" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "disabled" } });
    // The modal opens and nothing is sent yet.
    await waitFor(() => {
      expect(screen.getByText(/Disable "Suspicious execution"/)).toBeInTheDocument();
    });
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
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "disabled" } });
    await waitFor(() => {
      expect(screen.getByText(/Disable "Suspicious execution"/)).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByText(/Disable "Suspicious execution"/)).not.toBeInTheDocument();
    });
    expect(upsert).not.toHaveBeenCalled();
  });

  // Every mode the server defines is selectable. Monitor was left out while it was a legacy value on a handful of rows; with most
  // of the catalog defaulting to it (#764), leaving it out made promotion one-way, since a rule moved to alert could not go back.
  // spec:web-ui/detection-configuration-admin-views/monitor-is-an-operator-selectable-mode
  it("offers all three modes, so a promoted rule can be put back in monitor", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "alert" })] });
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toHaveValue("alert");
    });

    const modes = within(screen.getByLabelText("mode for suspicious_exec"))
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(modes).toEqual(["alert", "monitor", "disabled"]);
  });

  // A stored value this build does not recognise is still shown, so the control reports what is actually persisted rather than
  // silently displaying the first option. This is the only case modeOptions still fires on now that every real mode is listed.
  it("displays a stored mode it does not recognise rather than showing something else", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "quarantine" })] });
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toHaveValue("quarantine");
    });

    const modes = within(screen.getByLabelText("mode for suspicious_exec"))
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(modes).toEqual(["quarantine", "alert", "monitor", "disabled"]);
  });

  // Moving a rule to monitor stops it alerting, so it prompts like disabling does. The prompt has to describe THIS change: the
  // modal hard-coded the disable wording, which was right while disabled was the only reducing choice and would otherwise have
  // shown an operator a "Disable rule" button for a change that disables nothing.
  it("prompts for a reason when an alerting rule is moved to monitor, and says so", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "monitor" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "monitor" } });
    await waitFor(() => {
      expect(screen.getByText(/Move to monitor "Suspicious execution"/)).toBeInTheDocument();
    });
    expect(screen.queryByText(/Disable "Suspicious execution"/)).not.toBeInTheDocument();
    expect(screen.getByText(/records what it would have fired on/)).toBeInTheDocument();
    expect(upsert).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText(/required for audit log/i), { target: { value: "too noisy on build hosts" } });
    fireEvent.click(screen.getByRole("button", { name: "Move to monitor" }));
    await waitFor(() => {
      expect(upsert).toHaveBeenCalledTimes(1);
    });
    expect(upsert.mock.calls[0][0]).toMatchObject({ rule_id: "suspicious_exec", mode: "monitor", reason: "too noisy on build hosts" });
  });

  // Disabling is reachable from monitor as well as from alert, so the modal cannot describe the change as "stops producing alerts":
  // a monitor rule produces none already, and what it actually loses is the recorded signal an operator would promote it on.
  it("describes disabling by its target state, since it is reachable from monitor too", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "monitor" })] });
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toHaveValue("monitor");
    });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "disabled" } });
    await waitFor(() => {
      expect(screen.getByText(/Disable "Suspicious execution"/)).toBeInTheDocument();
    });
    expect(screen.getByText(/neither alerts nor monitor signals/)).toBeInTheDocument();
  });

  // modeOptions renders a stored mode this build cannot read so an operator can move a rule off it. Moving to alert from such a
  // value used to record "re-enabled via admin UI", asserting the rule had been disabled when nothing knows that it had.
  it("records a neutral reason when the prior mode is one it cannot read", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "quarantine" })] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "alert" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toHaveValue("quarantine");
    });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "alert" } });
    await waitFor(() => {
      expect(upsert).toHaveBeenCalledTimes(1);
    });
    expect(upsert.mock.calls[0][0]).toMatchObject({ mode: "alert", reason: "mode changed to alert via admin UI" });
  });

  // Out of disabled into monitor the rule does MORE than it did, so it applies immediately like any other restoration. Prompting
  // here would ask an operator to justify turning something back on.
  it("applies disabled to monitor immediately with a generated reason", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "disabled", severity_override: undefined })] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "monitor" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toHaveValue("disabled");
    });

    fireEvent.change(screen.getByLabelText("mode for suspicious_exec"), { target: { value: "monitor" } });
    await waitFor(() => {
      expect(upsert).toHaveBeenCalledTimes(1);
    });
    expect(upsert.mock.calls[0][0]).toMatchObject({ mode: "monitor", reason: "re-enabled in monitor mode via admin UI" });
    expect(screen.queryByRole("button", { name: "Move to monitor" })).not.toBeInTheDocument();
  });

  // created_by shows the server-resolved label (a user's email or a service account's name) when present, falling back to the raw
  // principal identifier otherwise.
  // spec:web-ui/detection-configuration-admin-views/exclusion-author-is-shown-as-a-resolved-email
  // spec:web-ui/detection-configuration-admin-views/exclusion-author-shows-a-service-account-name
  it("renders created_by_label (user email or service-account name) when resolved, else the raw identifier", async () => {
    stubReads({
      exclusions: [
        makeExclusion({ id: 1, created_by: "usr_8", created_by_label: "ops@fleetdm.com" }),
        makeExclusion({ id: 2, created_by: "svc_5", created_by_label: "ci-bot" }),
        makeExclusion({ id: 3, created_by: "usr_9" }),
      ],
    });
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("ops@fleetdm.com")).toBeInTheDocument();
    });
    expect(screen.getByText("ci-bot")).toBeInTheDocument();
    expect(screen.getByText("usr_9")).toBeInTheDocument();
  });

  it("re-enabling a rule (mode -> alert) applies immediately with a generated reason and no modal", async () => {
    stubReads({ rules: [makeRuleEntry()], settings: [makeSetting({ mode: "disabled", severity_override: undefined })] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "alert" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument();
    });

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
    await waitFor(() => {
      expect(screen.getByLabelText("severity override for suspicious_exec")).toBeInTheDocument();
    });

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
      new Promise<void>((res) => {
        resolveDelete = res;
      }),
    );
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument();
    });

    const del = screen.getByRole("button", { name: "Delete" });
    expect(del).not.toBeDisabled();
    fireEvent.click(del);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Delete" })).toBeDisabled();
    });

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
    await waitFor(() => {
      expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("reason required");
    });
  });

  it("hides write affordances for a read-only operator", async () => {
    stubReads({ exclusions: [makeExclusion()], rules: [makeRuleEntry()], settings: [makeSetting()] });
    renderPage([PermissionAction.DetectionConfigRead]);
    await waitFor(() => {
      expect(screen.getByText("*/claude/versions/*")).toBeInTheDocument();
    });

    // No add form and no delete control.
    expect(screen.queryByRole("button", { name: /add exclusion/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    // The mode/severity selects render disabled.
    expect(screen.getByLabelText("mode for suspicious_exec")).toBeDisabled();
    expect(screen.getByLabelText("severity override for suspicious_exec")).toBeDisabled();
  });
});

describe("DetectionConfig monitor-default rules", () => {
  // Sixty-six imported rules ship with a monitor default and no persisted setting (issue #764). Falling back to "alert" showed
  // them as alerting, which is wrong on its own, but the same value is what handleSeverityChange resubmits: touching only the
  // severity of one of these rules would have written mode=alert and silently promoted a rule nobody decided to promote.
  it("shows a monitor-default rule as monitor rather than alert", async () => {
    stubReads({
      rules: [makeRuleEntry({ id: "vendored", default_mode: "monitor" })],
      settings: [],
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByLabelText("mode for vendored")).toBeInTheDocument();
    });
    expect(screen.getByLabelText("mode for vendored")).toHaveValue("monitor");
  });

  it("does not promote a monitor-default rule when only its severity changes", async () => {
    stubReads({
      rules: [makeRuleEntry({ id: "vendored", default_mode: "monitor" })],
      settings: [],
    });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "monitor" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("severity override for vendored")).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("severity override for vendored"), { target: { value: "high" } });

    await waitFor(() => {
      expect(upsert).toHaveBeenCalled();
    });
    expect(upsert).toHaveBeenCalledWith(expect.objectContaining({ rule_id: "vendored", mode: "monitor", severity_override: "high" }));
  });

  // The audit row is read later by someone asking what happened, so the two ways a rule reaches alert have to read differently. A
  // rule coming from disabled was off and is being re-enabled; a rule coming from monitor was never off, it was evaluating and
  // recording, and what changed is that its matches now raise alerts.
  it("records a monitor-to-alert change as a promotion, not a re-enable", async () => {
    stubReads({ rules: [makeRuleEntry({ id: "vendored", default_mode: "monitor" })], settings: [] });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "alert" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for vendored")).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("mode for vendored"), { target: { value: "alert" } });

    await waitFor(() => {
      expect(upsert).toHaveBeenCalled();
    });
    expect(upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        rule_id: "vendored",
        mode: "alert",
        reason: "promoted from monitor to alert via admin UI",
      }),
    );
  });

  it("still records a disabled-to-alert change as a re-enable", async () => {
    stubReads({
      rules: [makeRuleEntry({ id: "ours" })],
      settings: [makeSetting({ rule_id: "ours", mode: "disabled" })],
    });
    const upsert = vi.spyOn(api, "upsertDetectionRuleSetting").mockResolvedValue(makeSetting({ mode: "alert" }));
    renderPage();
    await waitFor(() => {
      expect(screen.getByLabelText("mode for ours")).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText("mode for ours"), { target: { value: "alert" } });

    await waitFor(() => {
      expect(upsert).toHaveBeenCalled();
    });
    expect(upsert).toHaveBeenCalledWith(expect.objectContaining({ rule_id: "ours", reason: "re-enabled via admin UI" }));
  });

  // A rule this project wrote still falls back to alert, so the fix does not change how the rest of the catalog behaves.
  it("still treats a rule with no default and no setting as alerting", async () => {
    stubReads({ rules: [makeRuleEntry({ id: "ours" })], settings: [] });
    renderPage();

    await waitFor(() => {
      expect(screen.getByLabelText("mode for ours")).toBeInTheDocument();
    });
    expect(screen.getByLabelText("mode for ours")).toHaveValue("alert");
  });
});

describe("DetectionConfig observed column", () => {
  // The column exists so the evidence sits beside the control it informs (issue #813). What it must never do is read as a
  // forecast: it counts matches, and alerts deduplicate on (host, rule, subject) permanently, so a rule matching one process
  // repeatedly would raise a single alert.
  it("shows the volume and the reach, and calls the number approximate", async () => {
    stubReads({
      rules: [makeRuleEntry()],
      matchCounts: [{ rule_id: "suspicious_exec", matches: 4102, hosts: 3, last_seen: "2026-09-01T00:00:00Z" }],
      matchCountDays: 7,
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByText("4,102")).toBeInTheDocument();
    });
    expect(screen.getByText(/on 3 hosts/)).toBeInTheDocument();
    expect(screen.getByTitle(/approximately 4,102 matches on 3 hosts in the last 7 days/)).toBeInTheDocument();
  });

  // A rule with nothing recorded is ABSENT from the response, and absence is not the same claim as zero: the rule may have been
  // promoted before the window opened, or registered after it did.
  it("reads \"not recorded\" rather than a zero for a rule with nothing recorded", async () => {
    stubReads({ rules: [makeRuleEntry()], matchCounts: [] });
    renderPage();

    await waitFor(() => {
      expect(screen.getByLabelText("no matches recorded for suspicious_exec")).toBeInTheDocument();
    });
    expect(screen.queryByText("0 on 0 hosts")).not.toBeInTheDocument();
  });

  // Singular host reads as "1 host", because "1 hosts" beside a promote control is the kind of detail that makes an operator
  // trust the rest of the page less.
  it("agrees in number for a single host", async () => {
    stubReads({
      rules: [makeRuleEntry()],
      matchCounts: [{ rule_id: "suspicious_exec", matches: 5, hosts: 1, last_seen: "2026-09-01T00:00:00Z" }],
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/on 1 host$/)).toBeInTheDocument();
    });
  });

  // Losing the counts must not cost an operator the mode control. They are evidence for a decision, not a precondition for
  // reaching it, so the column degrades and the rest of the page loads.
  it("still renders the table when the counts cannot be read", async () => {
    stubReads({ rules: [makeRuleEntry()] });
    vi.spyOn(api, "listDetectionRuleMatchCounts").mockRejectedValue(new Error("db down"));
    renderPage();

    await waitFor(() => {
      expect(screen.getByLabelText("mode for suspicious_exec")).toBeInTheDocument();
    });
    expect(screen.queryByText(/Error:/)).not.toBeInTheDocument();
  });

  // spec:observability-instrumentation/recorded-monitor-match-counts-are-readable-per-rule/a-failed-read-is-not-presented-as-an-absence-of-matches
  // A FAILED read must not render as absence. This test previously asserted the opposite (that the cell fell back to "no matches
  // recorded"), which quietly turned an outage into fleet-wide evidence that every rule is quiet: the exact reading that gets a
  // noisy rule promoted, and the reading the spec forbids.
  it("says the counts are unavailable when the read fails, rather than showing them as absent", async () => {
    stubReads({ rules: [makeRuleEntry()] });
    vi.spyOn(api, "listDetectionRuleMatchCounts").mockRejectedValue(new Error("db down"));
    renderPage();

    await waitFor(() => {
      expect(screen.getByLabelText("match counts unavailable for suspicious_exec")).toBeInTheDocument();
    });
    expect(screen.queryByLabelText("no matches recorded for suspicious_exec")).not.toBeInTheDocument();
    // And the mode control stays usable, because the counts inform the decision rather than gate it.
    expect(screen.getByLabelText("mode for suspicious_exec")).toBeEnabled();
  });

  // A rule genuinely absent from a SUCCESSFUL read is the other case, and must keep reading as absence.
  it("reads \"not recorded\" for a rule absent from a SUCCESSFUL read", async () => {
    stubReads({ rules: [makeRuleEntry()], matchCounts: [] });
    renderPage();

    await waitFor(() => {
      expect(screen.getByLabelText("no matches recorded for suspicious_exec")).toBeInTheDocument();
    });
    expect(screen.queryByLabelText("match counts unavailable for suspicious_exec")).not.toBeInTheDocument();
  });

  // The caveat and the window must be readable without a mouse. Both were tooltip-only, on non-focusable elements, which reaches
  // neither keyboard nor touch users; the caveat in particular is what stops a bare number beside a promote control reading as a
  // forecast of alert volume.
  it("states the caveat and the window in visible text, not only in a tooltip", async () => {
    stubReads({
      rules: [makeRuleEntry()],
      matchCounts: [{ rule_id: "suspicious_exec", matches: 5, hosts: 1, last_seen: new Date().toISOString() }],
    });
    renderPage();

    // toBeVisible, not toBeInTheDocument: the point of this fix is that the caveat is SEEN, not merely present. A mutation that
    // hid the note passed against toBeInTheDocument, which asserts the wrong property for a visibility requirement.
    await waitFor(() => {
      expect(screen.getByText(/not of how many alerts promoting the rule would raise/)).toBeVisible();
    });
    expect(screen.getByText(/over the last 7 days/)).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "Observed (7d)" })).toBeVisible();
  });

  // The visible cell abbreviates, so the exact figure and the window have to reach assistive technology some other way.
  it("labels the cell with the exact count and the window it covers", async () => {
    stubReads({
      rules: [makeRuleEntry()],
      matchCounts: [{ rule_id: "suspicious_exec", matches: 42000, hosts: 1, last_seen: new Date().toISOString() }],
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/42k/)).toBeInTheDocument();
    });
    expect(screen.getByLabelText(/approximately 42,000 matches on 1 host in the last 7 days/)).toBeInTheDocument();
  });

  // "approximately 1 matches" is the kind of wrong that makes a number look unread. The host noun was already pluralised; the
  // match noun was not.
  it("pluralises the match noun for a single match", async () => {
    stubReads({
      rules: [makeRuleEntry()],
      matchCounts: [{ rule_id: "suspicious_exec", matches: 1, hosts: 1, last_seen: new Date().toISOString() }],
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByLabelText(/approximately 1 match on 1 host/)).toBeInTheDocument();
    });
    expect(screen.queryByLabelText(/1 matches/)).not.toBeInTheDocument();
  });

  // When the read fails the visible note must say so too, not leave the normal caption implying the empty cells are data.
  it("replaces the visible caveat with the unavailable notice when the read fails", async () => {
    stubReads({ rules: [makeRuleEntry()] });
    vi.spyOn(api, "listDetectionRuleMatchCounts").mockRejectedValue(new Error("db down"));
    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/Match counts could not be loaded/)).toBeVisible();
    });
    expect(screen.queryByText(/not of how many alerts promoting the rule would raise/)).not.toBeInTheDocument();
    // And the header must not advertise a window it cannot cover.
    expect(screen.getByRole("columnheader", { name: "Observed" })).toBeInTheDocument();
  });

  // Recency is the third signal the column promises: heavy-but-quiet and heavy-and-current are different promotion cases.
  it("shows how recently a rule last matched", async () => {
    // Plain arithmetic, flagged only because dash-lint's C-style scanner has no string-literal state: an exclusion glob near the
    // top of this file ends in the two characters that open a block comment, so the scanner reads much of the file as commented
    // prose. Identical arithmetic in HostList.test.tsx passes. Issue #820.
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 3_600_000).toISOString(); // dash-lint:ignore
    stubReads({
      rules: [makeRuleEntry()],
      matchCounts: [{ rule_id: "suspicious_exec", matches: 5, hosts: 1, last_seen: twoDaysAgo }],
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/2d ago/)).toBeInTheDocument();
    });
  });

  // Large counts abbreviate, because scanning this column is about telling tens from thousands.
  it("abbreviates counts in the tens of thousands", async () => {
    stubReads({
      rules: [makeRuleEntry()],
      matchCounts: [{ rule_id: "suspicious_exec", matches: 42_300, hosts: 12, last_seen: "2026-09-01T00:00:00Z" }],
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByText("42k")).toBeInTheDocument();
    });
    expect(screen.getByTitle(/approximately 42,300 matches/)).toBeInTheDocument();
  });
});
