import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { Link, MemoryRouter, Routes, Route } from "react-router";
import { PolicyDetail } from "./PolicyDetail";
import * as api from "../../api";
import { PermissionAction, PermissionsContext } from "../../permissions-core";
import type { ApplicationControlPolicy, ApplicationControlRule } from "../../types";

const makeRule = (over: Partial<ApplicationControlRule> = {}): ApplicationControlRule => ({
  id: 1,
  policy_id: 1,
  rule_type: "BINARY",
  identifier: "a".repeat(64),
  action: "BLOCK",
  enforcement: "PROTECT",
  enabled: true,
  severity: "high",
  source: "admin",
  custom_msg: "Blocked by corp policy",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "user:1",
  ...over,
});

const makePolicy = (over: Partial<ApplicationControlPolicy> = {}): ApplicationControlPolicy => ({
  id: 7,
  name: "Default",
  description: "Default app-control policy fixture",
  version: 5,
  default_action: "NONE",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "system",
  updated_by: "user:1",
  assignment_count: 1,
  rule_count: 0,
  ...over,
});

// Every rule affordance the page offers, and nothing else. A test about something other than permissions grants this so a
// gated button is present for the reason the test is about rather than missing for one it is not. Detection tuning is
// deliberately absent: the would-block figure is gated separately and several tests below turn on that distinction.
const EVERY_RULE_ACTION = [
  PermissionAction.AppControlRead,
  PermissionAction.AppControlRuleCreate,
  PermissionAction.AppControlRuleUpdate,
  PermissionAction.AppControlRuleDelete,
  PermissionAction.AppControlRuleBulkUpsert,
];

// normalize collapses the whitespace JSX leaves between a text node and an inline element, so an assertion can name the whole
// message an operator reads rather than a fragment of it.
const normalize = (text: string | null) => text?.replace(/\s+/g, " ").trim();

// PolicyDetail uses useParams, so we route through MemoryRouter +
// Routes so the :id parameter is bound. Wrapping the rendered
// component this way keeps the test focused on the page output
// rather than reproducing the App.tsx routing pyramid.
// A row's actions live behind one "Actions" menu rather than as a run of inline links, so opening that menu is what puts Edit /
// Disable / Delete in the document. Every row-level assertion goes through here. Returns false when the row offers no actions at
// all, which is itself what a read-only operator should see.
function openRowActions(): boolean {
  const triggers = screen.queryAllByRole("button", { name: /^Actions for / });
  if (triggers.length === 0) return false;
  fireEvent.click(triggers[0]);
  return true;
}

function renderPolicyDetailAt(path: string, permissions?: readonly string[]) {
  return render(
    <PermissionsContext.Provider value={permissions}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/app-control/policies/:id" element={<PolicyDetail />} />
        </Routes>
      </MemoryRouter>
    </PermissionsContext.Provider>,
  );
}

beforeEach(() => {
  // The page reads the would-block counts for Detect rules; keep it off the network unless a test says otherwise.
  vi.spyOn(api, "listDetectionRuleMatchCounts").mockResolvedValue({ counts: [], days: 7 });
  // Same jsdom-stub posture as AddRuleModal.test.tsx; the runtime
  // existence check trips no-unnecessary-condition because TS
  // believes the prototype methods exist.
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

describe("PolicyDetail", () => {
  it("renders the policy header + a rules table carrying each rule's whole identifier", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: [makeRule()] }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Default" })).toBeInTheDocument();
    });
    expect(screen.getByText(/version 5/i)).toBeInTheDocument();
    expect(screen.getByText(/default app-control policy fixture/i)).toBeInTheDocument();
    // The cell holds the WHOLE identifier and lets its box clip what does not fit, so selecting the cell copies the value rather
    // than a fragment ending in an ellipsis, and the copy control has something to offer.
    expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: `Copy identifier ${"a".repeat(64)}` })).toBeVisible();
    expect(screen.getByText(/blocked by corp policy/i)).toBeInTheDocument();
    // Per-row Edit/Disable/Delete are wired and enabled (Phase A close-out PR-1d): each opens a modal that prompts for an audit
    // reason before firing the PATCH / DELETE endpoint.
    openRowActions();
    const edit = screen.getByRole("button", { name: "Edit" });
    expect(edit).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "Disable" })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "Delete" })).not.toBeDisabled();
  });

  // spec:web-ui/the-policy-rules-table-shows-each-rule-s-enforcement/a-rule-s-enforcement-is-visible-in-the-list
  it("shows each rule's enforcement in its row", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({
        rules: [
          makeRule({ id: 1, identifier: "a".repeat(64), enforcement: "DETECT" }),
          makeRule({ id: 2, identifier: "b".repeat(64), enforcement: "PROTECT" }),
        ],
      }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Default" })).toBeInTheDocument();
    });
    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    // The badge is the cell's first element; a Detect rule's cell also carries its would-block figure beneath it.
    const enforcementBadge = (row: HTMLElement) => within(row).getAllByRole("cell")[2].firstElementChild?.textContent;
    await waitFor(() => {
      expect(rows.map(enforcementBadge)).toEqual(["Detect", "Protect"]);
    });
  });

  // spec:web-ui/a-detect-rule-can-be-promoted-with-its-impact-in-view/promoting-shows-what-the-rule-would-have-blocked
  it("shows a Detect rule's would-block impact and promotes it to Protect with a reason", async () => {
    const detectRule = makeRule({ id: 7, identifier: "e".repeat(64), enforcement: "DETECT" });
    const getSpy = vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [detectRule] }));
    vi.spyOn(api, "listDetectionRuleMatchCounts").mockResolvedValue({
      counts: [{ rule_id: "app_control:7", matches: 12, hosts: 3, last_seen: "2026-09-14T00:00:00Z" }],
      days: 7,
    });
    const updateSpy = vi.spyOn(api, "updateAppControlRule").mockResolvedValue(makeRule({ id: 7, enforcement: "PROTECT" }));

    renderPolicyDetailAt("/app-control/policies/7");
    const impactLink = await screen.findByRole("link", { name: "Would have blocked 12 runs on 3 hosts in 7 days" });
    expect(impactLink).toHaveAttribute("href", "/rules/app_control%3A7/monitor-records");

    openRowActions();
    fireEvent.click(screen.getByRole("button", { name: "Promote to Protect" }));
    const dialog = await waitFor(() => openModal(/promote rule to protect/i));
    expect(dialog.textContent).toMatch(/protect makes this rule block the executables it matches for .*, instead of recording them/i);
    expect(dialog.textContent).toContain("Would have blocked 12 runs on 3 hosts in 7 days");
    expect(within(dialog).getByRole("link", { name: /review the records/i })).toHaveAttribute(
      "href",
      "/rules/app_control%3A7/monitor-records",
    );
    fireEvent.change(within(dialog).getByLabelText(/reason \(required for audit log\)/i), {
      target: { value: "a week of expected matches" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: /promote to protect/i }));

    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledWith(7, { enforcement: "PROTECT", reason: "a week of expected matches" });
    });
    await waitFor(() => {
      expect(getSpy).toHaveBeenCalledTimes(2);
    });
  });

  it("moves a Protect rule back to Detect", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule({ id: 9, enforcement: "PROTECT" })] }));
    // Counts left over from when the rule ran in Detect mode: a Protect rule blocks, so its row states no would-block figure.
    const countsSpy = vi.spyOn(api, "listDetectionRuleMatchCounts").mockResolvedValue({
      counts: [{ rule_id: "app_control:9", matches: 5, hosts: 2, last_seen: "2026-09-14T00:00:00Z" }],
      days: 7,
    });
    const updateSpy = vi.spyOn(api, "updateAppControlRule").mockResolvedValue(makeRule({ id: 9, enforcement: "DETECT" }));

    renderPolicyDetailAt("/app-control/policies/7");
    await screen.findByRole("button", { name: /^Actions for / });
    openRowActions();
    fireEvent.click(screen.getByRole("button", { name: "Move to Detect" }));
    await waitFor(() => {
      expect(countsSpy).toHaveBeenCalled();
    });
    expect(screen.queryByRole("link", { name: /would have blocked/i })).toBeNull();
    const dialog = await waitFor(() => openModal(/move rule to detect/i));
    expect(dialog.textContent).toMatch(
      /detect makes this rule record the executables it matches for .* that run, instead of blocking them\. another protect rule/i,
    );
    fireEvent.change(within(dialog).getByLabelText(/reason \(required for audit log\)/i), { target: { value: "too noisy" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /move to detect/i }));

    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledWith(9, { enforcement: "DETECT", reason: "too noisy" });
    });
  });

  // spec:web-ui/a-detect-rule-can-be-promoted-with-its-impact-in-view/without-access-to-match-counts-the-figure-is-left-out
  it("leaves the impact out for an operator who cannot read detection tuning", async () => {
    const countsSpy = vi.spyOn(api, "listDetectionRuleMatchCounts");
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule({ id: 7, enforcement: "DETECT" })] }));

    renderPolicyDetailAt("/app-control/policies/7", EVERY_RULE_ACTION);
    await screen.findByRole("button", { name: /^Actions for / });
    openRowActions();
    expect(screen.getByRole("button", { name: "Promote to Protect" })).toBeInTheDocument();
    expect(countsSpy).not.toHaveBeenCalled();
    expect(screen.queryByText(/would-block|would have blocked/i)).toBeNull();
  });

  it("stops showing the impact when a permission refresh revokes detection tuning", async () => {
    vi.spyOn(api, "listDetectionRuleMatchCounts").mockResolvedValue({
      counts: [{ rule_id: "app_control:7", matches: 12, hosts: 3, last_seen: "2026-09-14T00:00:00Z" }],
      days: 7,
    });
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule({ id: 7, enforcement: "DETECT" })] }));
    const tree = (permissions?: readonly string[]) => (
      <PermissionsContext.Provider value={permissions}>
        <MemoryRouter initialEntries={["/app-control/policies/7"]}>
          <Routes>
            <Route path="/app-control/policies/:id" element={<PolicyDetail />} />
          </Routes>
        </MemoryRouter>
      </PermissionsContext.Provider>
    );

    const { rerender } = render(tree());
    expect(await screen.findByRole("link", { name: /would have blocked 12 runs/i })).toBeVisible();
    rerender(tree(EVERY_RULE_ACTION));
    expect(screen.queryByRole("link", { name: /would have blocked/i })).toBeNull();
    openRowActions();
    fireEvent.click(screen.getByRole("button", { name: "Promote to Protect" }));
    const dialog = await waitFor(() => openModal(/promote rule to protect/i));
    expect(dialog.textContent).not.toMatch(/would have blocked/i);
  });

  it("shows no counts from an earlier grant while a read after access is restored is pending", async () => {
    const countsSpy = vi
      .spyOn(api, "listDetectionRuleMatchCounts")
      .mockResolvedValueOnce({
        counts: [{ rule_id: "app_control:7", matches: 12, hosts: 3, last_seen: "2026-09-14T00:00:00Z" }],
        days: 7,
      })
      .mockReturnValueOnce(new Promise(() => undefined));
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule({ id: 7, enforcement: "DETECT" })] }));
    const tree = (permissions?: readonly string[]) => (
      <PermissionsContext.Provider value={permissions}>
        <MemoryRouter initialEntries={["/app-control/policies/7"]}>
          <Routes>
            <Route path="/app-control/policies/:id" element={<PolicyDetail />} />
          </Routes>
        </MemoryRouter>
      </PermissionsContext.Provider>
    );

    const { rerender } = render(tree());
    expect(await screen.findByRole("link", { name: /would have blocked 12 runs/i })).toBeVisible();
    rerender(tree(EVERY_RULE_ACTION));
    rerender(tree());
    await waitFor(() => {
      expect(countsSpy).toHaveBeenCalledTimes(2);
    });
    expect(screen.queryByRole("link", { name: /would have blocked/i })).toBeNull();
  });

  it("keeps the rules usable when the match counts cannot be read", async () => {
    const countsSpy = vi.spyOn(api, "listDetectionRuleMatchCounts").mockRejectedValue(new Error("counts unavailable"));
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule({ id: 7, enforcement: "DETECT" })] }));

    renderPolicyDetailAt("/app-control/policies/7");
    await screen.findByRole("button", { name: /^Actions for / });
    openRowActions();
    fireEvent.click(screen.getByRole("button", { name: "Promote to Protect" }));
    const dialog = await waitFor(() => openModal(/promote rule to protect/i));
    expect(countsSpy).toHaveBeenCalled();
    expect(dialog.textContent).not.toMatch(/would have blocked|would-block/i);
    expect(screen.queryByRole("link", { name: /would have blocked|would-block/i })).toBeNull();
  });

  // PolicyDetail mounts the modals as siblings. Each modal renders a <dialog> that, even when closed in JSDOM, keeps its
  // children in the DOM, so RTL queries against `screen` match labels in closed dialogs too. Scope to the dialog addressed by
  // its accessible name AND require its `open` attribute to be set so a test that fires the action but doesn't actually open
  // the dialog (e.g. a regression in the wiring) fails loudly instead of false-passing on the closed dialog. Addresses the
  // Copilot finding on PR #189.
  function openModal(name: RegExp): HTMLElement {
    const dialog = screen.getByRole("dialog", { name });
    if (!(dialog as HTMLDialogElement).open) {
      throw new Error(`expected dialog matching ${String(name)} to be open, but its .open attribute is false`);
    }
    return dialog;
  }

  it("opens the disable-confirm modal, fires PATCH with reason + enabled=false, refreshes the policy", async () => {
    const getSpy = vi.spyOn(api, "getAppControlPolicy");
    getSpy.mockResolvedValueOnce(makePolicy({ rules: [makeRule()] }));
    const updateSpy = vi.spyOn(api, "updateAppControlRule").mockResolvedValue(
      makeRule({ enabled: false }),
    );
    // Refresh fetches the policy a second time; return the disabled-rule shape so the table reflects the new state.
    getSpy.mockResolvedValueOnce(makePolicy({ rules: [makeRule({ enabled: false })], version: 6 }));

    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /^Actions for / })).toBeInTheDocument();
    });
    openRowActions();
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));

    // Confirm modal is now open; scope all the queries to that dialog so RTL doesn't pick up the Add/Edit modals' inputs.
    const dialog = await waitFor(() => openModal(/disable rule/i));
    const reasonInput = within(dialog).getByLabelText(/reason \(required for audit log\)/i);
    fireEvent.change(reasonInput, { target: { value: "Pause for triage" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /disable rule/i }));

    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledTimes(1);
    });
    expect(updateSpy.mock.calls[0]).toEqual([
      1,
      { enabled: false, reason: "Pause for triage" },
    ]);
    // Page refetched after success; the second mocked policy load fires.
    await waitFor(() => {
      expect(getSpy).toHaveBeenCalledTimes(2);
    });
  });

  it("opens the delete-confirm modal, fires DELETE with reason, refreshes the policy", async () => {
    const getSpy = vi.spyOn(api, "getAppControlPolicy");
    getSpy.mockResolvedValueOnce(makePolicy({ rules: [makeRule()] }));
    const deleteSpy = vi.spyOn(api, "deleteAppControlRule").mockResolvedValue();
    getSpy.mockResolvedValueOnce(makePolicy({ rules: [] }));

    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /^Actions for / })).toBeInTheDocument();
    });
    openRowActions();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    const dialog = await waitFor(() => openModal(/delete rule/i));
    const reasonInput = within(dialog).getByLabelText(/reason \(required for audit log\)/i);
    fireEvent.change(reasonInput, { target: { value: "Misfire on legit binary" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /delete rule/i }));

    await waitFor(() => {
      expect(deleteSpy).toHaveBeenCalledTimes(1);
    });
    expect(deleteSpy.mock.calls[0]).toEqual([
      1,
      { reason: "Misfire on legit binary" },
    ]);
    await waitFor(() => {
      expect(getSpy).toHaveBeenCalledTimes(2);
    });
  });

  it("opens the edit modal, sends only changed fields + reason on save", async () => {
    const getSpy = vi.spyOn(api, "getAppControlPolicy");
    getSpy.mockResolvedValueOnce(makePolicy({ rules: [makeRule()] }));
    const updateSpy = vi.spyOn(api, "updateAppControlRule").mockResolvedValue(
      makeRule({ severity: "critical" }),
    );
    getSpy.mockResolvedValueOnce(makePolicy({ rules: [makeRule({ severity: "critical" })], version: 6 }));

    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /^Actions for / })).toBeInTheDocument();
    });
    openRowActions();
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));

    const dialog = await waitFor(() => openModal(/edit rule/i));
    // Severity dropdown reflects the current value; change it.
    const severitySelect = within(dialog).getByLabelText(/^severity$/i);
    fireEvent.change(severitySelect, { target: { value: "critical" } });
    // Reason is required.
    const reasonInput = within(dialog).getByLabelText(/reason \(required for audit log\)/i);
    fireEvent.change(reasonInput, { target: { value: "Promote based on intel signal" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /save changes/i }));

    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledTimes(1);
    });
    // PATCH body carries only the changed field (severity) + reason; custom_msg / custom_url / comment did not change so
    // they MUST NOT appear on the wire (the audit log would otherwise show a multi-field edit for a single-field intent).
    expect(updateSpy.mock.calls[0]).toEqual([
      1,
      { severity: "critical", reason: "Promote based on intel signal" },
    ]);
  });

  it("renders an empty-state CTA when the policy has zero rules", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: [] }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByText(/no rules yet/i)).toBeInTheDocument();
    });
    // Add rule button is the primary CTA; renders enabled once
    // policy load completes.
    const addRule = screen.getByRole("button", { name: /add rule/i });
    expect(addRule).not.toBeDisabled();
  });

  it("shows the bad-id message when the URL parameter is not a number", () => {
    renderPolicyDetailAt("/app-control/policies/not-a-number");
    expect(screen.getByText(/invalid policy id/i)).toBeInTheDocument();
  });

  it("surfaces an error when getAppControlPolicy rejects", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockRejectedValue(new Error("nope"));
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByText(/error: nope/i)).toBeInTheDocument();
    });
  });

  // Filter tests. Per spec task 8.7 + the web-ui spec's filterable-rules-table requirement, these pin the four filter
  // dimensions and the empty-state behavior when no rule matches.

  const makeFilterFixture = (): ApplicationControlRule[] => [
    makeRule({
      id: 1, rule_type: "BINARY", identifier: "aaaa1111".repeat(8),
      source: "admin", enabled: true, custom_msg: "blocked by IT",
    }),
    makeRule({
      id: 2, rule_type: "CDHASH", identifier: "bbbb2222".repeat(5),
      source: "import", enabled: false, comment: "legacy paste", custom_msg: undefined,
    }),
    makeRule({
      id: 3, rule_type: "TEAMID", identifier: "ABCDE12345",
      source: "admin", enabled: true, custom_msg: undefined,
    }),
    makeRule({
      id: 4, rule_type: "SIGNINGID", identifier: "platform:com.apple.curl",
      source: "import", enabled: true, custom_msg: undefined,
    }),
  ];

  function identifiersInTable(): string[] {
    const table = screen.getByRole("table");
    return within(table).getAllByRole("row").slice(1).map((row) => {
      const cells = within(row).getAllByRole("cell");
      // Identifier is the second column. Its text IS the full value now: the box clips what it shows, not what it holds.
      return cells[1].textContent;
    });
  }

  it("renders the filter bar with adaptive type + source dropdowns", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("search")).toBeInTheDocument();
    });
    const typeSelect = screen.getByLabelText(/filter by rule type/i);
    const sourceSelect = screen.getByLabelText(/filter by source/i);
    expect(Array.from((typeSelect as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(["", "BINARY", "CDHASH", "SIGNINGID", "TEAMID"]);
    expect(Array.from((sourceSelect as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(["", "admin", "import"]);
  });

  it("filters by free-text search over identifier", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/search rules by identifier or comment/i), {
      target: { value: "platform" },
    });
    expect(identifiersInTable()).toEqual(["platform:com.apple.curl"]);
    expect(screen.getByText(/showing 1 of 4 rules/i)).toBeInTheDocument();
  });

  it("filters by free-text search over comment", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/search rules by identifier or comment/i), {
      target: { value: "LEGACY" },
    });
    // CDHASH rule's comment is "legacy paste"; a case-insensitive match should surface only it.
    expect(identifiersInTable().map((id) => id.slice(0, 8))).toEqual(["bbbb2222"]);
  });

  it("filters by exact rule_type", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/filter by rule type/i), { target: { value: "TEAMID" } });
    expect(identifiersInTable()).toEqual(["ABCDE12345"]);
  });

  it("filters by enabled tri-state (Enabled then Disabled)", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    const statusSelect = screen.getByLabelText(/filter by status/i);
    fireEvent.change(statusSelect, { target: { value: "enabled" } });
    expect(identifiersInTable()).toHaveLength(3);
    fireEvent.change(statusSelect, { target: { value: "disabled" } });
    expect(identifiersInTable().map((id) => id.slice(0, 8))).toEqual(["bbbb2222"]);
  });

  it("filters by source", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/filter by source/i), { target: { value: "import" } });
    const ids = identifiersInTable();
    expect(ids).toHaveLength(2);
    expect(ids).toContain("platform:com.apple.curl");
  });

  it("intersects multiple filter dimensions (BINARY + enabled)", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/filter by rule type/i), { target: { value: "BINARY" } });
    fireEvent.change(screen.getByLabelText(/filter by status/i), { target: { value: "enabled" } });
    expect(identifiersInTable()).toHaveLength(1);
    expect(screen.getByText(/showing 1 of 4 rules/i)).toBeInTheDocument();
  });

  it("shows the no-match empty state when filters exclude every rule, with a working Clear link", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/filter by rule type/i), { target: { value: "TEAMID" } });
    fireEvent.change(screen.getByLabelText(/filter by source/i), { target: { value: "import" } });
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByText(/no rules match the current filter/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /clear filters/i }));
    // After clear, every rule is visible again.
    expect(identifiersInTable()).toHaveLength(4);
  });

  it("hides the filter summary when no filter is active and shows it when one is", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    // No filter applied -> no summary line.
    expect(screen.queryByText(/showing \d+ of \d+ rules/i)).toBeNull();
    // Type something into the search to activate the filter.
    fireEvent.change(screen.getByLabelText(/search rules by identifier or comment/i), {
      target: { value: "aaaa" },
    });
    expect(screen.getByText(/showing 1 of 4 rules/i)).toBeInTheDocument();
  });

  it("resets the filter when the operator navigates to a different policy", async () => {
    // PolicyDetail reuses the same component instance across :id changes via React Router. Without the policyID-keyed
    // reset effect, the previous policy's filter would persist (Copilot finding on PR #193). Render under a parent that
    // can swap the :id at runtime and assert the filter clears when policyID changes.
    const getSpy = vi.spyOn(api, "getAppControlPolicy");
    getSpy.mockImplementation((id: number) => {
      if (id === 7) return Promise.resolve(makePolicy({ id: 7, rules: makeFilterFixture() }));
      const otherRule = makeRule({ id: 99, rule_type: "BINARY", identifier: "z".repeat(64) });
      return Promise.resolve(makePolicy({ id: 8, name: "Other", rules: [otherRule] }));
    });

    // Production-shape harness: a single MemoryRouter (NO `key` prop so it stays mounted across navigation) plus a
    // "switch policy" link that triggers a route change via React Router's <Link>. This exercises the actual production
    // path where the same <Routes> resolves both URLs to a re-rendered PolicyDetail with a fresh policyID prop -
    // forcing the policyID-keyed reset effect to be what clears the filter. An earlier shape used a `key={path}`
    // remount which would pass even with the reset effect removed (Copilot finding on PR #194).
    function SwitchToOther() {
      return <Link to="/app-control/policies/8">switch</Link>;
    }
    render(
      <MemoryRouter initialEntries={["/app-control/policies/7"]}>
        <SwitchToOther />
        <Routes>
          <Route path="/app-control/policies/:id" element={<PolicyDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByRole("table")).toBeInTheDocument();
    // Activate the filter on policy 7.
    fireEvent.change(screen.getByLabelText(/search rules by identifier or comment/i), { target: { value: "platform" } });
    expect(screen.getByText(/showing 1 of 4 rules/i)).toBeInTheDocument();
    // Switch to policy 8 via in-router navigation (no router remount).
    fireEvent.click(screen.getByRole("link", { name: /switch/i }));
    expect(await screen.findByRole("heading", { name: "Other" })).toBeInTheDocument();
    // Filter is back to defaults: no summary line; search input is empty.
    expect(screen.queryByText(/showing \d+ of \d+ rules/i)).toBeNull();
    const searchInput = screen.getByLabelText(/search rules by identifier or comment/i);
    expect(searchInput).toHaveProperty("value", "");
  });

  // An operator who can read the page and change nothing is a real role (senior_analyst), and every one of these controls was
  // offered to them before issue #1056. Each is named by the control's own label rather than by a container, because the label
  // is what the operator sees and what a future refactor would have to keep meaning the same thing.
  describe("gates each control on the permission its own call needs", () => {
    const CONTROLS = [
      { name: "Paste many", needs: PermissionAction.AppControlRuleBulkUpsert, inRowMenu: false },
      { name: "Add rule", needs: PermissionAction.AppControlRuleCreate, inRowMenu: false },
      { name: "Move to Detect", needs: PermissionAction.AppControlRuleUpdate, inRowMenu: true },
      { name: "Edit", needs: PermissionAction.AppControlRuleUpdate, inRowMenu: true },
      { name: "Disable", needs: PermissionAction.AppControlRuleUpdate, inRowMenu: true },
      { name: "Delete", needs: PermissionAction.AppControlRuleDelete, inRowMenu: true },
    ];

    // spec:web-ui/application-control-rule-controls-follow-their-own-permission/a-control-is-hidden-without-its-own-permission
    it.each(CONTROLS)("hides $name from an operator without $needs", async ({ name, needs, inRowMenu }) => {
      vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule()] }));
      renderPolicyDetailAt("/app-control/policies/7", EVERY_RULE_ACTION.filter((action) => action !== needs));
      await waitFor(() => {
        expect(screen.getByRole("heading", { name: "Default" })).toBeVisible();
      });
      // A row action is only in the document while its menu is open, so the menu is opened before looking for its absence:
      // querying a closed menu would report every row action as hidden and pass whatever the permissions said.
      if (inRowMenu) openRowActions();
      expect(screen.queryByRole("button", { name })).toBeNull();
    });

    // spec:web-ui/application-control-rule-controls-follow-their-own-permission/a-control-is-shown-with-its-own-permission
    it.each(CONTROLS)("shows $name to an operator who holds $needs", async ({ name, inRowMenu }) => {
      vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule()] }));
      renderPolicyDetailAt("/app-control/policies/7", EVERY_RULE_ACTION);
      if (inRowMenu) {
        await screen.findByRole("button", { name: /^Actions for / });
        openRowActions();
      }
      expect(await screen.findByRole("button", { name })).toBeVisible();
    });

    // spec:web-ui/application-control-rule-controls-follow-their-own-permission/a-read-only-operator-still-sees-the-rules
    it("leaves a read-only operator the rules themselves, with no Actions column over empty cells", async () => {
      vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule()] }));
      renderPolicyDetailAt("/app-control/policies/7", [PermissionAction.AppControlRead]);
      expect(await screen.findByText("a".repeat(64))).toBeVisible();
      expect(screen.getByText(/blocked by corp policy/i)).toBeVisible();
      expect(screen.queryByRole("columnheader", { name: "Actions" })).toBeNull();
      expect(openRowActions()).toBe(false);
      const row = within(screen.getByRole("table")).getAllByRole("row")[1];
      // The copy control is the one button a read-only operator keeps: reading an identifier is reading.
      expect(within(row).queryAllByRole("button").map((b) => b.getAttribute("aria-label"))).toEqual([
        `Copy identifier ${"a".repeat(64)}`,
      ]);
    });

    // The empty state told the operator to click a button that is no longer there, which reads as a broken page rather than as
    // a permission they lack.
    // spec:web-ui/application-control-rule-controls-follow-their-own-permission/a-read-only-operator-still-sees-the-rules
    it("does not tell a read-only operator to click Add rule on an empty policy", async () => {
      vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [] }));
      renderPolicyDetailAt("/app-control/policies/7", [PermissionAction.AppControlRead]);
      const empty = await screen.findByText(/this policy has no rules yet/i);
      expect(empty).toBeVisible();
      // The whole message, not a substring: the prompt it used to carry is split across a <strong>, so a text query for it
      // matches nothing whether the prompt is there or not.
      expect(normalize(empty.textContent)).toBe("This policy has no rules yet.");
    });

    it("still tells an operator who may add rules how to add the first one", async () => {
      vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [] }));
      renderPolicyDetailAt("/app-control/policies/7", EVERY_RULE_ACTION);
      const empty = await screen.findByText(/this policy has no rules yet/i);
      expect(normalize(empty.textContent)).toBe("This policy has no rules yet. Click Add rule to author the first one.");
    });

    // A permission can go away while its dialog is open: the submit gets a 403, App.tsx refreshes the permission set, and the
    // button behind the dialog disappears. The dialog has to go with it, or the operator is left looking at a Save button whose
    // only remaining outcome is another 403. Qodo caught this on PR #1132: hiding the buttons alone left the two out of step.
    // spec:web-ui/application-control-rule-controls-follow-their-own-permission/a-dialog-closes-when-its-permission-is-revoked
    it.each([
      { name: "Edit", dialog: /edit rule/i, needs: PermissionAction.AppControlRuleUpdate },
      { name: "Delete", dialog: /delete rule/i, needs: PermissionAction.AppControlRuleDelete },
    ])("closes the $name dialog when $needs is revoked while it is open", async ({ name, dialog, needs }) => {
      vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule()] }));
      const tree = (permissions: readonly string[]) => (
        <PermissionsContext.Provider value={permissions}>
          <MemoryRouter initialEntries={["/app-control/policies/7"]}>
            <Routes>
              <Route path="/app-control/policies/:id" element={<PolicyDetail />} />
            </Routes>
          </MemoryRouter>
        </PermissionsContext.Provider>
      );

      const { rerender } = render(tree(EVERY_RULE_ACTION));
      await screen.findByRole("button", { name: /^Actions for / });
      openRowActions();
      fireEvent.click(screen.getByRole("button", { name }));
      expect(await waitFor(() => openModal(dialog))).toBeTruthy();

      rerender(tree(EVERY_RULE_ACTION.filter((action) => action !== needs)));
      await waitFor(() => {
        expect(screen.queryByRole("dialog", { name: dialog })).toBeNull();
      });
      openRowActions();
      expect(screen.queryByRole("button", { name })).toBeNull();
    });

    // A server that returns no permission set at all (one predating the field) renders optimistically and leans on the 403,
    // which is the pre-gating behaviour the capability seam promises. Gating must not turn that into a page with no controls.
    it("still offers every control when the permission set is unknown", async () => {
      vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(makePolicy({ rules: [makeRule()] }));
      renderPolicyDetailAt("/app-control/policies/7");
      // Opened once, not per control: the trigger is a toggle, so opening it again for the second row action would close it.
      await screen.findByRole("button", { name: /^Actions for / });
      openRowActions();
      for (const { name } of CONTROLS) {
        expect(await screen.findByRole("button", { name })).toBeVisible();
      }
    });
  });
});
