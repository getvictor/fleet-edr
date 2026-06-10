import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { Link, MemoryRouter, Routes, Route } from "react-router-dom";
import { PolicyDetail } from "./PolicyDetail";
import * as api from "../../api";
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
  ...over,
});

// PolicyDetail uses useParams, so we route through MemoryRouter +
// Routes so the :id parameter is bound. Wrapping the rendered
// component this way keeps the test focused on the page output
// rather than reproducing the App.tsx routing pyramid.
function renderPolicyDetailAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/app-control/policies/:id" element={<PolicyDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
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
  it("renders the policy header + a rules table including the truncated identifier", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: [makeRule()] }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Default" })).toBeInTheDocument();
    });
    expect(screen.getByText(/version 5/i)).toBeInTheDocument();
    expect(screen.getByText(/default app-control policy fixture/i)).toBeInTheDocument();
    // Identifier is truncated to 16 chars + ellipsis in the table.
    expect(screen.getByText("aaaaaaaaaaaaaaaa…")).toBeInTheDocument();
    expect(screen.getByText(/blocked by corp policy/i)).toBeInTheDocument();
    // Per-row Edit/Disable/Delete are wired and enabled (Phase A close-out PR-1d): each opens a modal that prompts for an audit
    // reason before firing the PATCH / DELETE endpoint.
    const edit = screen.getByRole("button", { name: "Edit" });
    expect(edit).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "Disable" })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "Delete" })).not.toBeDisabled();
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
      expect(screen.getByRole("button", { name: "Disable" })).toBeInTheDocument();
    });
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
      expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
    });
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
      expect(screen.getByRole("button", { name: "Edit" })).toBeInTheDocument();
    });
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
      // Identifier is the second column; its full value is on the title attribute (the cell text is truncated).
      return cells[1].getAttribute("title") ?? "";
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText(/filter by rule type/i), { target: { value: "TEAMID" } });
    expect(identifiersInTable()).toEqual(["ABCDE12345"]);
  });

  it("filters by enabled tri-state (Enabled then Disabled)", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: makeFilterFixture() }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByRole("table")).toBeInTheDocument());
    // Activate the filter on policy 7.
    fireEvent.change(screen.getByLabelText(/search rules by identifier or comment/i), { target: { value: "platform" } });
    expect(screen.getByText(/showing 1 of 4 rules/i)).toBeInTheDocument();
    // Switch to policy 8 via in-router navigation (no router remount).
    fireEvent.click(screen.getByRole("link", { name: /switch/i }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Other" })).toBeInTheDocument());
    // Filter is back to defaults: no summary line; search input is empty.
    expect(screen.queryByText(/showing \d+ of \d+ rules/i)).toBeNull();
    const searchInput = screen.getByLabelText(/search rules by identifier or comment/i);
    expect(searchInput).toHaveProperty("value", "");
  });
});
