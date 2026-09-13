import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { PermissionsProvider } from "../permissions";
import { PermissionAction } from "../permissions-core";
import { MemoryRouter, Routes, Route, useNavigate } from "react-router";
import { RuleDetail } from "./RuleDetail";
import * as api from "../api";
import type { RuleDocEntry } from "../api";

// RuleDetail loads /api/rules and renders one rule's documentation by :ruleId. Tests pin
// the loading state, the unknown-rule empty state (old bookmark to a deleted rule),
// the fetch-error path, the full body (summary, ATT&CK links, config / FP / limitations
// tables that only render when populated), the no-mapping fallback, and the severity
// badge allowlist (unknown severity falls back to the neutral pill class).

function makeEntry(over: Partial<RuleDocEntry> = {}): RuleDocEntry {
  return {
    id: "suspicious_exec",
    techniques: ["T1059.004"],
    doc: {
      title: "Suspicious exec",
      summary: "Detects suspicious execution.",
      description: "First paragraph.\n\nSecond paragraph.",
      severity: "high",
      event_types: ["exec"],
      false_positives: ["build scripts"],
      limitations: ["macOS only"],
    },
    ...over,
  };
}

function renderAt(ruleId: string) {
  return render(
    <MemoryRouter initialEntries={[`/rules/${ruleId}`]}>
      <Routes>
        <Route path="/rules/:ruleId" element={<RuleDetail />} />
        <Route path="/coverage" element={<div>COVERAGE</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.spyOn(api, "fetchRuleDocs");
  // Every render asks for the rule's document when the operator may read one; an empty corpus keeps these tests off the network.
  vi.spyOn(api, "listRuleContentDocuments").mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

const mockDocs = (entries: RuleDocEntry[]) => vi.mocked(api.fetchRuleDocs).mockResolvedValue(entries);

describe("RuleDetail loading and error states", () => {
  it("shows the loading state before the docs resolve", () => {
    vi.mocked(api.fetchRuleDocs).mockReturnValue(
      new Promise<RuleDocEntry[]>(() => {
        /* never resolves */
      }),
    );
    renderAt("suspicious_exec");
    expect(screen.getByText(/loading rule documentation/i)).toBeInTheDocument();
  });

  it("surfaces a fetch failure as an alert", async () => {
    vi.mocked(api.fetchRuleDocs).mockRejectedValue(new Error("boom"));
    renderAt("suspicious_exec");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/boom/i));
  });

  it("falls back to a generic message for a non-Error rejection", async () => {
    vi.mocked(api.fetchRuleDocs).mockRejectedValue("nope");
    renderAt("suspicious_exec");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/failed to load rule docs/i));
  });

  // The page is kept across rules, so moving to another rule reloads it; a failure on the first must not hide the second.
  it("clears an earlier failure once another rule loads", async () => {
    vi.mocked(api.fetchRuleDocs).mockRejectedValueOnce(new Error("boom")).mockResolvedValue([makeEntry({ id: "other_rule" })]);
    function Next() {
      const navigate = useNavigate();
      return <button type="button" onClick={() => { void navigate("/rules/other_rule"); }}>next</button>;
    }
    render(
      <MemoryRouter initialEntries={["/rules/suspicious_exec"]}>
        <Next />
        <Routes>
          <Route path="/rules/:ruleId" element={<RuleDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");

    fireEvent.click(screen.getByRole("button", { name: "next" }));
    expect(await screen.findByText("Suspicious exec")).toBeVisible();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("renders the unknown-rule empty state with a back link when the id is not found", async () => {
    mockDocs([makeEntry({ id: "other_rule" })]);
    renderAt("missing_rule");
    expect(await screen.findByText(/unknown rule/i)).toBeInTheDocument();
    expect(screen.getByText("missing_rule", { selector: "code" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to coverage/i })).toHaveAttribute("href", "/coverage");
  });
});

describe("RuleDetail body", () => {
  it("renders the title, summary, ATT&CK link, and split description paragraphs", async () => {
    mockDocs([makeEntry()]);
    renderAt("suspicious_exec");
    expect(await screen.findByText("Suspicious exec")).toBeInTheDocument();
    expect(screen.getByText("Detects suspicious execution.")).toBeInTheDocument();
    expect(screen.getByText("First paragraph.")).toBeInTheDocument();
    expect(screen.getByText("Second paragraph.")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "T1059.004" });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/004/");
  });

  it("renders the false-positive and limitations lists", async () => {
    mockDocs([makeEntry()]);
    renderAt("suspicious_exec");
    expect(await screen.findByText("Known false-positive sources")).toBeInTheDocument();
    expect(screen.getByText("build scripts")).toBeInTheDocument();
    expect(screen.getByText("Limitations")).toBeInTheDocument();
    expect(screen.getByText("macOS only")).toBeInTheDocument();
  });

  it("shows 'no mapping' and omits the optional sections when the rule declares none", async () => {
    mockDocs([
      makeEntry({
        techniques: [],
        doc: {
          title: "Bare rule",
          summary: "s",
          description: "d",
          severity: "low",
          event_types: ["exec"],
        },
      }),
    ]);
    renderAt("suspicious_exec");
    expect(await screen.findByText("Bare rule")).toBeInTheDocument();
    expect(screen.getByText(/no mapping/i)).toBeInTheDocument();
    expect(screen.queryByText("Configuration")).not.toBeInTheDocument();
    expect(screen.queryByText("Known false-positive sources")).not.toBeInTheDocument();
    expect(screen.queryByText("Limitations")).not.toBeInTheDocument();
  });

  it("renders a known severity with its modifier class", async () => {
    mockDocs([makeEntry()]);
    renderAt("suspicious_exec");
    const badge = await screen.findByText("high");
    expect(badge).toHaveClass("rule-detail__sev--high");
  });

  it("falls back to the unknown modifier for an out-of-allowlist severity", async () => {
    mockDocs([makeEntry({ doc: { ...makeEntry().doc, severity: "spicy" } })]);
    renderAt("suspicious_exec");
    const badge = await screen.findByText("spicy");
    expect(badge).toHaveClass("rule-detail__sev--unknown");
  });
});

describe("RuleDetail monitor mode and attribution", () => {
  // A monitor-mode rule records matches and raises nothing until promoted (issue #764). Severity alone reads as a promise the rule
  // does not make: "high" on a rule that never alerts is the most misleading pair on this page, so the mode has to appear beside it.
  it("says a monitor-mode rule raises no alert, next to its severity", async () => {
    mockDocs([makeEntry({ id: "vendored", default_mode: "monitor", mode: "monitor", mode_source: "default" })]);
    renderAt("vendored");

    expect(await screen.findByText(/Monitor/)).toBeInTheDocument();
    expect(screen.getByText(/records what it would have fired on and raises no alert/)).toBeInTheDocument();
    expect(screen.getByText(/This is the mode the rule declares/)).toBeInTheDocument();
    expect(screen.getByText(/Resolved at global scope/)).toBeInTheDocument();
  });

  // spec:web-ui/detection-configuration-admin-views/the-rule-detail-view-reports-the-mode-a-rule-runs-in
  //
  // The mode a rule RUNS IN is the question this page has to answer, and it is not always the mode the rule declares. A rule that
  // ships in monitor and that an operator has disabled reads as monitor if the page reports the declaration, which is the mode it
  // is not in. Reporting the source alongside is what separates the two cases the operator would act on differently.
  it("reports the mode a setting put the rule in, not the one it declares", async () => {
    mockDocs([makeEntry({ id: "vendored", default_mode: "monitor", mode: "disabled", mode_source: "setting" })]);
    renderAt("vendored");

    expect(await screen.findByText("Disabled")).toBeInTheDocument();
    expect(screen.getByText(/This rule is off and produces nothing/)).toBeInTheDocument();
    expect(screen.getByText(/An operator set this through the detection-config surface/)).toBeInTheDocument();
  });

  // A rule that alerts BECAUSE someone promoted it is worth a row, even though a rule that simply alerts is not: the reader would
  // otherwise have no way to tell that the catalog ships this rule in monitor and that alerting is a decision someone took.
  it("shows the row for a promoted rule, which alerts only because an operator said so", async () => {
    mockDocs([makeEntry({ id: "promoted", default_mode: "monitor", mode: "alert", mode_source: "setting" })]);
    renderAt("promoted");

    expect(await screen.findByText("Alert")).toBeInTheDocument();
    expect(screen.getByText(/This rule raises alerts as normal/)).toBeInTheDocument();
    expect(screen.getByText(/An operator set this through the detection-config surface/)).toBeInTheDocument();
  });

  // The absence of the row is the point for an alerting rule: adding "Mode: Alert" to every rule that behaves normally is noise,
  // and an older server that omits the field must keep its previous appearance rather than claiming anything new.
  it("says nothing about mode for a rule that alerts, or for a server that omits the field", async () => {
    mockDocs([makeEntry({ id: "alerting", default_mode: "alert", mode: "alert", mode_source: "default" })]);
    const { unmount } = renderAt("alerting");
    expect(await screen.findByText("Severity")).toBeInTheDocument();
    expect(screen.queryByText("Mode")).not.toBeInTheDocument();
    unmount();

    mockDocs([makeEntry({ id: "legacy" })]);
    renderAt("legacy");
    expect(await screen.findByText("Severity")).toBeInTheDocument();
    expect(screen.queryByText("Mode")).not.toBeInTheDocument();
  });

  // Disabled is the other non-alerting default ModeDefaulter permits. Keying the row on "monitor" alone left a disabled-default
  // rule looking exactly like an alerting one, which is the case the requirement is about: distinguish every rule that does not
  // alert, not just the mode this PR happens to ship.
  it("distinguishes a disabled default too, not only monitor", async () => {
    mockDocs([makeEntry({ id: "off", default_mode: "disabled", mode: "disabled", mode_source: "default" })]);
    renderAt("off");

    expect(await screen.findByText("Disabled")).toBeInTheDocument();
    expect(screen.getByText(/This rule is off and produces nothing/)).toBeInTheDocument();
  });

  // A server that omits `mode` has not said "no configuration applies"; it has failed to answer. During a rolling deploy an older
  // replica can report default_mode monitor for a rule whose global setting is disabled, so presenting the declaration as the mode
  // in force would state the opposite of the truth. The row reports the declaration AS the declaration and says the server did not
  // report the mode in force.
  it("labels the declaration as a declaration when the server reports no resolved mode", async () => {
    mockDocs([makeEntry({ id: "vendored", default_mode: "monitor" })]);
    renderAt("vendored");

    expect(await screen.findByText("Default mode")).toBeInTheDocument();
    expect(screen.getByText(/This server does not report the mode in force/)).toBeInTheDocument();
    expect(screen.queryByText("Mode")).not.toBeInTheDocument();
    // Saying "resolved at global scope" one sentence after "does not report the mode in force" contradicts itself.
    expect(screen.queryByText(/Resolved at global scope/)).not.toBeInTheDocument();
  });

  // `mode_source: default` means the reported MODE came from the rule's declaration. It does not mean no setting exists: a setting
  // whose stored mode this server cannot interpret also reports `default`, and can still carry an active severity override, so
  // claiming "no operator setting applies" would be a claim the field does not support.
  it("attributes a default-sourced mode to the rule without claiming no setting exists", async () => {
    mockDocs([makeEntry({ id: "vendored", default_mode: "monitor", mode: "monitor", mode_source: "default" })]);
    renderAt("vendored");

    expect(await screen.findByText(/This is the mode the rule declares/)).toBeInTheDocument();
    expect(screen.queryByText(/no operator setting applies/i)).not.toBeInTheDocument();
  });

  // A vendored rule is rendered exactly like one this project wrote, so without this an operator cannot tell whose rule they are
  // reading. The corpus is under DRL 1.1 and each rule names its own author, which is the attribution this carries.
  it("credits the source of a vendored rule and stays silent for our own", async () => {
    mockDocs([makeEntry({ id: "vendored", origin: "SigmaHQ, by Someone Else" })]);
    const { unmount } = renderAt("vendored");
    expect(await screen.findByText("SigmaHQ, by Someone Else")).toBeInTheDocument();
    unmount();

    mockDocs([makeEntry({ id: "ours" })]);
    renderAt("ours");
    expect(await screen.findByText("Severity")).toBeInTheDocument();
    expect(screen.queryByText("Source")).not.toBeInTheDocument();
  });
});

// Rule references (issue #765). These come from the upstream YAML of a rule this project vendored rather than wrote, so they are
// untrusted input rendered into an anchor: the scheme guard is a security control, not formatting.
describe("RuleDetail references", () => {
  // spec:server-detection-rules-engine/a-detection-s-references-are-available-beside-its-attribution/an-upstream-reference-is-offered-as-a-link
  it("renders an upstream reference as a link that opens safely", async () => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeEntry({ doc: { ...makeEntry().doc, references: ["https://redcanary.com/blog/applescript/"] } }),
    ]);
    renderAt("suspicious_exec");

    const link = await screen.findByRole("link", { name: "https://redcanary.com/blog/applescript/" });
    expect(link).toBeVisible();
    expect(link).toHaveAttribute("href", "https://redcanary.com/blog/applescript/");
    // noopener keeps the opened page from reaching back through window.opener into this session.
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });

  // The payload is third-party content. A javascript: href is script execution on click, so the guard renders it inert. Asserted
  // on the ABSENCE of a link rather than on the text, because the text is displayed either way and only the anchor is dangerous.
  // spec:server-detection-rules-engine/a-detection-s-references-are-available-beside-its-attribution/a-reference-carrying-an-executable-scheme-is-displayed-but-not-followable
  it.each([
    ["javascript:alert(1)", "a script URL"],
    ["data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "a data URL"],
    ["vbscript:msgbox(1)", "a vbscript URL"],
  ])("renders %s as inert text rather than a link (%s)", async (ref) => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeEntry({ doc: { ...makeEntry().doc, references: [ref] } }),
    ]);
    renderAt("suspicious_exec");

    expect(await screen.findByText(ref)).toBeVisible();
    expect(screen.queryByRole("link", { name: ref })).toBeNull();
  });

  // The bug this pins: isHTTPURL trims before parsing, so a citation with a leading non-breaking space is accepted, and an href
  // built from the untrimmed original resolves as a same-origin relative URL because the browser does not strip U+00A0. The href
  // must therefore be the value that was validated, not the value that was supplied. Found by Copilot on #824.
  it("links the normalized value, not the raw one, for a citation carrying a non-breaking space", async () => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeEntry({ doc: { ...makeEntry().doc, references: ["\u00A0https://redcanary.com/blog/x\u00A0"] } }),
    ]);
    renderAt("suspicious_exec");

    const link = await screen.findByRole("link", { name: "https://redcanary.com/blog/x" });
    expect(link).toHaveAttribute("href", "https://redcanary.com/blog/x");
  });

  // Not every citation is a URL. A bare DOI or a book title should still be shown rather than dropped.
  it("shows a non-URL citation as text", async () => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeEntry({ doc: { ...makeEntry().doc, references: ["Internal research note, 2026"] } }),
    ]);
    renderAt("suspicious_exec");

    expect(await screen.findByText("Internal research note, 2026")).toBeVisible();
  });

  it("omits the References heading when the rule cites nothing", async () => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([makeEntry()]);
    renderAt("suspicious_exec");

    await screen.findByText("Suspicious exec");
    expect(screen.queryByRole("heading", { name: "References" })).toBeNull();
  });
});

// The rule's document is read through endpoints gated on rule_content.read, so the page shows it only to an operator who holds that
// permission and never offers a panel that could only fail (issue #1001).
describe("RuleDetail rule document", () => {
  function renderWithPermissions(permissions: string[]) {
    return render(
      <PermissionsProvider permissions={permissions}>
        <MemoryRouter initialEntries={["/rules/suspicious_exec"]}>
          <Routes>
            <Route path="/rules/:ruleId" element={<RuleDetail />} />
          </Routes>
        </MemoryRouter>
      </PermissionsProvider>,
    );
  }

  // spec:web-ui/the-rule-catalogue-is-browsable/an-operator-reads-a-rule-as-written
  it("offers the rule document to an operator who may read rule content", async () => {
    mockDocs([makeEntry()]);
    renderWithPermissions([PermissionAction.AlertRead, PermissionAction.RuleContentRead]);

    expect(await screen.findByRole("heading", { name: "Rule document" })).toBeVisible();
  });

  // Shipped rules are tuned in Detection tuning, not rewritten here, so only the deployment's own rule gets Edit and Delete.
  it("offers edit only for the deployment's own rule, and only to an operator who may write", async () => {
    vi.mocked(api.listRuleContentDocuments).mockResolvedValue([{ path: "authored/suspicious_exec.yml", bytes: 1 }]);
    vi.spyOn(api, "getRuleContentDocument").mockResolvedValue("title: x\n");
    const write = [PermissionAction.AlertRead, PermissionAction.RuleContentRead, PermissionAction.RuleContentWrite];

    mockDocs([makeEntry({ origin: "Locally authored" })]);
    const { unmount } = renderWithPermissions(write);
    expect(await screen.findByRole("link", { name: "Edit" })).toBeVisible();
    unmount();

    mockDocs([makeEntry({ origin: "SigmaHQ, by Someone" })]);
    const shipped = renderWithPermissions(write);
    await screen.findByText("authored/suspicious_exec.yml");
    expect(screen.queryByRole("link", { name: "Edit" })).toBeNull();
    shipped.unmount();

    mockDocs([makeEntry({ origin: "Locally authored" })]);
    renderWithPermissions([PermissionAction.AlertRead, PermissionAction.RuleContentRead]);
    await screen.findByText("authored/suspicious_exec.yml");
    expect(screen.queryByRole("link", { name: "Edit" })).toBeNull();
  });

  it("does not offer it without rule_content.read", async () => {
    mockDocs([makeEntry()]);
    renderWithPermissions([PermissionAction.AlertRead]);

    expect(await screen.findByText("Suspicious exec")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Rule document" })).toBeNull();
    expect(api.listRuleContentDocuments).not.toHaveBeenCalled();
  });
});

describe("RuleDetail after a save", () => {
  function renderAfterSave(saved: "created" | "updated") {
    return render(
      <MemoryRouter initialEntries={[{ pathname: "/rules/suspicious_exec", state: { saved } }]}>
        <Routes>
          <Route path="/rules/:ruleId" element={<RuleDetail />} />
        </Routes>
      </MemoryRouter>,
    );
  }

  afterEach(() => {
    vi.useRealTimers();
  });

  // spec:web-ui/rules-can-be-written-in-the-console/a-new-rule-s-page-waits-for-the-server-to-load-it
  // The server serves a stored rule only after its next reload, so the page just after a create waits rather than calling it unknown.
  it("waits for a rule it has just created to be loaded, then shows it", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.fetchRuleDocs).mockResolvedValueOnce([]).mockResolvedValue([makeEntry()]);
    renderAfterSave("created");

    expect(await screen.findByText(/Waiting for the server to load/)).toBeVisible();
    expect(screen.queryByText(/Unknown rule/)).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent("Rule created. The server applies it when it next reloads its rules, within 30");
    expect(screen.getByRole("status")).toHaveTextContent("It runs in monitor mode until you promote it in Detection tuning.");

    // The notice leads the page, above whatever the body shows while it waits.
    const waiting = screen.getByText(/Waiting for the server to load/);
    expect(screen.getByRole("status").compareDocumentPosition(waiting) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    await act(() => vi.advanceTimersByTimeAsync(2_000));
    expect(await screen.findByText("Suspicious exec")).toBeVisible();
    expect(screen.queryByText(/Waiting for the server to load/)).toBeNull();
    await act(() => vi.advanceTimersByTimeAsync(10_000));
    expect(api.fetchRuleDocs).toHaveBeenCalledTimes(2);
  });

  it("stops asking once the page is left", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.fetchRuleDocs).mockResolvedValue([]);
    const { unmount } = renderAfterSave("created");

    await screen.findByText(/Waiting for the server to load/);
    unmount();
    await act(() => vi.advanceTimersByTimeAsync(10_000));
    expect(api.fetchRuleDocs).toHaveBeenCalledTimes(1);
  });

  it("stops waiting once a reload should have happened, and calls the rule unknown", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.fetchRuleDocs).mockResolvedValue([]);
    renderAfterSave("created");

    await screen.findByText(/Waiting for the server to load/);
    await act(() => vi.advanceTimersByTimeAsync(38_000));
    expect(screen.getByText(/Waiting for the server to load/)).toBeVisible();
    await act(() => vi.advanceTimersByTimeAsync(4_000));
    expect(await screen.findByText(/Unknown rule/)).toBeVisible();
    const calls = vi.mocked(api.fetchRuleDocs).mock.calls.length;
    await act(() => vi.advanceTimersByTimeAsync(10_000));
    expect(api.fetchRuleDocs).toHaveBeenCalledTimes(calls);
  });

  it("does not wait after an edit, whose rule is already loaded, and says nothing of monitor mode", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockDocs([]);
    renderAfterSave("updated");

    expect(await screen.findByText(/Unknown rule/)).toBeVisible();
    await act(() => vi.advanceTimersByTimeAsync(10_000));
    expect(screen.getByRole("status")).toHaveTextContent(
      /^Rule saved\. The server applies it when it next reloads its rules, within 30 seconds\.$/,
    );
    expect(api.fetchRuleDocs).toHaveBeenCalledTimes(1);
  });

  it("reports a load failure rather than waiting", async () => {
    vi.mocked(api.fetchRuleDocs).mockRejectedValue(new Error("boom"));
    renderAfterSave("created");

    expect(await screen.findByRole("alert")).toHaveTextContent("Error: boom");
    expect(screen.queryByText(/Waiting for the server to load/)).toBeNull();
  });
});
