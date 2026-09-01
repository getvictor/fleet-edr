import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router";
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

