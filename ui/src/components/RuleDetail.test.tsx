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

const mockDocs = (entries: RuleDocEntry[]) =>
  vi.mocked(api.fetchRuleDocs).mockResolvedValue(entries);

describe("RuleDetail loading and error states", () => {
  it("shows the loading state before the docs resolve", () => {
    vi.mocked(api.fetchRuleDocs).mockReturnValue(new Promise<RuleDocEntry[]>(() => { /* never resolves */ }));
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
    mockDocs([makeEntry({ id: "vendored", default_mode: "monitor" })]);
    renderAt("vendored");

    expect(await screen.findByText(/Monitor/)).toBeInTheDocument();
    expect(screen.getByText(/By default this rule records matches without raising an alert/)).toBeInTheDocument();
    expect(screen.getByText(/not the mode in force for a given host/)).toBeInTheDocument();
  });

  // The absence of the row is the point for an alerting rule: adding "Mode: Alert" to every rule that behaves normally is noise,
  // and an older server that omits the field must keep its previous appearance rather than claiming anything new.
  it("says nothing about mode for a rule that alerts, or for a server that omits the field", async () => {
    mockDocs([makeEntry({ id: "alerting", default_mode: "alert" })]);
    const { unmount } = renderAt("alerting");
    expect(await screen.findByText("Severity")).toBeInTheDocument();
    expect(screen.queryByText(/By default this rule records matches/)).not.toBeInTheDocument();
    unmount();

    mockDocs([makeEntry({ id: "legacy" })]);
    renderAt("legacy");
    expect(await screen.findByText("Severity")).toBeInTheDocument();
    expect(screen.queryByText(/By default this rule records matches/)).not.toBeInTheDocument();
  });

  // Disabled is the other non-alerting default ModeDefaulter permits. Keying the row on "monitor" alone left a disabled-default
  // rule looking exactly like an alerting one, which is the case the requirement is about: distinguish every rule that does not
  // alert, not just the mode this PR happens to ship.
  it("distinguishes a disabled default too, not only monitor", async () => {
    mockDocs([makeEntry({ id: "off", default_mode: "disabled" })]);
    renderAt("off");

    expect(await screen.findByText("Disabled")).toBeInTheDocument();
    expect(screen.getByText(/this rule is off and produces nothing/)).toBeInTheDocument();
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
