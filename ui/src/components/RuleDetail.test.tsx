import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
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
      config: [
        { env_var: "EDR_FOO", type: "bool", default: "", description: "toggle foo" },
        { env_var: "EDR_BAR", type: "int", default: "5", description: "bar threshold" },
      ],
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
  (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(entries);

describe("RuleDetail loading and error states", () => {
  it("shows the loading state before the docs resolve", () => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => { /* never resolves */ }));
    renderAt("suspicious_exec");
    expect(screen.getByText(/loading rule documentation/i)).toBeInTheDocument();
  });

  it("surfaces a fetch failure as an alert", async () => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("boom"));
    renderAt("suspicious_exec");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/boom/i));
  });

  it("falls back to a generic message for a non-Error rejection", async () => {
    (api.fetchRuleDocs as unknown as ReturnType<typeof vi.fn>).mockRejectedValue("nope");
    renderAt("suspicious_exec");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/failed to load rule docs/i));
  });

  it("renders the unknown-rule empty state with a back link when the id is not found", async () => {
    mockDocs([makeEntry({ id: "other_rule" })]);
    renderAt("missing_rule");
    await waitFor(() => expect(screen.getByText(/unknown rule/i)).toBeInTheDocument());
    expect(screen.getByText("missing_rule", { selector: "code" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to coverage/i })).toHaveAttribute("href", "/coverage");
  });
});

describe("RuleDetail body", () => {
  it("renders the title, summary, ATT&CK link, and split description paragraphs", async () => {
    mockDocs([makeEntry()]);
    renderAt("suspicious_exec");
    await waitFor(() => expect(screen.getByText("Suspicious exec")).toBeInTheDocument());
    expect(screen.getByText("Detects suspicious execution.")).toBeInTheDocument();
    expect(screen.getByText("First paragraph.")).toBeInTheDocument();
    expect(screen.getByText("Second paragraph.")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "T1059.004" });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/004/");
  });

  it("renders the config table, marking an empty default as (unset)", async () => {
    mockDocs([makeEntry()]);
    renderAt("suspicious_exec");
    await waitFor(() => expect(screen.getByText("Configuration")).toBeInTheDocument());
    expect(screen.getByText("EDR_FOO")).toBeInTheDocument();
    expect(screen.getByText("(unset)")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("renders the false-positive and limitations lists", async () => {
    mockDocs([makeEntry()]);
    renderAt("suspicious_exec");
    await waitFor(() => expect(screen.getByText("Known false-positive sources")).toBeInTheDocument());
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
    await waitFor(() => expect(screen.getByText("Bare rule")).toBeInTheDocument());
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
