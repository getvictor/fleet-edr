import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { RulesCatalog } from "./RulesCatalog";
import { PermissionsProvider } from "../permissions";
import { PermissionAction } from "../permissions-core";
import * as api from "../api";
import type { RuleDocEntry } from "../api";

function rule(id: string, title: string, over: Partial<RuleDocEntry> = {}): RuleDocEntry {
  return {
    id,
    techniques: [],
    doc: { title, summary: "", description: "", severity: "high", event_types: ["exec"] },
    ...over,
  };
}

const rules: RuleDocEntry[] = [
  rule("suspicious_exec", "Suspicious exec chain", { origin: "Fleet EDR", mode: "alert", mode_source: "default" }),
  rule("keychain_extra", "Keychain extra", { origin: "Locally authored", mode: "monitor", mode_source: "default" }),
  // An older replica mid-upgrade reports neither the mode in force nor an origin.
  rule("legacy_rule", "Legacy rule", { default_mode: "monitor" }),
  rule("proc_creation_macos_curl", "Curl download", {
    origin: "SigmaHQ, by Someone",
    mode: "alert",
    mode_source: "setting",
    doc: { title: "Curl download", summary: "", description: "", severity: "low", event_types: ["exec"] },
  }),
];

function renderCatalog(permissions: string[] = [PermissionAction.RuleContentRead]) {
  return render(
    <PermissionsProvider permissions={permissions}>
      <MemoryRouter>
        <RulesCatalog />
      </MemoryRouter>
    </PermissionsProvider>,
  );
}

beforeEach(() => {
  vi.spyOn(api, "getRulePackStatus").mockResolvedValue({
    installed: "p", available: "p", previous: "", declined: "", current: true, can_roll_back: false, added: [], removed: [], changed: [],
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("RulesCatalog", () => {
  // spec:web-ui/the-rule-catalogue-is-browsable/an-operator-browses-the-rules-the-deployment-runs
  it("lists every rule by name with its identifier, severity, and mode, linking to its detail", async () => {
    vi.spyOn(api, "fetchRuleDocs").mockResolvedValue(rules);
    renderCatalog();

    const table = await screen.findByRole("table");
    const names = within(table).getAllByRole("link").map((l) => l.textContent);
    expect(names).toEqual(["Curl download", "Keychain extra", "Legacy rule", "Suspicious exec chain"]);
    expect(within(table).getByRole("link", { name: "Keychain extra" })).toHaveAttribute("href", "/rules/keychain_extra");
    expect(within(table).getByText("keychain_extra")).toBeVisible();
    const curlRow = within(table).getByRole("link", { name: "Curl download" }).closest("tr") as HTMLElement;
    expect(within(curlRow).getByText("low")).toBeVisible();
    // A mode an operator chose is marked, because a rule sitting in its own default and one moved there call for different follow-ups.
    expect(within(curlRow).getByText("Alert (set)")).toBeVisible();
    expect(screen.getByText("4 rules, 1 written on this deployment.")).toBeVisible();
    // Without a reported mode, the rule's declaration is not presented as the mode in force.
    const legacyRow = within(table).getByRole("link", { name: "Legacy rule" }).closest("tr") as HTMLElement;
    expect(within(legacyRow).getAllByText("Unknown")).toHaveLength(2);
    expect(within(legacyRow).queryByText("Monitor")).toBeNull();
  });

  // spec:web-ui/the-rule-catalogue-is-browsable/the-catalogue-distinguishes-shipped-rules-from-the-deployment-s-own
  it("marks the deployment's own rules apart from shipped ones, crediting shipped authors", async () => {
    vi.spyOn(api, "fetchRuleDocs").mockResolvedValue(rules);
    renderCatalog();

    const table = await screen.findByRole("table");
    const ownRow = within(table).getByRole("link", { name: "Keychain extra" }).closest("tr") as HTMLElement;
    expect(within(ownRow).getByText("Yours")).toBeVisible();
    const vendoredRow = within(table).getByRole("link", { name: "Curl download" }).closest("tr") as HTMLElement;
    expect(within(vendoredRow).getByText("Shipped")).toBeVisible();
    expect(within(vendoredRow).getByText("SigmaHQ, by Someone")).toBeVisible();

    fireEvent.change(screen.getByLabelText("Show:"), { target: { value: "yours" } });
    expect(within(screen.getByRole("table")).getAllByRole("link").map((l) => l.textContent)).toEqual(["Keychain extra"]);
    fireEvent.change(screen.getByLabelText("Show:"), { target: { value: "shipped" } });
    const shipped = within(screen.getByRole("table")).getAllByRole("link").map((l) => l.textContent);
    // A rule whose origin the server did not report is neither shipped nor yours.
    expect(shipped).toEqual(["Curl download", "Suspicious exec chain"]);
  });

  it("filters by name or identifier", async () => {
    vi.spyOn(api, "fetchRuleDocs").mockResolvedValue(rules);
    renderCatalog();

    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText("Search:"), { target: { value: "macos_curl" } });
    expect(within(screen.getByRole("table")).getAllByRole("link").map((l) => l.textContent)).toEqual(["Curl download"]);
    fireEvent.change(screen.getByLabelText("Search:"), { target: { value: "no such rule" } });
    expect(screen.getByText("No rules match.")).toBeVisible();
  });

  // spec:web-ui/rules-can-be-written-in-the-console/an-operator-deletes-a-rule-with-a-reason
  it("offers New rule only to an operator who may write rules", async () => {
    vi.spyOn(api, "fetchRuleDocs").mockResolvedValue(rules);
    const { unmount } = renderCatalog();
    await screen.findByRole("table");
    expect(screen.queryByRole("link", { name: "New rule" })).toBeNull();
    unmount();

    renderCatalog([PermissionAction.RuleContentRead, PermissionAction.RuleContentWrite]);
    expect(await screen.findByRole("link", { name: "New rule" })).toHaveAttribute("href", "/rules/new");
  });

  it("reports a failed load rather than an empty catalogue", async () => {
    vi.spyOn(api, "fetchRuleDocs").mockRejectedValue(new Error("boom"));
    renderCatalog();

    expect(await screen.findByText("Rules could not be loaded: boom")).toBeVisible();
    expect(screen.queryByText("No rules match.")).toBeNull();
  });
});
