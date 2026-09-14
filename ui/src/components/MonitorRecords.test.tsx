import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { MonitorRecords } from "./MonitorRecords";
import * as api from "../api";
import type { Alert } from "../types";

const rule = "proc_creation_macos_remote_access_tools_teamviewer_incoming_connection";

const makeRecord = (over: Partial<Alert> = {}): Alert => ({
  id: 377,
  host_id: "host-a",
  rule_id: rule,
  source: "detection",
  severity: "low",
  title: "Team Viewer Session Started On MacOS Host",
  description: "",
  process_id: 98446,
  status: "open",
  disposition: "monitor",
  origin: "SigmaHQ, by Josh Nickels, Qi Nan",
  created_at: "2026-09-13T05:38:34Z",
  updated_at: "2026-09-13T05:38:34Z",
  ...over,
});

function renderPage(ruleID: string = rule) {
  return render(
    <MemoryRouter initialEntries={[`/rules/${encodeURIComponent(ruleID)}/monitor-records`]}>
      <Routes>
        <Route path="/rules/:ruleId/monitor-records" element={<MonitorRecords />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // The page resolves hostnames the way the Alerts page does; stub the host list so these tests stay off the network.
  vi.spyOn(api, "listHosts").mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("MonitorRecords", () => {
  // spec:web-ui/monitor-records-are-reachable-from-the-observed-count/an-operator-opens-the-records-behind-a-count
  it("asks for this rule's monitor records and links each to its investigation surface", async () => {
    const list = vi.spyOn(api, "listAlerts").mockResolvedValue([
      makeRecord({ id: 378, created_at: "2026-09-13T05:40:00Z" }),
      makeRecord({ id: 377 }),
    ]);
    renderPage();

    const table = await screen.findByRole("table");
    // Monitor records, for exactly this rule. Without the disposition the server serves alerts, and the page would list the wrong
    // kind of row under a heading that says otherwise.
    expect(list).toHaveBeenCalledWith({ disposition: "monitor", rule_id: rule, limit: 101 });
    const links = within(table).getAllByRole("link", { name: /Team Viewer Session Started/ });
    expect(links.map((l) => l.getAttribute("href"))).toEqual(["/alerts/378", "/alerts/377"]);
    // The licence credit rides every surface showing a match, and a monitor record is a match.
    expect(within(table).getAllByText("SigmaHQ, by Josh Nickels, Qi Nan")).toHaveLength(2);
  });

  // spec:web-ui/monitor-records-are-reachable-from-the-observed-count/the-records-view-explains-why-it-can-show-fewer-than-the-count
  it("explains that records are not alerts and can be fewer than the count", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue([makeRecord()]);
    renderPage();

    await screen.findByRole("table");
    const explanation = screen.getByText(/These are not alerts/);
    expect(explanation).toBeVisible();
    expect(explanation).toHaveTextContent(/fewer records than the rule's Observed count/);
    expect(explanation).toHaveTextContent(/retention window, 7 days by default/);
  });

  // spec:web-ui/a-detect-rule-can-be-promoted-with-its-impact-in-view/app-control-records-read-as-would-block-runs
  it("explains an application-control rule's records as executables it would have blocked", async () => {
    const listSpy = vi.spyOn(api, "listAlerts").mockResolvedValue([
      makeRecord({ rule_id: "app_control:7", source: "application_control", origin: "", title: "Application would be blocked: tool" }),
    ]);
    renderPage("app_control:7");

    await screen.findByRole("table");
    expect(listSpy).toHaveBeenCalledWith(expect.objectContaining({ disposition: "monitor", rule_id: "app_control:7" }));
    const explanation = screen.getByText(/would have blocked while it ran in Detect mode/);
    expect(explanation).toBeVisible();
    expect(explanation).not.toHaveTextContent(/Observed/);
  });

  // spec:web-ui/monitor-records-are-reachable-from-the-observed-count/a-monitor-record-offers-no-triage
  it("offers no triage on the list", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue([makeRecord()]);
    renderPage();

    await screen.findByRole("table");
    expect(screen.queryByRole("button", { name: /acknowledge|resolve|reopen/i })).toBeNull();
    expect(screen.queryByRole("columnheader", { name: /status|actions/i })).toBeNull();
  });

  it("says why a rule with a count can have no records", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText(/No monitor records for this rule/)).toBeVisible();
    expect(screen.getByText(/aged out/)).toBeVisible();
  });

  // A failed read must not read as "this rule has no records", which is the conclusion an operator would promote on.
  it("reports a failed read as a failure, not as an empty list", async () => {
    vi.spyOn(api, "listAlerts").mockRejectedValue(new Error("boom"));
    renderPage();

    expect(await screen.findByText(/Monitor records could not be loaded: boom/)).toBeVisible();
    expect(screen.queryByText(/No monitor records for this rule/)).toBeNull();
  });

  // The page asks for one row past what it shows, so the notice rests on a row that exists. A rule with exactly a page of records is
  // complete, and telling its operator some were left out would send them looking for records that do not exist.
  it("says it is showing only the newest records when more exist", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue(Array.from({ length: 101 }, (_, i) => makeRecord({ id: 1000 + i })));
    renderPage();

    expect(await screen.findByText("Showing the 100 most recent records.")).toBeVisible();
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(101); // header plus the 100 shown
  });

  it("does not claim truncation for exactly a page of records", async () => {
    vi.spyOn(api, "listAlerts").mockResolvedValue(Array.from({ length: 100 }, (_, i) => makeRecord({ id: 1000 + i })));
    renderPage();

    await screen.findByRole("table");
    expect(screen.queryByText(/most recent records/)).toBeNull();
  });
});
