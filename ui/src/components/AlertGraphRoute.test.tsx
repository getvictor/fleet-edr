import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { beforeAll, beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import * as api from "../api";
import type { AlertDetail, ProcessNode } from "../types";
import { AlertGraphRoute } from "./AlertGraphRoute";

// On success AlertGraphRoute renders the shared ProcessTreeView, which lays out a d3 tree. jsdom lacks the SVG geometry APIs d3 needs,
// so stub them exactly as ProcessTree.test.tsx does or a non-empty render throws.
beforeAll(() => {
  (SVGElement.prototype as unknown as { getBBox: () => DOMRect }).getBBox = () =>
    ({ x: 0, y: 0, width: 40, height: 12 }) as DOMRect;
  const dim = (value: number) => ({ baseVal: { value } });
  Object.defineProperty(SVGSVGElement.prototype, "width", { configurable: true, get: () => dim(800) });
  Object.defineProperty(SVGSVGElement.prototype, "height", { configurable: true, get: () => dim(600) });
  Element.prototype.scrollTo = () => { /* no-op in jsdom */ };
});

function process(id: number, pid: number, ppid: number, path: string): ProcessNode {
  return { id, host_id: "h1", pid, ppid, path, fork_time_ns: 1 };
}

const forest: ProcessNode[] = [
  { ...process(1, 100, 1, "/sbin/launchd"), children: [process(2, 200, 100, "/usr/local/bin/fleet-edr-agent")] },
];

const alert: AlertDetail = {
  id: 842,
  host_id: "h1",
  rule_id: "suspicious_exec",
  source: "detection",
  severity: "high",
  title: "Suspicious exec chain",
  description: "A suspicious exec chain fired",
  techniques: ["T1059"],
  process_id: 2,
  status: "open",
  created_at: "2026-06-18T12:00:00Z",
  updated_at: "2026-06-18T12:00:00Z",
  event_ids: ["evt-1"],
};

function renderRoute() {
  return render(
    <MemoryRouter initialEntries={["/alerts/842"]}>
      <Routes>
        <Route path="/alerts/:alertId" element={<AlertGraphRoute />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // ProcessTreeView fetches the tree and this host's alerts on mount; resolve both to empty/known shapes so it renders.
  vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: forest });
  vi.spyOn(api, "listAlerts").mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AlertGraphRoute", () => {
  it("fetches the alert and renders the shared ProcessTreeView (breadcrumb + view tabs + host tree)", async () => {
    vi.spyOn(api, "getAlertDetail").mockResolvedValue(alert);
    renderRoute();

    // While the alert is in flight the minimal loading state shows (the loading branch).
    expect(screen.getByText(/loading alert/i)).toBeInTheDocument();

    // Once loaded, the alert breadcrumb (seeded from entryAlert) renders the alert title.
    expect(await screen.findByText("Suspicious exec chain")).toBeInTheDocument();
    // The shared ProcessTreeView chrome is present: the Graph/Timeline view tabs...
    expect(screen.getByRole("link", { name: "Graph" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Timeline" })).toBeInTheDocument();
    // ...and the host's process node from the tree fetch.
    expect(await screen.findByText(/fleet-edr-agent/)).toBeInTheDocument();
  });

  it("fetches by the alertId parsed from the route param", async () => {
    const spy = vi.spyOn(api, "getAlertDetail").mockResolvedValue(alert);
    renderRoute();
    await waitFor(() => { expect(spy).toHaveBeenCalledWith(842); });
  });

  it("renders a not-found message when the alert fetch rejects", async () => {
    vi.spyOn(api, "getAlertDetail").mockRejectedValue(new Error("not found"));
    renderRoute();
    expect(await screen.findByText(/alert not found/i)).toBeInTheDocument();
  });
});
