import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { beforeAll, beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import * as api from "../api";
import type { AlertDetail, ProcessNode } from "../types";
import { ProcessTreeView } from "./ProcessTree";

// spec:web-ui/alert-pivots-to-the-host-process-tree/operator-pivots-from-a-process-optional-alert
//
// Covers the process-optional alert pivot: a finding with process_id === 0 (e.g. LaunchDaemon persistence, where the BTM
// instigator is Apple's smd, not the actor) opens with no attributed process node. The receiving page MUST render the
// finding detail (description + technique tags) and an explicit explanation instead of a silent blank canvas, with an
// opt-in to widen to the surrounding host activity. A normal (process-backed) alert MUST still focus its chain.

// d3 calls SVGElement.getBBox to size label backgrounds; jsdom does not implement it. Stub a benign box so the render
// effect doesn't throw when a tree is laid out.
beforeAll(() => {
  (SVGElement.prototype as unknown as { getBBox: () => DOMRect }).getBBox = () =>
    ({ x: 0, y: 0, width: 40, height: 12 }) as DOMRect;
});

function process(id: number, pid: number, ppid: number, path: string): ProcessNode {
  return { id, host_id: "h1", pid, ppid, path, fork_time_ns: 1 };
}

const forest: ProcessNode[] = [
  { ...process(1, 100, 1, "/sbin/launchd"), children: [process(2, 200, 100, "/usr/local/bin/fleet-edr-agent")] },
];

const launchDaemonAlert: AlertDetail = {
  id: 7,
  host_id: "h1",
  rule_id: "privilege_launchd_plist_write",
  source: "detection",
  severity: "high",
  title: "LaunchDaemon persistence",
  description:
    "Untrusted executable /usr/local/bin/fleet-edr-agent registered as system LaunchDaemon " +
    "com.fleetdm.edr.agent.plist: persistence (MITRE T1543.004)",
  techniques: ["T1543.004"],
  process_id: 0,
  status: "open",
  created_at: "2026-06-18T12:00:00Z",
  updated_at: "2026-06-18T12:00:00Z",
  event_ids: ["evt-1"],
};

function renderTree(search: string) {
  return render(
    <MemoryRouter initialEntries={[`/hosts/h1${search}`]}>
      <Routes>
        <Route path="/hosts/:hostId" element={<ProcessTreeView />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: forest });
  vi.spyOn(api, "listAlerts").mockResolvedValue([]);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ProcessTreeView process-optional alert", () => {
  it("renders the finding detail and an explanatory empty state instead of a blank canvas", async () => {
    vi.spyOn(api, "getAlertDetail").mockResolvedValue(launchDaemonAlert);
    renderTree("?alert=7&process=0&at=1750248000000");

    // The finding description (the what + why) is rendered.
    expect(await screen.findByText(/registered as system LaunchDaemon/i)).toBeInTheDocument();
    // The MITRE technique tag is rendered.
    expect(screen.getByText("T1543.004")).toBeInTheDocument();
    // The explicit explanation replaces the silent blank canvas.
    expect(screen.getByText(/isn’t attributed to a single process/i)).toBeInTheDocument();
    // The generic "no processes" message must NOT be what the analyst sees here.
    expect(screen.queryByText(/No processes in this time range/i)).not.toBeInTheDocument();
  });

  it("offers an opt-in that widens out of the focused (empty) view", async () => {
    // Empty host tree so widening doesn't trigger the d3/SVG render path (jsdom lacks the SVG geometry APIs d3 needs); the
    // assertion is about the focus state flipping off, not about drawing the forest.
    vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: [] });
    vi.spyOn(api, "getAlertDetail").mockResolvedValue(launchDaemonAlert);
    renderTree("?alert=7&process=0&at=1750248000000");

    const widen = await screen.findByRole("button", { name: /show surrounding host activity/i });
    fireEvent.click(widen);

    // After opting in, focus mode is off so the process-optional explanation is gone.
    await waitFor(() => {
      expect(screen.queryByText(/isn’t attributed to a single process/i)).not.toBeInTheDocument();
    });
  });
});

describe("ProcessTreeView process-backed alert", () => {
  it("keys the explanation on process_id === 0, not on an empty graph", async () => {
    // An attributed alert (process_id !== 0) whose target happens to be outside the loaded window: the graph is empty, but
    // the process-optional explanation must NOT appear. This guards the regression that the explanation is gated on
    // process-optional-ness, not merely on "the focused chain came back empty".
    vi.spyOn(api, "getAlertDetail").mockResolvedValue({
      ...launchDaemonAlert,
      rule_id: "suspicious_exec",
      title: "Shell spawn with outbound network connection",
      process_id: 99,
    });
    renderTree("?alert=7&process=99&at=1750248000000");

    // The finding detail still renders for a process-backed alert.
    expect(await screen.findByText(/registered as system LaunchDaemon/i)).toBeInTheDocument();
    // But the process-optional explanation must not appear.
    expect(screen.queryByText(/isn’t attributed to a single process/i)).not.toBeInTheDocument();
  });
});
