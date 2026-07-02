import { render, screen, fireEvent, waitFor } from "@testing-library/react";
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
  // d3-zoom's defaultExtent reads width.baseVal.value / height.baseVal.value off the <svg>; jsdom implements neither, so a
  // non-empty tree render throws. Stub benign dimensions so the zoom-attach path survives when we actually lay out a forest.
  const dim = (value: number) => ({ baseVal: { value } });
  Object.defineProperty(SVGSVGElement.prototype, "width", { configurable: true, get: () => dim(800) });
  Object.defineProperty(SVGSVGElement.prototype, "height", { configurable: true, get: () => dim(600) });
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
    // Single control: the generic breadcrumb chain toggle is hidden for process-optional alerts, leaving only the info-bar
    // button below, so the analyst isn't faced with two controls that do the same thing.
    expect(screen.queryByRole("button", { name: /full host tree|focused on chain/i })).not.toBeInTheDocument();
  });

  it("widens and collapses via the single info-bar control", async () => {
    // Empty host tree so widening doesn't trigger the d3/SVG render path (jsdom lacks the SVG geometry APIs d3 needs); the
    // assertion is about the focus state flipping, not about drawing the forest.
    vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: [] });
    vi.spyOn(api, "getAlertDetail").mockResolvedValue(launchDaemonAlert);
    renderTree("?alert=7&process=0&at=1750248000000");

    const widen = await screen.findByRole("button", { name: /show surrounding host activity/i });
    fireEvent.click(widen);

    // After widening: the explanation is gone and the single control flips to a collapse-back affordance.
    const collapse = await screen.findByRole("button", { name: /show alert detail only/i });
    expect(collapse).toBeInTheDocument();
    expect(screen.queryByText(/isn’t attributed to a single process/i)).not.toBeInTheDocument();

    // Collapsing returns to the explanation, and there is never a second (breadcrumb) chain toggle.
    fireEvent.click(collapse);
    expect(await screen.findByText(/isn’t attributed to a single process/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /full host tree|focused on chain/i })).not.toBeInTheDocument();
  });

  it("still explains the alert (no blank canvas) when getAlertDetail fails", async () => {
    // The focus filter empties the forest from ?process=0 on mount, before (or even if never) alertDetail loads. Keying the
    // process-optional classification on the URL param means the explanation still renders, so a slow or failed
    // getAlertDetail never leaves a silent blank canvas. Regression guard for the Gemini/Qodo race finding on PR #466.
    vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: forest });
    vi.spyOn(api, "getAlertDetail").mockRejectedValue(new Error("alert detail unavailable"));
    renderTree("?alert=7&process=0&at=1750248000000");

    expect(await screen.findByText(/isn’t attributed to a single process/i)).toBeInTheDocument();
    expect(screen.queryByText(/No processes in this time range/i)).not.toBeInTheDocument();
  });
});

// spec:web-ui/process-tree-visualization/repeated-siblings-render-as-an-aggregated-badge
//
// Issue #416: the server collapses repeated identical-path siblings into one node carrying a count. The tree MUST render that as a
// "×N" badge, expand it in place to the sample on click, and expose a Flatten toggle that refetches the raw (un-aggregated) forest.
describe("ProcessTreeView sibling aggregation", () => {
  const aggregatedChild: ProcessNode = {
    ...process(10, 200, 100, "/usr/bin/grep"),
    fork_time_ns: 1000,
    aggregated: {
      count: 3,
      exited_count: 2,
      running_count: 1,
      first_fork_ns: 1000,
      last_fork_ns: 3000,
      sample: [
        { ...process(10, 200, 100, "/usr/bin/grep"), fork_time_ns: 1000 },
        { ...process(11, 201, 100, "/usr/bin/grep"), fork_time_ns: 2000 },
      ],
    },
  };
  const aggregatedForest: ProcessNode[] = [
    { ...process(1, 100, 1, "/bin/bash"), children: [aggregatedChild] },
  ];

  beforeEach(() => {
    // Flatten/showSystem persist to localStorage; clear it so a prior test's toggle can't leak into this render.
    localStorage.clear();
    vi.spyOn(api, "getAlertDetail").mockResolvedValue(launchDaemonAlert);
  });

  it("renders a ×N badge for an aggregated group and expands to the sample on click", async () => {
    vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: aggregatedForest });
    renderTree("");

    // The aggregated node reads as a group header, not a single pid.
    const badge = await screen.findByText(/grep ×3/);
    expect(badge).toBeInTheDocument();
    // The underlying members are not shown until the node is expanded.
    expect(screen.queryByText(/grep \(201\)/)).not.toBeInTheDocument();

    fireEvent.click(badge);

    // Expanding materializes the capped sample as children in place.
    expect(await screen.findByText(/grep \(201\)/)).toBeInTheDocument();
  });

  it("expands via the chevron and collapses on a second activation", async () => {
    vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: aggregatedForest });
    const { container } = renderTree("");
    await screen.findByText(/grep ×3/);

    // The aggregated node ships collapsed, so its chevron is the only "▶" in this single-group forest. Clicking the chevron
    // (not the label) exercises the chevron-side expand path.
    const collapsedChevron = [...container.querySelectorAll("text.node__chevron")].find((c) => c.textContent === "▶");
    expect(collapsedChevron).toBeTruthy();
    fireEvent.click(collapsedChevron as Element);
    expect(await screen.findByText(/grep \(201\)/)).toBeInTheDocument();

    // A second activation collapses the group again (the toggle's delete branch).
    fireEvent.click(screen.getByText(/grep ×3/));
    await waitFor(() => { expect(screen.queryByText(/grep \(201\)/)).not.toBeInTheDocument(); });
  });

  it("Flatten toggle refetches the raw forest with flatten=true", async () => {
    const spy = vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: aggregatedForest });
    renderTree("");
    await screen.findByText(/grep ×3/);

    // Initial fetch is aggregated (flatten falsy).
    expect(spy).toHaveBeenLastCalledWith("h1", expect.any(Number), expect.any(Number), undefined, false);

    fireEvent.click(screen.getByLabelText("Flatten"));

    // Flipping the toggle refetches asking for the un-aggregated forest.
    expect(spy).toHaveBeenLastCalledWith("h1", expect.any(Number), expect.any(Number), undefined, true);
  });

  it("selects a normal process, colors an alerted and an exited node, and toggles a normal chevron", async () => {
    // A forest mixing the aggregated group with two plain leaves: one alerted (red dot), one exited (grey dot). Bash is a normal
    // parent so its chevron drives the generic subtree collapse, distinct from the aggregated expand.
    const alertedLeaf: ProcessNode = { ...process(30, 300, 100, "/usr/bin/curl"), fork_time_ns: 100 };
    const exitedLeaf: ProcessNode = { ...process(20, 500, 100, "/usr/bin/sleep"), fork_time_ns: 100, exit_time_ns: 200 };
    const forest: ProcessNode[] = [
      { ...process(1, 100, 1, "/bin/bash"), children: [aggregatedChild, alertedLeaf, exitedLeaf] },
    ];
    vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: forest });
    // Alert on the curl leaf so alertProcessIds drives its red dot.
    vi.spyOn(api, "listAlerts").mockResolvedValue([
      { id: 1, host_id: "h1", rule_id: "r", source: "detection", severity: "high", title: "t", description: "",
        process_id: 30, status: "open", created_at: "", updated_at: "" },
    ]);
    vi.spyOn(api, "getProcessDetail").mockResolvedValue({ process: exitedLeaf, network_connections: [], dns_queries: [] });

    const { container } = renderTree("");
    await screen.findByText(/curl \(300\)/);

    // Clicking a normal (non-aggregated) node opens the detail panel rather than expanding.
    fireEvent.click(screen.getByText(/sleep \(500\)/));
    await screen.findByText(/curl \(300\)/); // still rendered; selection does not collapse the tree

    // Toggling bash's chevron collapses its subtree (the generic collapse path, not the aggregated one).
    const chevrons = container.querySelectorAll("text.node__chevron");
    expect(chevrons.length).toBeGreaterThan(0);
    fireEvent.click(chevrons[0]);
    await waitFor(() => { expect(screen.queryByText(/curl \(300\)/)).not.toBeInTheDocument(); });
  });
});

describe("ProcessTreeView process-backed alert", () => {
  it("keys the explanation on process_id === 0, not on an empty graph", async () => {
    // An attributed alert (process_id !== 0) whose target happens to be outside the loaded window: the graph is empty, but
    // the process-optional explanation must NOT appear. This guards the regression that the explanation is gated on
    // process-optional-ness, not merely on "the focused chain came back empty".
    // Empty host tree so toggling focus off doesn't trigger the d3/SVG render path (jsdom lacks the SVG geometry APIs).
    vi.spyOn(api, "getProcessTree").mockResolvedValue({ roots: [] });
    vi.spyOn(api, "getAlertDetail").mockResolvedValue({
      ...launchDaemonAlert,
      rule_id: "suspicious_exec",
      title: "Suspicious exec chain",
      process_id: 99,
    });
    renderTree("?alert=7&process=99&at=1750248000000");

    // The finding detail still renders for a process-backed alert.
    expect(await screen.findByText(/registered as system LaunchDaemon/i)).toBeInTheDocument();
    // But the process-optional explanation must not appear.
    expect(screen.queryByText(/isn’t attributed to a single process/i)).not.toBeInTheDocument();

    // The generic chain toggle IS present for a process-backed alert (it is only hidden for process-optional ones), and it
    // is a state label that flips between "Focused on chain" and "Full host tree" rather than reading as a stale action.
    const toggle = screen.getByRole("button", { name: /focused on chain/i });
    fireEvent.click(toggle);
    expect(await screen.findByRole("button", { name: /full host tree/i })).toBeInTheDocument();
  });
});
