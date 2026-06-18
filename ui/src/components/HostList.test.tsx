import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { HostList } from "./HostList";
import * as api from "../api";
import type { HostSummary } from "../types";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";

// A last_seen this many ms ago decides online vs offline (HostList's threshold
// is 5 min). Build ns timestamps relative to now so isOnline is deterministic.
const minutesAgoNs = (mins: number): number =>
  (Date.now() - mins * 60 * 1000) * NANOSECONDS_PER_MILLISECOND;

const makeHost = (over: Partial<HostSummary> = {}): HostSummary => ({
  host_id: "UUID-DEFAULT",
  hostname: "host.local",
  os_version: "macOS 26.0",
  event_count: 1234,
  last_seen_ns: minutesAgoNs(1),
  ...over,
});

const renderList = () =>
  render(
    <MemoryRouter initialEntries={["/hosts"]}>
      <Routes>
        <Route path="/hosts" element={<HostList />} />
        <Route path="/hosts/:id" element={<div>detail page</div>} />
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.spyOn(api, "listHosts");
});

afterEach(() => {
  vi.restoreAllMocks();
});

const mockHosts = (hosts: HostSummary[]) => {
  (api.listHosts as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(hosts);
};

describe("HostList rendering", () => {
  it("shows the hostname over the full UUID when enrollment metadata exists", async () => {
    mockHosts([makeHost({ host_id: "F4A2-UUID", hostname: "ci-builder.local" })]);
    renderList();
    await waitFor(() => {
      expect(screen.getByText("ci-builder.local")).toBeInTheDocument();
    });
    // The full hardware UUID appears as the secondary line, not collapsed away.
    expect(screen.getByText("F4A2-UUID")).toBeInTheDocument();
  });

  it("falls back to the UUID as the primary line when hostname is empty", async () => {
    mockHosts([makeHost({ host_id: "BARE-UUID", hostname: "" })]);
    renderList();
    await waitFor(() => {
      expect(screen.getByText("BARE-UUID")).toBeInTheDocument();
    });
    // Only one line is rendered: the UUID is the hostname element, no separate uuid line.
    expect(document.querySelector(".host-list__uuid")).not.toBeInTheDocument();
  });

  it("formats the event count with thousands separators in a right-aligned column", async () => {
    mockHosts([makeHost({ event_count: 128944 })]);
    renderList();
    const cell = await screen.findByText("128,944");
    expect(cell).toHaveClass("host-list__events-col");
  });
});

describe("HostList summary strip", () => {
  // spec:web-ui/host-list-is-the-home-view/host-list-shows-hostname-and-a-fleet-summary
  it("counts online, offline and total hosts", async () => {
    mockHosts([
      makeHost({ host_id: "a", last_seen_ns: minutesAgoNs(1) }), // online
      makeHost({ host_id: "b", last_seen_ns: minutesAgoNs(2) }), // online
      makeHost({ host_id: "c", last_seen_ns: minutesAgoNs(30) }), // offline
    ]);
    renderList();
    const strip = await waitFor(() => {
      const el = document.querySelector(".summary-strip");
      expect(el).toBeInTheDocument();
      return el as HTMLElement;
    });
    const cardFor = (label: string) =>
      within(strip).getByText(label).closest(".stat-card") as HTMLElement;
    expect(within(cardFor("Online")).getByText("2")).toBeInTheDocument();
    expect(within(cardFor("Offline")).getByText("1")).toBeInTheDocument();
    expect(within(cardFor("Total hosts")).getByText("3")).toBeInTheDocument();
  });
});

describe("HostList navigation", () => {
  it("navigates to the host detail route on row click", async () => {
    mockHosts([makeHost({ host_id: "click-me", hostname: "click.local" })]);
    renderList();
    const row = (await screen.findByText("click.local")).closest("tr");
    expect(row).not.toBeNull();
    fireEvent.click(row as HTMLElement);
    await waitFor(() => {
      expect(screen.getByText("detail page")).toBeInTheDocument();
    });
  });
});

describe("HostList states", () => {
  it("shows the empty state when no hosts report", async () => {
    mockHosts([]);
    renderList();
    await waitFor(() => {
      expect(screen.getByText(/no hosts reporting yet/i)).toBeInTheDocument();
    });
  });

  it("surfaces fetch failures", async () => {
    (api.listHosts as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("boom"));
    renderList();
    await waitFor(() => {
      expect(screen.getByText(/error: boom/i)).toBeInTheDocument();
    });
  });
});
