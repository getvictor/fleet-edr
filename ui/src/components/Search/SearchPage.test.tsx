import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

import { SearchPage } from "./SearchPage";
import * as api from "../../api";
import type { HostSummary, Process } from "../../types";

function proc(over: Partial<Process> = {}): Process {
  return { id: 1, host_id: "H1", pid: 100, ppid: 1, path: "/usr/bin/grep", fork_time_ns: 1_000_000_000, ...over };
}

function host(id: string, name: string): HostSummary {
  return { host_id: id, hostname: name, os_version: "26.4", platform: "darwin", event_count: 0, last_seen_ns: 0, overall_status: "unknown" };
}

function renderSearch(initial = "/search?path=grep") {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/search" element={<SearchPage />} />
        <Route path="/hosts/:hostId" element={<div>HOST TREE</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => { vi.restoreAllMocks(); });

describe("SearchPage", () => {
  // spec:web-ui/fleet-wide-search-page/search-renders-matches-with-a-total-and-host-names
  it("renders matches with the total and resolved host names", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({
      rows: [proc({ id: 1, host_id: "H1", args: ["grep", "-r", "x"] }), proc({ id: 2, host_id: "H2", pid: 200 })],
      total_matched: 2,
    });
    vi.spyOn(api, "listHosts").mockResolvedValue([host("H1", "mac-a.local"), host("H2", "mac-b.local")]);

    renderSearch();
    expect(await screen.findByText("mac-a.local")).toBeInTheDocument();
    expect(screen.getByText("mac-b.local")).toBeInTheDocument();
    expect(screen.getByText("grep -r x")).toBeInTheDocument();
    expect(screen.getByText(/Showing 2 of 2 matches/)).toBeInTheDocument();
  });

  it("passes the URL filters to the search call", async () => {
    const spy = vi.spyOn(api, "searchProcesses").mockResolvedValue({ rows: [], total_matched: 0 });
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    renderSearch("/search?signing=unsigned&uid=0");
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    expect(spy.mock.calls[0][0]).toMatchObject({ signing: "unsigned", uid: "0" });
  });

  // spec:web-ui/fleet-wide-search-page/load-more-appends-the-next-page
  it("appends the next page on load more", async () => {
    const spy = vi.spyOn(api, "searchProcesses")
      .mockResolvedValueOnce({ rows: [proc({ id: 1 })], next_cursor: "c1", total_matched: 2 })
      .mockResolvedValueOnce({ rows: [proc({ id: 2, pid: 200 })], total_matched: 2 });
    vi.spyOn(api, "listHosts").mockResolvedValue([host("H1", "mac-a.local")]);

    renderSearch();
    await screen.findByText(/Showing 1 of 2/);
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => { expect(screen.getByText(/Showing 2 of 2/)).toBeInTheDocument(); });
    expect(spy.mock.calls[1][1]).toBe("c1"); // second call carried the cursor
    expect(screen.queryByRole("button", { name: "Load more" })).not.toBeInTheDocument();
  });

  // spec:web-ui/fleet-wide-search-page/a-result-row-opens-the-host-tree-at-the-process
  it("links a result row to the host tree anchored at the process", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({ rows: [proc({ id: 77, host_id: "H1", pid: 100, exec_time_ns: 2_000_000_000, fork_time_ns: 2_000_000_000 })], total_matched: 1 });
    vi.spyOn(api, "listHosts").mockResolvedValue([host("H1", "mac-a.local")]);
    renderSearch();
    const link = await screen.findByRole("link", { name: "grep" });
    // ?process= is the process DB row id (id=77), not the OS pid (100), matching the tree's findNodeByDbId lookup.
    expect(link).toHaveAttribute("href", "/hosts/H1?process=77&at=2000");
  });

  it("falls back to the host id and shows no verdict for a fork-only row", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({
      rows: [proc({ id: 1, host_id: "UNKNOWN-HOST", exec_time_ns: undefined })],
      total_matched: 1,
    });
    vi.spyOn(api, "listHosts").mockResolvedValue([]); // no hostname known
    renderSearch();
    expect(await screen.findByText("UNKNOWN-HOST")).toBeInTheDocument(); // id shown when hostname absent
    expect(screen.queryByText("unsigned")).not.toBeInTheDocument(); // fork-only: no verdict badge
  });

  it("surfaces a search error", async () => {
    vi.spyOn(api, "searchProcesses").mockRejectedValue(new Error("boom"));
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    renderSearch();
    expect(await screen.findByText("Error: boom")).toBeInTheDocument();
  });

  // spec:web-ui/fleet-wide-search-page/removing-a-chip-drops-that-filter
  it("removing a chip refetches without that filter", async () => {
    const spy = vi.spyOn(api, "searchProcesses").mockResolvedValue({ rows: [proc()], total_matched: 1 });
    vi.spyOn(api, "listHosts").mockResolvedValue([host("H1", "mac-a.local")]);
    renderSearch("/search?path=grep&signing=unsigned");
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    fireEvent.click(screen.getByRole("button", { name: "Remove Path filter" }));
    await waitFor(() => {
      expect(spy.mock.calls.some(([f]) => !("path" in f) && f.signing === "unsigned")).toBe(true);
    });
  });

  it("shows the empty state when there are no matches", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({ rows: [], total_matched: 0 });
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    renderSearch();
    expect(await screen.findByText("No matching processes.")).toBeInTheDocument();
  });
});

describe("SearchPage mode selector", () => {
  it("defaults to process mode and marks it current", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({ rows: [], total_matched: 0 });
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    renderSearch("/search");
    await waitFor(() => { expect(screen.getByRole("link", { name: "Processes" })).toHaveAttribute("aria-current", "page"); });
    expect(screen.getByRole("link", { name: "Connections" })).not.toHaveAttribute("aria-current");
  });

  it("switches to connection mode and prompts without issuing an event search", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({ rows: [], total_matched: 0 });
    const evtSpy = vi.spyOn(api, "searchEvents").mockResolvedValue({ events: [], total_matched: 0 });
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    renderSearch("/search");
    fireEvent.click(screen.getByRole("link", { name: "Connections" }));
    expect(await screen.findByText(/Enter a remote address/i)).toBeInTheDocument();
    expect(evtSpy).not.toHaveBeenCalled(); // no artifact value yet -> no request
    expect(screen.getByRole("link", { name: "Connections" })).toHaveAttribute("aria-current", "page");
  });

  it("renders DNS mode from a ?mode=dns URL", async () => {
    vi.spyOn(api, "searchEvents").mockResolvedValue({ events: [], total_matched: 0 });
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    renderSearch("/search?mode=dns");
    expect(await screen.findByText(/Enter a domain/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "DNS" })).toHaveAttribute("aria-current", "page");
  });
});
