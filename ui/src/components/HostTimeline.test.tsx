import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Link } from "react-router-dom";

import { HostTimeline } from "./HostTimeline";
import * as api from "../api";
import type { EventRecord } from "../types";

const BOUNDS = { fromNs: 1_000, toNs: 9_000 };

function execEvent(id: string, pid: number, path: string, ts = 1_000_000_000): EventRecord {
  return { event_id: id, host_id: "H1", timestamp_ns: ts, event_type: "exec", payload: { pid, path, args: [path] } };
}
function connEvent(id: string, pid: number, addr: string, port: number, ts = 2_000_000_000): EventRecord {
  return {
    event_id: id, host_id: "H1", timestamp_ns: ts, event_type: "network_connect",
    payload: { pid, path: "/usr/bin/curl", protocol: "tcp", direction: "outbound", remote_address: addr, remote_port: port },
  };
}
function dnsEvent(id: string, pid: number, name: string, ts = 3_000_000_000): EventRecord {
  return { event_id: id, host_id: "H1", timestamp_ns: ts, event_type: "dns_query", payload: { pid, query_name: name, query_type: "A", response_addresses: ["9.9.9.9"] } };
}

function renderTimeline(search = "", emphasizePid?: number) {
  return render(
    <MemoryRouter initialEntries={[`/hosts/H1${search}`]}>
      <HostTimeline hostId="H1" bounds={BOUNDS} emphasizePid={emphasizePid} />
    </MemoryRouter>,
  );
}

afterEach(() => { vi.restoreAllMocks(); });

describe("HostTimeline", () => {
  // spec:web-ui/host-event-timeline-view/timeline-view-lists-window-events-filterable-by-type
  it("lists interleaved events with type and originating process, and passes the window", async () => {
    const spy = vi.spyOn(api, "getHostTimeline").mockResolvedValue({
      events: [dnsEvent("d", 7, "evil.example"), connEvent("n", 42, "1.2.3.4", 443), execEvent("x", 42, "/bin/sh")],
      total_matched: 3,
    });
    renderTimeline();
    expect(await screen.findByText("evil.example A -> 9.9.9.9")).toBeInTheDocument();
    expect(screen.getByText("1.2.3.4:443", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("sh (42)")).toBeInTheDocument();
    expect(screen.getByText(/Showing 3 of 3/)).toBeInTheDocument();
    // The window bounds rode into the request.
    expect(spy.mock.calls[0][1]).toMatchObject({ from: "1000", to: "9000" });
  });

  // spec:web-ui/host-event-timeline-view/timeline-view-lists-window-events-filterable-by-type
  it("filters by event type when a chip is toggled", async () => {
    const spy = vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [], total_matched: 0 });
    renderTimeline();
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    fireEvent.click(screen.getByRole("button", { name: "DNS" }));
    await waitFor(() => {
      expect(spy.mock.calls.some(([, f]) => f.types?.length === 1 && f.types[0] === "dns_query")).toBe(true);
    });
  });

  // spec:web-ui/host-event-timeline-view/a-text-filter-narrows-the-timeline
  it("passes a text filter from the URL to the query", async () => {
    const spy = vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [], total_matched: 0 });
    renderTimeline("?text=payload");
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    expect(spy.mock.calls[0][1]).toMatchObject({ text: "payload" });
  });

  // spec:web-ui/host-event-timeline-view/a-text-filter-narrows-the-timeline
  it("commits a typed text filter to the query after debouncing (input never drops characters)", async () => {
    const spy = vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [], total_matched: 0 });
    renderTimeline();
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    const box = screen.getByRole("searchbox");
    fireEvent.change(box, { target: { value: "python3" } });
    expect(box).toHaveValue("python3"); // local state keeps the full value, not just the last char
    await waitFor(() => {
      expect(spy.mock.calls.some(([, f]) => f.text === "python3")).toBe(true);
    });
  });

  // spec:web-ui/graph-and-timeline-cross-navigation/a-timeline-row-opens-its-process-in-the-graph
  it("links a row to its process in the graph anchored at the event time", async () => {
    vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [execEvent("x", 42, "/bin/sh", 2_000_000_000)], total_matched: 1 });
    renderTimeline();
    const link = await screen.findByRole("link", { name: "sh (42)" });
    expect(link).toHaveAttribute("href", "/hosts/H1?view=graph&pid=42&at=2000");
  });

  it("emphasizes rows whose process matches emphasizePid", async () => {
    vi.spyOn(api, "getHostTimeline").mockResolvedValue({
      events: [connEvent("n1", 42, "1.2.3.4", 443), connEvent("n2", 99, "5.6.7.8", 80)],
      total_matched: 2,
    });
    renderTimeline("", 42);
    const emphasized = await screen.findByRole("link", { name: "curl (42)" });
    const row = emphasized.closest("tr");
    expect(row?.className).toContain("host-timeline__row--emphasis");
  });

  it("offers a fleet-search pivot on a connection row", async () => {
    vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [connEvent("n", 42, "203.0.113.7", 8443)], total_matched: 1 });
    renderTimeline();
    const pivot = await screen.findByRole("link", { name: "Search all hosts for this address" });
    expect(pivot).toHaveAttribute("href", "/search?mode=connections&remote_address=203.0.113.7");
  });

  it("appends the next page on load more", async () => {
    const spy = vi.spyOn(api, "getHostTimeline")
      .mockResolvedValueOnce({ events: [execEvent("x1", 1, "/bin/a")], next_cursor: "c1", total_matched: 2 })
      .mockResolvedValueOnce({ events: [execEvent("x2", 2, "/bin/b")], total_matched: 2 });
    renderTimeline();
    await screen.findByText(/Showing 1 of 2/);
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => { expect(screen.getByText(/Showing 2 of 2/)).toBeInTheDocument(); });
    expect(spy.mock.calls[1][2]).toBe("c1");
  });

  it("marks every chip pressed when no type filter is active (all shown)", async () => {
    vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [], total_matched: 0 });
    renderTimeline(); // no ?type= -> all types shown
    const exec = await screen.findByRole("button", { name: "Exec" });
    // aria-pressed agrees with the visual "on" state (was previously false while the chip looked on).
    expect(exec).toHaveAttribute("aria-pressed", "true");
  });

  it("re-syncs the text input when the URL text changes externally", async () => {
    vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [], total_matched: 0 });
    render(
      <MemoryRouter initialEntries={["/hosts/H1?text=first"]}>
        <Link to="/hosts/H1?text=second">nav</Link>
        <HostTimeline hostId="H1" bounds={BOUNDS} />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("searchbox")).toHaveValue("first");
    // Simulate external navigation (e.g. a link/back-forward) changing ?text=; the input must follow, not keep the stale draft.
    fireEvent.click(screen.getByRole("link", { name: "nav" }));
    await waitFor(() => { expect(screen.getByRole("searchbox")).toHaveValue("second"); });
  });

  it("shows the empty state when the window has no events", async () => {
    vi.spyOn(api, "getHostTimeline").mockResolvedValue({ events: [], total_matched: 0 });
    renderTimeline();
    expect(await screen.findByText("No events in this time range.")).toBeInTheDocument();
  });
});
