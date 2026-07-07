import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { EventSearch } from "./EventSearch";
import * as api from "../../api";
import type { EventRecord, NetworkConnectPayload, DNSQueryPayload } from "../../types";

function connEvent(id: string, host: string, over: Partial<NetworkConnectPayload> = {}): EventRecord {
  return {
    event_id: id,
    host_id: host,
    timestamp_ns: 1_000_000_000,
    event_type: "network_connect",
    payload: { pid: 42, path: "/usr/bin/curl", protocol: "tcp", direction: "outbound", remote_address: "1.2.3.4", remote_port: 443, ...over },
  };
}

function dnsEvent(id: string, host: string, over: Partial<DNSQueryPayload> = {}): EventRecord {
  return {
    event_id: id,
    host_id: host,
    timestamp_ns: 1_000_000_000,
    event_type: "dns_query",
    payload: { pid: 7, path: "/usr/bin/nslookup", query_name: "evil.example.com", query_type: "A", response_addresses: ["9.9.9.9"], ...over },
  };
}

const HOSTS = new Map([["H1", "mac-a.local"], ["H2", "mac-b.local"]]);

function renderEvent(mode: api.EventSearchMode, search: string, hostNames: Map<string, string> = HOSTS) {
  return render(
    <MemoryRouter initialEntries={[`/search${search}`]}>
      <EventSearch mode={mode} hostNames={hostNames} />
    </MemoryRouter>,
  );
}

afterEach(() => { vi.restoreAllMocks(); });

describe("EventSearch connections mode", () => {
  // spec:web-ui/fleet-wide-connection-and-dns-search/connection-mode-lists-fleet-wide-connections-to-an-address
  it("lists connections to a remote address with host, process, and remote endpoint", async () => {
    const spy = vi.spyOn(api, "searchEvents").mockResolvedValue({
      events: [connEvent("a", "H1"), connEvent("b", "H2", { remote_port: 8443 })],
      total_matched: 2,
    });

    renderEvent("connections", "?remote_address=1.2.3.4");
    expect(await screen.findByText("mac-a.local")).toBeInTheDocument();
    expect(screen.getByText("mac-b.local")).toBeInTheDocument();
    expect(screen.getByText("1.2.3.4:443")).toBeInTheDocument();
    expect(screen.getByText("1.2.3.4:8443")).toBeInTheDocument();
    expect(screen.getAllByText("curl (42)")).toHaveLength(2); // both rows share the originating process
    expect(screen.getByText(/Showing 2 of 2 matches/)).toBeInTheDocument();
    // The search hit the connections endpoint carrying the remote address.
    expect(spy).toHaveBeenCalledWith("connections", expect.objectContaining({ value: "1.2.3.4" }), undefined);
  });

  it("brackets an IPv6 remote address so addr:port is unambiguous", async () => {
    vi.spyOn(api, "searchEvents").mockResolvedValue({
      events: [connEvent("a", "H1", { remote_address: "2606::1", remote_port: 443 })],
      total_matched: 1,
    });
    renderEvent("connections", "?remote_address=2606::1");
    expect(await screen.findByText("[2606::1]:443")).toBeInTheDocument();
  });

  it("narrows to a single host when a host chip is present", async () => {
    const spy = vi.spyOn(api, "searchEvents").mockResolvedValue({ events: [], total_matched: 0 });
    renderEvent("connections", "?remote_address=1.2.3.4&host_id=H9");
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    expect(spy.mock.calls[0][1]).toMatchObject({ value: "1.2.3.4", host_id: "H9" });
  });
});

describe("EventSearch DNS mode", () => {
  // spec:web-ui/fleet-wide-connection-and-dns-search/dns-mode-lists-fleet-wide-lookups-of-a-domain
  it("lists DNS lookups of a domain with query type and resolved addresses", async () => {
    vi.spyOn(api, "searchEvents").mockResolvedValue({
      events: [dnsEvent("d1", "H1", { query_type: "AAAA", response_addresses: ["2606::1", "2606::2"] })],
      total_matched: 1,
    });
    renderEvent("dns", "?query_name=evil.example.com");
    expect(await screen.findByText("AAAA")).toBeInTheDocument();
    expect(screen.getByText("evil.example.com")).toBeInTheDocument(); // the queried domain renders in its own column
    expect(screen.getByText("2606::1, 2606::2")).toBeInTheDocument();
    expect(screen.getByText("nslookup (7)")).toBeInTheDocument();
  });
});

describe("EventSearch recent events + pagination + error", () => {
  // spec:web-ui/fleet-wide-connection-and-dns-search/an-event-mode-opens-on-recent-events
  it("lists recent connections and issues a request when no artifact value is supplied", async () => {
    // The recent-events browse skips the count, so the endpoint reports a negative total and the frame shows "Showing N" only.
    const spy = vi.spyOn(api, "searchEvents").mockResolvedValue({ events: [connEvent("a", "H1")], total_matched: -1 });
    renderEvent("connections", "");
    expect(await screen.findByText("mac-a.local")).toBeInTheDocument();
    expect(screen.getByText("Showing 1")).toBeInTheDocument();
    expect(screen.queryByText(/of .* matches/)).not.toBeInTheDocument();
    // The request fired with no artifact filter (recent events across the fleet), rather than sitting behind a prompt.
    expect(spy).toHaveBeenCalledWith("connections", expect.objectContaining({ value: "" }), undefined);
  });

  it("lists recent DNS lookups with the queried domain when no domain filter is supplied", async () => {
    const spy = vi.spyOn(api, "searchEvents").mockResolvedValue({
      events: [dnsEvent("d1", "H1", { query_name: "recent.example.com" })],
      total_matched: -1,
    });
    renderEvent("dns", "");
    // The queried domain is shown per row (it varies across the recent feed), alongside the process.
    expect(await screen.findByText("recent.example.com")).toBeInTheDocument();
    expect(screen.getByText("nslookup (7)")).toBeInTheDocument();
    expect(spy).toHaveBeenCalledWith("dns", expect.objectContaining({ value: "" }), undefined);
  });

  // spec:web-ui/fleet-wide-connection-and-dns-search/load-more-appends-the-next-page-of-events
  it("appends the next page of events on load more", async () => {
    const spy = vi.spyOn(api, "searchEvents")
      .mockResolvedValueOnce({ events: [connEvent("a", "H1")], next_cursor: "c1", total_matched: 2 })
      .mockResolvedValueOnce({ events: [connEvent("b", "H1", { remote_port: 8443 })], total_matched: 2 });
    renderEvent("connections", "?remote_address=1.2.3.4");
    await screen.findByText(/Showing 1 of 2/);
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => { expect(screen.getByText(/Showing 2 of 2/)).toBeInTheDocument(); });
    expect(spy.mock.calls[1][2]).toBe("c1"); // second call carried the cursor
    expect(screen.queryByRole("button", { name: "Load more" })).not.toBeInTheDocument();
  });

  it("surfaces a search error", async () => {
    vi.spyOn(api, "searchEvents").mockRejectedValue(new Error("archive down"));
    renderEvent("dns", "?query_name=evil.example.com");
    expect(await screen.findByText("Error: archive down")).toBeInTheDocument();
  });

  it("shows the empty state when a valid search matches nothing", async () => {
    vi.spyOn(api, "searchEvents").mockResolvedValue({ events: [], total_matched: 0 });
    renderEvent("connections", "?remote_address=1.2.3.4");
    expect(await screen.findByText("No matching connections.")).toBeInTheDocument();
  });
});
