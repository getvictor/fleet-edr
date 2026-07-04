import { describe, it, expect } from "vitest";
import { render as rtlRender, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { NetworkConnections } from "./NetworkConnections";
import type { EventRecord, NetworkConnectPayload, DNSQueryPayload } from "../types";

// NetworkConnections now renders "search fleet" pivot Links, so every render needs a Router context.
function render(ui: ReactNode) {
  return rtlRender(<MemoryRouter>{ui}</MemoryRouter>);
}

// NetworkConnections is pure presentation over two event lists. These tests pin the
// empty state, the connection-grouping (identical remote+port+proto+direction collapse
// into one row with a hit count), the inbound suffix, the "N unique" header that only
// appears once grouping actually collapsed something, and the DNS table including the
// response-addresses join / dash fallback.

const NS = 1_000_000; // 1 ms in ns; keeps timestamps readable and ordered.

function connEvent(over: Partial<NetworkConnectPayload> & { id: string; ts: number }): EventRecord {
  const { id, ts, ...payload } = over;
  return {
    event_id: id,
    host_id: "h1",
    timestamp_ns: ts * NS,
    event_type: "network_connect",
    payload: {
      pid: 1,
      protocol: "tcp",
      direction: "outbound",
      remote_address: "1.2.3.4",
      remote_port: 443,
      ...payload,
    } satisfies NetworkConnectPayload,
  };
}

function dnsEvent(over: Partial<DNSQueryPayload> & { id: string; ts: number }): EventRecord {
  const { id, ts, ...payload } = over;
  return {
    event_id: id,
    host_id: "h1",
    timestamp_ns: ts * NS,
    event_type: "dns_query",
    payload: {
      pid: 1,
      query_name: "example.com",
      query_type: "A",
      ...payload,
    } satisfies DNSQueryPayload,
  };
}

describe("NetworkConnections empty state", () => {
  it("renders the empty message when both lists are null", () => {
    render(<NetworkConnections connections={null} dnsQueries={null} />);
    expect(screen.getByText(/no network activity/i)).toBeInTheDocument();
  });

  it("renders the empty message when both lists are empty arrays", () => {
    render(<NetworkConnections connections={[]} dnsQueries={[]} />);
    expect(screen.getByText(/no network activity/i)).toBeInTheDocument();
  });
});

describe("NetworkConnections grouping", () => {
  it("collapses identical endpoints into one row with a ×count and shows the unique label", () => {
    render(
      <NetworkConnections
        connections={[
          connEvent({ id: "a", ts: 1 }),
          connEvent({ id: "b", ts: 5 }),
          connEvent({ id: "c", ts: 3 }),
        ]}
        dnsQueries={null}
      />,
    );
    // Three raw events collapse to one unique grouped row.
    expect(screen.getByText(/network connections \(3, 1 unique\)/i)).toBeInTheDocument();
    expect(screen.getByText("1.2.3.4:443")).toBeInTheDocument();
    expect(screen.getByText(/tcp ×3/)).toBeInTheDocument();
  });

  it("omits the unique label when no grouping collapsed anything", () => {
    render(
      <NetworkConnections
        connections={[
          connEvent({ id: "a", ts: 1, remote_address: "1.1.1.1" }),
          connEvent({ id: "b", ts: 2, remote_address: "2.2.2.2" }),
        ]}
        dnsQueries={null}
      />,
    );
    expect(screen.getByText(/network connections \(2\)/i)).toBeInTheDocument();
    expect(screen.queryByText(/unique/i)).not.toBeInTheDocument();
  });

  it("marks inbound connections with an 'in' suffix and no ×count for a single hit", () => {
    render(
      <NetworkConnections
        connections={[connEvent({ id: "a", ts: 1, direction: "inbound" })]}
        dnsQueries={null}
      />,
    );
    const cell = screen.getByText(/tcp in/);
    expect(cell).toBeInTheDocument();
    expect(cell.textContent).not.toMatch(/×/);
  });

  it("sorts the noisiest endpoint (highest count) first", () => {
    render(
      <NetworkConnections
        connections={[
          connEvent({ id: "q1", ts: 1, remote_address: "9.9.9.9", remote_port: 53 }),
          connEvent({ id: "n1", ts: 2, remote_address: "8.8.8.8", remote_port: 53 }),
          connEvent({ id: "n2", ts: 3, remote_address: "8.8.8.8", remote_port: 53 }),
        ]}
        dnsQueries={null}
      />,
    );
    const rows = screen.getAllByRole("row").filter((r) => within(r).queryByText(/:53/));
    // The 8.8.8.8 group (count 2) floats above the single 9.9.9.9 hit.
    expect(within(rows[0]).getByText("8.8.8.8:53")).toBeInTheDocument();
    expect(within(rows[1]).getByText("9.9.9.9:53")).toBeInTheDocument();
  });
});

describe("NetworkConnections DNS table", () => {
  it("renders DNS rows with joined response addresses", () => {
    render(
      <NetworkConnections
        connections={null}
        dnsQueries={[
          dnsEvent({ id: "d1", ts: 1, query_name: "fleetdm.com", response_addresses: ["1.1.1.1", "2.2.2.2"] }),
        ]}
      />,
    );
    expect(screen.getByText(/dns queries \(1\)/i)).toBeInTheDocument();
    expect(screen.getByText("fleetdm.com")).toBeInTheDocument();
    expect(screen.getByText("1.1.1.1, 2.2.2.2")).toBeInTheDocument();
  });

  it("falls back to a dash when a DNS query has no response addresses", () => {
    render(
      <NetworkConnections
        connections={null}
        dnsQueries={[dnsEvent({ id: "d1", ts: 1, response_addresses: [] })]}
      />,
    );
    expect(screen.getByText("-")).toBeInTheDocument();
  });

  it("renders both sections together when connections and DNS are present", () => {
    render(
      <NetworkConnections
        connections={[connEvent({ id: "a", ts: 1 })]}
        dnsQueries={[dnsEvent({ id: "d1", ts: 1 })]}
      />,
    );
    expect(screen.getByText(/network connections/i)).toBeInTheDocument();
    expect(screen.getByText(/dns queries/i)).toBeInTheDocument();
  });
});

describe("NetworkConnections search-fleet pivots", () => {
  // spec:web-ui/network-artifact-search-pivots/pivoting-from-a-remote-address-searches-connections-fleet-wide
  it("links a connection's remote address to the fleet-wide connection search", () => {
    render(
      <NetworkConnections
        connections={[connEvent({ id: "a", ts: 1, remote_address: "203.0.113.7", remote_port: 8443 })]}
        dnsQueries={null}
      />,
    );
    const link = screen.getByRole("link", { name: "Search all hosts for this address" });
    expect(link).toHaveAttribute("href", "/search?mode=connections&remote_address=203.0.113.7");
  });

  // spec:web-ui/network-artifact-search-pivots/pivoting-from-a-dns-query-searches-lookups-fleet-wide
  it("links a DNS query name to the fleet-wide DNS search", () => {
    render(
      <NetworkConnections
        connections={null}
        dnsQueries={[dnsEvent({ id: "d1", ts: 1, query_name: "evil.example.com" })]}
      />,
    );
    const link = screen.getByRole("link", { name: "Search all hosts for this domain" });
    expect(link).toHaveAttribute("href", "/search?mode=dns&query_name=evil.example.com");
  });
});
