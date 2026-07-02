import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { HostHeader } from "./HostHeader";
import * as api from "../api";
import type { HostDetail } from "../types";

const NANOSECONDS_PER_MILLISECOND = 1_000_000;

function detailFixture(overrides: Partial<HostDetail> = {}): HostDetail {
  return {
    host_id: "93DFC6F5-763D-5075-B305-8AC145D12F96",
    hostname: "mac-01.local",
    platform: "darwin",
    os_name: "macOS",
    os_version: "26.4",
    os_build: "25E123",
    agent_version: "0.5.0",
    source_ip: "203.0.113.7",
    enrolled_at_ns: new Date("2026-06-01T12:00:00Z").getTime() * NANOSECONDS_PER_MILLISECOND,
    inventory_reported_at_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
    event_count: 12345,
    last_seen_ns: Date.now() * NANOSECONDS_PER_MILLISECOND,
    overall_status: "healthy",
    ...overrides,
  };
}

function renderHeader(hostId: string) {
  return render(
    <MemoryRouter initialEntries={[`/hosts/${hostId}`]}>
      <HostHeader hostId={hostId} />
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("HostHeader", () => {
  // spec:web-ui/host-detail-header/header-shows-identity-for-an-enrolled-host
  it("shows the hostname title, online pill, meta row, and copyable host id", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    renderHeader(detail.host_id);

    expect(await screen.findByText("mac-01.local")).toBeInTheDocument();
    expect(screen.getByText("online")).toBeInTheDocument();
    expect(screen.getByText("macOS 26.4 (25E123)")).toBeInTheDocument();
    expect(screen.getByText("agent 0.5.0")).toBeInTheDocument();
    expect(screen.getByText(/^last seen /)).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText(`${(12345).toLocaleString()} events`)).toBeInTheDocument();
    // The raw id stays visible for log correlation and is copyable in one click.
    expect(screen.getByText(detail.host_id)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy host id" })).toBeInTheDocument();
  });

  it("classifies a stale host offline and drops empty identity segments", async () => {
    const detail = detailFixture({
      hostname: "",
      os_name: "",
      os_version: "",
      os_build: "",
      agent_version: "",
      source_ip: "",
      enrolled_at_ns: 0,
      last_seen_ns: (Date.now() - 10 * 60 * 1000) * NANOSECONDS_PER_MILLISECOND,
    });
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    renderHeader(detail.host_id);

    expect(await screen.findByText("offline")).toBeInTheDocument();
    // Never-enrolled host: the id takes the title slot, and unknown facts render no segment at all.
    expect(screen.getByText(detail.host_id)).toBeInTheDocument();
    expect(screen.queryByText(/^agent /)).not.toBeInTheDocument();
    expect(screen.queryByText(/enrolled /)).not.toBeInTheDocument();
    expect(screen.getByText(/^last seen \d+m ago$/)).toBeInTheDocument();
  });

  // spec:web-ui/host-detail-header/header-degrades-when-the-detail-fetch-fails
  it("falls back to the host id title when the detail fetch fails", async () => {
    vi.spyOn(api, "getHostDetail").mockRejectedValue(new Error("boom"));
    renderHeader("HOST-XYZ");

    expect(await screen.findByText("HOST-XYZ")).toBeInTheDocument();
    expect(screen.queryByText("online")).not.toBeInTheDocument();
    expect(screen.queryByText("offline")).not.toBeInTheDocument();
    // Still copyable even in the degraded state.
    expect(screen.getByRole("button", { name: "Copy host id" })).toBeInTheDocument();
  });
});
