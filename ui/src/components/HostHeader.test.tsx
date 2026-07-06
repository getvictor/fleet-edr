import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
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
  it("shows hostname + online pill + OS, and keeps reference facts in the Details popover", async () => {
    const detail = detailFixture();
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    renderHeader(detail.host_id);

    // At a glance: identity, status, and OS only. The online pill conveys liveness, so no "last seen" segment when online.
    expect(await screen.findByText("mac-01.local")).toBeInTheDocument();
    expect(screen.getByText("online")).toBeInTheDocument();
    expect(screen.getByText("macOS 26.4 (25E123)")).toBeInTheDocument();
    expect(screen.queryByText(/last seen/)).not.toBeInTheDocument();

    // Reference facts (raw id + copy, agent, IP, events, enrolled) are hidden until the popover is opened, and the copy control is not
    // sitting next to the hostname.
    expect(screen.queryByText(detail.host_id)).not.toBeInTheDocument();
    expect(screen.queryByText("0.5.0")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy host id" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Details" }));

    expect(screen.getByText(detail.host_id)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy host id" })).toBeInTheDocument();
    expect(screen.getByText("0.5.0")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText((12345).toLocaleString())).toBeInTheDocument();
    expect(screen.getByText("Last seen")).toBeInTheDocument();
  });

  it("shows 'last seen' in the meta row only when the host is offline", async () => {
    const detail = detailFixture({
      last_seen_ns: (Date.now() - 10 * 60 * 1000) * NANOSECONDS_PER_MILLISECOND,
    });
    vi.spyOn(api, "getHostDetail").mockResolvedValue(detail);
    renderHeader(detail.host_id);

    expect(await screen.findByText("offline")).toBeInTheDocument();
    // Offline: staleness matters, so the exact age surfaces in the always-visible meta row.
    expect(screen.getByText(/^last seen \d+m ago$/)).toBeInTheDocument();
  });

  it("drops unknown facts rather than rendering empty segments", async () => {
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

    // Never-enrolled host: the id takes the title slot; unknown facts (agent, IP, enrolled) render no popover row at all.
    expect(await screen.findByText(detail.host_id)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Details" }));
    expect(screen.queryByText("Agent")).not.toBeInTheDocument();
    expect(screen.queryByText("IP")).not.toBeInTheDocument();
    expect(screen.queryByText("Enrolled")).not.toBeInTheDocument();
  });

  // spec:web-ui/host-detail-header/header-degrades-when-the-detail-fetch-fails
  it("falls back to the host id title when the detail fetch fails", async () => {
    vi.spyOn(api, "getHostDetail").mockRejectedValue(new Error("boom"));
    renderHeader("HOST-XYZ");

    expect(await screen.findByText("HOST-XYZ")).toBeInTheDocument();
    expect(screen.queryByText("online")).not.toBeInTheDocument();
    expect(screen.queryByText("offline")).not.toBeInTheDocument();
    // With no detail there is nothing to disclose, so no Details trigger renders; the raw-id title is itself selectable.
    expect(screen.queryByRole("button", { name: "Details" })).not.toBeInTheDocument();
  });
});
