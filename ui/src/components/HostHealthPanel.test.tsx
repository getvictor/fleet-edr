import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { HostHealthPanel } from "./HostHealthPanel";
import * as api from "../api";
import type { HostHealth } from "../types";

afterEach(() => {
  vi.restoreAllMocks();
});

const nowNs = () => Date.now() * 1_000_000;

describe("HostHealthPanel", () => {
  // spec:web-ui/the-host-detail-surfaces-the-health-conditions/the-detail-lists-a-component-with-its-message-and-age
  it("renders each component condition with its friendly label and message", async () => {
    const health: HostHealth = {
      overall_status: "unhealthy",
      reported_at_ns: nowNs(),
      components: [
        {
          type: "endpoint_security_extension",
          status: "unhealthy",
          reason: "never_connected",
          message: "Security extension not activated",
          last_transition_ns: nowNs(),
        },
        {
          type: "network_extension",
          status: "healthy",
          reason: "activated",
          message: "Network extension connected",
          last_transition_ns: nowNs(),
        },
      ],
    };
    vi.spyOn(api, "getHostHealth").mockResolvedValue(health);

    render(<HostHealthPanel hostId="h1" />);

    expect(await screen.findByText("Security extension not activated")).toBeInTheDocument();
    expect(screen.getByText("Network extension connected")).toBeInTheDocument();
    expect(screen.getByText("Security extension")).toBeInTheDocument();
    expect(screen.getByText("Network extension")).toBeInTheDocument();
    // The overall rollup and the unhealthy security extension both render a "needs attention" badge; the network extension is healthy.
    expect(screen.getAllByText("needs attention")).toHaveLength(2);
    expect(screen.getByText("healthy")).toHaveClass("badge--success");
  });

  it("shows an empty state when no components are reported", async () => {
    vi.spyOn(api, "getHostHealth").mockResolvedValue({
      overall_status: "unknown",
      reported_at_ns: 0,
      components: null,
    });

    render(<HostHealthPanel hostId="h1" />);

    expect(await screen.findByText(/no component health reported/i)).toBeInTheDocument();
  });

  it("renders nothing when the health fetch fails, so the process tree still loads", async () => {
    vi.spyOn(api, "getHostHealth").mockRejectedValue(new Error("boom"));

    const { container } = render(<HostHealthPanel hostId="h1" />);

    await waitFor(() => {
      expect(api.getHostHealth).toHaveBeenCalled();
    });
    expect(container).toBeEmptyDOMElement();
  });
});
