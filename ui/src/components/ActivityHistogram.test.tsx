import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

import { ActivityHistogram } from "./ActivityHistogram";
import * as api from "../api";

const SEC = 1_000_000_000;

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ActivityHistogram", () => {
  // spec:web-ui/host-page-time-navigation/histogram-bucket-click-narrows-the-window
  it("renders a bar per bucket and narrows the window on click", async () => {
    vi.spyOn(api, "getActivityHistogram").mockResolvedValue({
      bucket_ns: 60 * SEC,
      total: 40,
      buckets: [
        { start_ns: 0, count: 3 },
        { start_ns: 120 * SEC, count: 37 },
      ],
    });
    const onSelect = vi.fn();
    render(<ActivityHistogram hostId="h1" fromNs={0} toNs={180 * SEC} onSelectBucket={onSelect} />);

    // Three slots for the 3-minute window: two with data, one zero-filled and disabled.
    const bars = await screen.findAllByRole("button");
    expect(bars).toHaveLength(3);
    expect(bars.filter((b) => (b as HTMLButtonElement).disabled)).toHaveLength(1);

    const spike = bars.find((b) => b.getAttribute("aria-label")?.includes("37 process starts"));
    expect(spike).toBeDefined();
    fireEvent.click(spike as Element);
    expect(onSelect).toHaveBeenCalledWith(120 * SEC, 180 * SEC);
  });

  it("renders nothing for an empty window or a failed fetch", async () => {
    vi.spyOn(api, "getActivityHistogram").mockResolvedValue({ bucket_ns: SEC, total: 0, buckets: null });
    const { container, rerender } = render(<ActivityHistogram hostId="h1" fromNs={0} toNs={SEC} onSelectBucket={vi.fn()} />);
    await waitFor(() => {
      expect(api.getActivityHistogram).toHaveBeenCalled();
    });
    expect(container.firstChild).toBeNull();

    vi.spyOn(api, "getActivityHistogram").mockRejectedValue(new Error("boom"));
    rerender(<ActivityHistogram hostId="h1" fromNs={0} toNs={2 * SEC} onSelectBucket={vi.fn()} />);
    await waitFor(() => {
      expect(container.firstChild).toBeNull();
    });
  });
});
