import { describe, it, expect, vi, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

import { useHostNames } from "./useHostNames";
import * as api from "../api";
import type { HostSummary } from "../types";

function host(id: string, name: string): HostSummary {
  return { host_id: id, hostname: name, os_version: "26.4", platform: "darwin", event_count: 0, last_seen_ns: 0, overall_status: "unknown" };
}

afterEach(() => { vi.restoreAllMocks(); });

describe("useHostNames", () => {
  it("resolves a host_id -> hostname map, dropping hosts with no hostname", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([host("H1", "mac-a.local"), { ...host("H2", ""), hostname: "" }]);
    const { result } = renderHook(() => useHostNames());
    await waitFor(() => { expect(result.current.get("H1")).toBe("mac-a.local"); });
    expect(result.current.has("H2")).toBe(false); // blank hostname is not mapped
  });

  it("leaves the map empty when listHosts fails (rows fall back to the id)", async () => {
    vi.spyOn(api, "listHosts").mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useHostNames());
    // Give the rejected promise a tick to settle; the map stays empty rather than throwing.
    await waitFor(() => { expect(result.current.size).toBe(0); });
  });
});
