import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router";

import { ProcessSearch } from "./ProcessSearch";
import * as api from "../../api";
import type { Process } from "../../types";

function proc(over: Partial<Process> = {}): Process {
  return { id: 1, host_id: "H1", pid: 100, ppid: 1, path: "/usr/bin/grep", fork_time_ns: 1_000_000_000, ...over };
}

const HOSTS = new Map([["H1", "mac-a.local"]]);

function renderProc(initial = "/search?path=grep", hostNames = HOSTS) {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/search" element={<ProcessSearch hostNames={hostNames} />} />
        <Route path="/hosts/:hostId" element={<div>HOST TREE</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => { vi.restoreAllMocks(); });

describe("ProcessSearch", () => {
  it("renders process rows with the resolved host name and passes URL filters to the search", async () => {
    const spy = vi.spyOn(api, "searchProcesses").mockResolvedValue({
      rows: [proc({ id: 7, args: ["grep", "-r", "x"], exec_time_ns: 2_000_000_000 })],
      total_matched: 1,
    });
    renderProc("/search?path=grep&signing=unsigned");
    expect(await screen.findByText("mac-a.local")).toBeInTheDocument(); // name from the prop map
    expect(screen.getByText("grep -r x")).toBeInTheDocument();
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    expect(spy.mock.calls[0][0]).toMatchObject({ path: "grep", signing: "unsigned" });
  });

  it("links a row to the host tree anchored at the process DB id (not the pid)", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({
      rows: [proc({ id: 77, pid: 100, exec_time_ns: 2_000_000_000, fork_time_ns: 2_000_000_000 })],
      total_matched: 1,
    });
    renderProc();
    const link = await screen.findByRole("link", { name: "grep" });
    expect(link).toHaveAttribute("href", "/hosts/H1?process=77&at=2000");
  });

  it("falls back to the host id and shows no verdict for a fork-only row", async () => {
    vi.spyOn(api, "searchProcesses").mockResolvedValue({
      rows: [proc({ id: 1, host_id: "UNKNOWN", exec_time_ns: undefined })],
      total_matched: 1,
    });
    renderProc("/search?path=grep", new Map());
    expect(await screen.findByText("UNKNOWN")).toBeInTheDocument();
    expect(screen.queryByText("unsigned")).not.toBeInTheDocument();
  });

  it("removing a chip refetches without that filter", async () => {
    const spy = vi.spyOn(api, "searchProcesses").mockResolvedValue({ rows: [proc()], total_matched: 1 });
    renderProc("/search?path=grep&signing=unsigned");
    await waitFor(() => { expect(spy).toHaveBeenCalled(); });
    fireEvent.click(screen.getByRole("button", { name: "Remove Path filter" }));
    await waitFor(() => {
      expect(spy.mock.calls.some(([f]) => !("path" in f) && f.signing === "unsigned")).toBe(true);
    });
  });
});
