import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AlertList } from "./AlertList";
import * as api from "../api";
import type { Alert, HostSummary } from "../types";

// AlertList shipped without component tests prior to step 9; the source filter
// chip is the demo cut's last UI surface and the easiest place to grow
// coverage of the AlertList tree on the way in. Tests below pin:
//   - the source filter renders with the All / Detection / App control options
//   - changing the source filter triggers a new listAlerts call with the
//     selected source value (proves the wire param flows through)
//   - the source column renders the readable label, not the wire value
//   - the default-open status filter survives the new filter (regression
//     guard since adding a third dependency to useEffect is easy to fumble)

const makeAlert = (over: Partial<Alert> = {}): Alert => ({
  id: 1,
  host_id: "host-a",
  rule_id: "rule-x",
  source: "detection",
  severity: "high",
  title: "Suspicious process",
  description: "",
  process_id: 100,
  status: "open",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  ...over,
});

const hostSummary = (id: string, name: string): HostSummary => ({
  host_id: id,
  hostname: name,
  os_version: "26.4",
  platform: "darwin",
  event_count: 0,
  last_seen_ns: 0,
  overall_status: "unknown",
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AlertList source filter", () => {
  beforeEach(() => {
    vi.spyOn(api, "listAlerts");
    // Every AlertList render now calls useHostNames(), which fetches /hosts; stub it so these suites stay isolated from the real API.
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
  });

  it("renders the source column with the readable label, not the wire value", async () => {
    (api.listAlerts as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeAlert({ id: 1, source: "detection", title: "detection alert" }),
      makeAlert({ id: 2, source: "application_control", title: "app-control alert" }),
    ]);
    render(
      <MemoryRouter>
        <AlertList />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText("detection alert")).toBeInTheDocument();
    });
    // Wire values must NOT leak into the UI; the column should map them. Both
    // labels also appear in the filter dropdown, so scope the cell-level
    // assertions to the table to avoid double-matching against the <option>s.
    expect(screen.queryByText("application_control")).not.toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("Detection")).toBeInTheDocument();
    expect(within(table).getByText("App control")).toBeInTheDocument();
  });

  it("renders the source filter with All / Detection / App control options", async () => {
    (api.listAlerts as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    render(
      <MemoryRouter>
        <AlertList />
      </MemoryRouter>,
    );
    const sourceSelect = await screen.findByLabelText("Source:");
    const options = Array.from(sourceSelect.querySelectorAll("option")).map(
      (o) => ({ value: o.value, label: o.textContent }),
    );
    expect(options).toEqual([
      { value: "", label: "All" },
      { value: "detection", label: "Detection" },
      { value: "application_control", label: "App control" },
    ]);
  });

  it("passes source=application_control to listAlerts when the filter is set", async () => {
    const spy = api.listAlerts as unknown as ReturnType<typeof vi.fn>;
    spy.mockResolvedValue([]);
    render(
      <MemoryRouter>
        <AlertList />
      </MemoryRouter>,
    );
    // First load: default status=open, no source.
    await waitFor(() => {
      expect(spy).toHaveBeenCalled();
    });
    spy.mockClear();
    fireEvent.change(await screen.findByLabelText("Source:"), {
      target: { value: "application_control" },
    });
    await waitFor(() => {
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({ source: "application_control", status: "open" }),
      );
    });
  });

  it("clears the source param when filter goes back to All", async () => {
    const spy = api.listAlerts as unknown as ReturnType<typeof vi.fn>;
    spy.mockResolvedValue([]);
    render(
      <MemoryRouter>
        <AlertList />
      </MemoryRouter>,
    );
    const sourceSelect = await screen.findByLabelText("Source:");
    fireEvent.change(sourceSelect, { target: { value: "detection" } });
    await waitFor(() => {
      expect(spy).toHaveBeenLastCalledWith(
        expect.objectContaining({ source: "detection" }),
      );
    });
    spy.mockClear();
    fireEvent.change(sourceSelect, { target: { value: "" } });
    await waitFor(() => {
      expect(spy).toHaveBeenCalled();
    });
    // source key is omitted (or undefined) when the All bucket is selected;
    // a literal empty string would let the server treat "" as a filter
    // value, which would suppress all rows since no alert has source="".
    const lastCall = spy.mock.calls[spy.mock.calls.length - 1] as [
      { source?: string },
    ];
    expect(lastCall[0].source).toBeUndefined();
  });
});

describe("AlertList general states", () => {
  beforeEach(() => {
    vi.spyOn(api, "listAlerts");
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
  });

  it("shows the loading state until the fetch resolves", async () => {
    let resolve: ((value: Alert[]) => void) | undefined;
    (api.listAlerts as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      new Promise<Alert[]>((r) => { resolve = r; }),
    );
    render(
      <MemoryRouter>
        <AlertList />
      </MemoryRouter>,
    );
    expect(screen.getByText(/loading alerts/i)).toBeInTheDocument();
    resolve?.([]);
    await waitFor(() => {
      expect(screen.getByText(/no alerts found/i)).toBeInTheDocument();
    });
  });

  it("surfaces fetch failures in the empty state", async () => {
    (api.listAlerts as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );
    render(
      <MemoryRouter>
        <AlertList />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText(/error: boom/i)).toBeInTheDocument();
    });
  });
});

describe("AlertList host column", () => {
  beforeEach(() => {
    vi.spyOn(api, "listAlerts");
  });

  // spec:web-ui/the-alert-list-identifies-a-host-by-name/alert-list-shows-the-enrollment-hostname
  it("shows the host's enrollment hostname, falling back to the hardware id when unknown", async () => {
    (api.listAlerts as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeAlert({ id: 1, host_id: "AAAA-1111", title: "named host alert" }),
      makeAlert({ id: 2, host_id: "BBBB-2222", title: "unknown host alert" }),
    ]);
    // Only the first host has a resolvable hostname; the second is absent from the map.
    vi.spyOn(api, "listHosts").mockResolvedValue([hostSummary("AAAA-1111", "mac-a.local")]);
    render(
      <MemoryRouter>
        <AlertList />
      </MemoryRouter>,
    );
    // The known host resolves to its name; the unknown host falls back to its raw hardware id in the cell.
    expect(await screen.findByText("mac-a.local")).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("BBBB-2222")).toBeInTheDocument();
    // The named host's UUID is not shown as the visible cell text (it lives in the link tooltip instead).
    expect(within(table).queryByText("AAAA-1111")).not.toBeInTheDocument();
  });
});
